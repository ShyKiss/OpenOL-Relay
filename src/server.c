/*=============================================================================
    server.c - core server logic, shared by the embedded relay (OLGame.exe,
    OPENOL_EMBEDDED) and the standalone OpenOL_Relay.
=============================================================================*/
#ifdef _MSC_VER
#  pragma warning(disable: 4127) /* conditional expression is constant */
#endif
#include "server.h"
#include "relay_compat.h"  /* snprintf polyfill — after server.h pulls in winsock2 */
#include "openol_protocol.h"
#ifndef OPENOL_EMBEDDED
#  include "cli.h"
#endif
#include <stdarg.h>

// ---------------------------------------------------------------------------
// Session token generation
// ---------------------------------------------------------------------------

static uint64_t gen_conn_id(void) {
    uint64_t id = 0;
    while (id == 0 && !ol_random((uint8_t *)&id, sizeof(id)))
        id = ((uint64_t)rand() << 32) ^ (uint64_t)rand() ^ (uint64_t)time(NULL);
    return id;
}

static void gen_session_token(uint8_t out[32]) {
    if (!ol_random(out, 32)) {
        // Last resort only: a predictable token is still better than no session.
        int i;
        srand((unsigned int)time(NULL) ^ (unsigned int)(size_t)out);
        for (i = 0; i < 32; i++) out[i] = (uint8_t)(rand() & 0xFF);
    }
}

// ---------------------------------------------------------------------------
// Logging — history ring in the embedded build (consumed by the ImGui panel),
// cli_log in the standalone build (handles both TUI and plain-text modes)
// ---------------------------------------------------------------------------

static void server_log(Server *s, const char *fmt, ...) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char ts[20];
    char body[256];
    va_list ap;
    strftime(ts, sizeof(ts), "%H:%M:%S", tm_info);
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
#ifdef OPENOL_EMBEDDED
    history_push(s, "[%s] %s", ts, body);
#else
    (void)s;
    cli_log("[%s] %s", ts, body);
#endif
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

int check_rate(Player *p) {
    double now = mono_now();
    if (now - p->pkt_window >= 1.0) {
        p->pkt_window = now;
        p->pkt_count  = 1;
        return 1;
    }
    p->pkt_count++;
    return p->pkt_count <= MAX_RATE;
}

// ---------------------------------------------------------------------------
// Room management
// ---------------------------------------------------------------------------

Room *server_find_room(Server *s, const char *code) {
    for (int i = 0; i < s->n_rooms; i++)
        if (s->rooms[i].active && strcmp(s->rooms[i].code, code) == 0)
            return &s->rooms[i];
    return NULL;
}

#define OL_PASSWORD_PREFIX "$ol1$"

static void hex_encode(char *out, const uint8_t *in, int len) {
    static const char digits[] = "0123456789abcdef";
    int i;
    for (i = 0; i < len; i++) {
        out[i * 2]     = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[len * 2] = '\0';
}

static int hex_decode(const char *in, uint8_t *out, int len) {
    int i;
    for (i = 0; i < len; i++) {
        unsigned value;
        if (!in[i * 2] || !in[i * 2 + 1] || sscanf(in + i * 2, "%2x", &value) != 1) return 0;
        out[i] = (uint8_t)value;
    }
    return 1;
}

// Rooms never keep a password in memory or on disk, only what proves it. Values already
// in this form come from the database; anything else, from an admin or an old file, is new.
static void room_password_store(Server *s, const char *password, char out[MAX_PASSWORD]) {
    size_t prefix = strlen(OL_PASSWORD_PREFIX);
    uint8_t key[32];
    out[0] = '\0';
    if (!password[0]) return;
    if (strncmp(password, OL_PASSWORD_PREFIX, prefix) == 0) {
        strncpy(out, password, MAX_PASSWORD - 1);
        out[MAX_PASSWORD - 1] = '\0';
    } else if (ol_password_key(s->hs.pub, password, key)) {
        strcpy(out, OL_PASSWORD_PREFIX);
        hex_encode(out + prefix, key, 32);
    } else {
        // Out of memory: the room must not silently become open.
        snprintf(out, MAX_PASSWORD, "%s!", OL_PASSWORD_PREFIX);
    }
}

static int room_password_ok(const Room *room, const OlHsAuth *auth) {
    uint8_t key[32];
    size_t prefix = strlen(OL_PASSWORD_PREFIX);
    if (strncmp(room->password, OL_PASSWORD_PREFIX, prefix) != 0 || !hex_decode(room->password + prefix, key, 32))
        return 0;
    return ol_hs_proof_ok_key(auth, key);
}

Room *server_add_room(Server *s, const char *code, const char *password) {
    if (s->n_rooms >= MAX_ROOMS) return NULL;
    Room *r = &s->rooms[s->n_rooms++];
    memset(r, 0, sizeof(*r));
    strncpy(r->code,     code,     MAX_ROOM_CODE - 1);
    room_password_store(s, password, r->password);
    r->active = 1;
    // Mirror into DB so trusted/bans are always accessible
    db_add_room(&s->db, code, r->password);
    // An old database held the password itself; this replaces it on disk.
    if (strcmp(password, r->password) != 0) {
        db_update_room_password(&s->db, code, r->password);
        db_save(&s->db);
    }
    return r;
}

// Change room password. Clears trusted IPs in DB.
void server_set_room_password(Server *s, Room *r, const char *password) {
    room_password_store(s, password ? password : "", r->password);
    DBRoom *dr = db_find_room(&s->db, r->code);
    if (dr) {
        strncpy(dr->password, r->password, DB_PASSWORD_LEN - 1);
        dr->password[DB_PASSWORD_LEN - 1] = '\0';
        db_clear_trusted(dr);
    }
}

// Clear all snapshots (doors, enemies, pickups, pushables) belonging to a room.
// Called when the last player in a room disconnects.
void server_clear_room_snapshots(Server *s, int room_idx) {
    for (int i = 0; i < MAX_DOOR_SNAPSHOTS; i++)
        if (s->doors[i].used && s->doors[i].room_idx == room_idx)
            memset(&s->doors[i], 0, sizeof(s->doors[i]));
    for (int i = 0; i < MAX_PUSH_SNAPSHOTS; i++)
        if (s->pushables[i].used && s->pushables[i].room_idx == room_idx)
            memset(&s->pushables[i], 0, sizeof(s->pushables[i]));
    for (int i = 0; i < MAX_ENEMY_SNAPSHOTS; i++)
        if (s->enemies[i].used && s->enemies[i].room_idx == room_idx)
            memset(&s->enemies[i], 0, sizeof(s->enemies[i]));
    for (int i = 0; i < MAX_PICKUP_SNAPSHOTS; i++)
        if (s->pickups[i].used && s->pickups[i].room_idx == room_idx)
            memset(&s->pickups[i], 0, sizeof(s->pickups[i]));
    for (int i = 0; i < MAX_TRIGGERS; i++)
        if (s->triggers[i].used && s->triggers[i].room_idx == room_idx)
            memset(&s->triggers[i], 0, sizeof(s->triggers[i]));
}

int server_room_player_count(Server *s, int room_idx) {
    int count = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used && s->players[i].room_idx == room_idx && !s->players[i].is_sim)
            count++;
    return count;
}

// ---------------------------------------------------------------------------
// Player management
// ---------------------------------------------------------------------------

static int next_player_id(Server *s) {
    // Use Server-owned counter instead of static local — safe if ever
    // called from multiple threads, and survives repeated server_init calls.
    for (;;) {
        if (s->player_id_seq <= 0) s->player_id_seq = 1000;
        int id = s->player_id_seq++;
        if (!server_find_player_by_id(s, id))
            return id;
    }
}

Player *server_find_player_by_addr(Server *s, const Addr *addr) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used && addr_eq(&s->players[i].addr, addr))
            return &s->players[i];
    return NULL;
}

Player *server_find_player_by_id(Server *s, int id) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used && s->players[i].id == id)
            return &s->players[i];
    return NULL;
}

Player *server_find_player_by_token(Server *s, int room_idx, const uint8_t token[32]) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->room_idx == room_idx && memcmp(p->session_token, token, 32) == 0)
            return p;
    }
    return NULL;
}

static Player *alloc_player(Server *s) {
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (!s->players[i].used)
            return &s->players[i];
    return NULL;
}

static int total_clients(Server *s) {
    int n = 0;
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used) n++;
    return n;
}

// ---------------------------------------------------------------------------
// Send / relay
// ---------------------------------------------------------------------------

// Only for the handshake, which happens before a session exists.
static void server_send_raw(Server *s, const Addr *addr, const char *msg, int len) {
    s->stats.tx_bytes += (uint64_t)len;
    s->stats.tx_packets++;
    sendto(s->sock, msg, len, 0,
           (const struct sockaddr *)&addr->sa, sizeof(addr->sa));
}

static void send_sealed(Server *s, const Addr *addr, const uint8_t result_key[32], const uint8_t *session_pub,
                        const void *msg, int len) {
    uint8_t out[OL_HS_RESULT_MAX];
    int n = ol_hs_server_result(result_key, session_pub, msg, len, out);
    if (n > 0)
        server_send_raw(s, addr, (const char *)out, n);
}

static void player_send(Player *p, const char *msg, int len) {
    int lane = OL_LANE_RELIABLE;
    if (len >= 2 && (unsigned char)msg[0] <= OL_CHANNEL_MAX)
        lane = ol_lane_for((uint8_t)msg[0], (uint8_t)msg[1]);
    ol_conn_send(&p->conn, lane, msg, len);
}

void server_send(Server *s, const Addr *addr, const char *msg, int len) {
    Player *p = server_find_player_by_addr(s, addr);
    if (p)
        player_send(p, msg, len);
}

void server_relay(Server *s, Player *sender, const char *payload, int len) {
    int room_idx = sender->room_idx;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p != sender && p->room_idx == room_idx && p->in_world)
            player_send(p, payload, len);
    }
}

void server_broadcast_room(Server *s, int room_idx, const char *msg, int len) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->room_idx == room_idx)
            server_send(s, &p->addr, msg, len);
    }
}

/*
 * Server→client binary format: [type(1)][pad LE4=0][payload...]
 * Matches the client binary framing: [type(1)][sender_id LE4][payload...].
 * SRV packets use sender_id=0 (pad) since they originate from the server.
 */
#define SRV_HDR_INIT(buf, type) \
    do { (buf)[0]=(type); (buf)[1]=0; (buf)[2]=0; (buf)[3]=0; (buf)[4]=0; } while(0)

/* Send SRV_READY: [type(1)][pad(4)][player_id LE4][name_len(1)][name...][token(32)]
 * token — 32-byte session token for NAT rebind identification (echoed in HELLO).
 * conn_id — identifies this session in every later datagram. */
static void send_ready(Server *s, const Addr *addr, const uint8_t result_key[32], const uint8_t session_pub[32], int player_id, const uint8_t token[32], uint64_t conn_id) {
    unsigned char buf[306]; /* 5 hdr + 4 id + 1 namelen + 255 name + 32 token + 8 conn_id */
    int ci;
    SRV_HDR_INIT(buf, SRV_READY);
    int name_len = (int)strlen(s->name);
    if (name_len > 255) name_len = 255;
    buf[5] = (unsigned char)(player_id & 0xFF);
    buf[6] = (unsigned char)((player_id >> 8)  & 0xFF);
    buf[7] = (unsigned char)((player_id >> 16) & 0xFF);
    buf[8] = (unsigned char)((player_id >> 24) & 0xFF);
    buf[9] = (unsigned char)name_len;
    memcpy(buf + 10, s->name, name_len);
    memcpy(buf + 10 + name_len, token, 32);
    for (ci = 0; ci < 8; ci++)
        buf[10 + name_len + 32 + ci] = (unsigned char)(conn_id >> (8 * ci));
    send_sealed(s, addr, result_key, session_pub, buf, 10 + name_len + 32 + 8);
}

/* Send SRV_ONLINE_COUNT: [0x28][0x00000000][count LE4] */
static void send_online_count(Server *s, const Addr *addr, int count) {
    unsigned char buf[9];
    SRV_HDR_INIT(buf, SRV_ONLINE_COUNT);
    buf[5] = (unsigned char)(count & 0xFF);
    buf[6] = (unsigned char)((count >> 8)  & 0xFF);
    buf[7] = (unsigned char)((count >> 16) & 0xFF);
    buf[8] = (unsigned char)((count >> 24) & 0xFF);
    server_send(s, addr, (const char *)buf, 9);
}

/* Broadcast SRV_ONLINE_COUNT to all players in a room */
static void broadcast_online_count(Server *s, int room_idx, int count) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->room_idx == room_idx)
            send_online_count(s, &p->addr, count);
    }
}

/* Send SRV_HELLO_FAIL: [0x29][0x00000000][reason_len(1)][reason ASCII] */
static void send_hello_fail(Server *s, const Addr *addr, const uint8_t result_key[32], const char *reason) {
    s->stats.auth_refused++;
    unsigned char buf[262];
    SRV_HDR_INIT(buf, SRV_HELLO_FAIL);
    int rlen = (int)strlen(reason);
    if (rlen > 255) rlen = 255;
    buf[5] = (unsigned char)rlen;
    memcpy(buf + 6, reason, rlen);
    send_sealed(s, addr, result_key, NULL, buf, 6 + rlen);
}

/* Send SRV_DISCONNECT: [0x2A][0x00000000][player_id LE4] */
static void send_disconnect_notify(Server *s, int room_idx, int player_id) {
    unsigned char buf[9];
    SRV_HDR_INIT(buf, SRV_DISCONNECT);
    buf[5] = (unsigned char)(player_id & 0xFF);
    buf[6] = (unsigned char)((player_id >> 8)  & 0xFF);
    buf[7] = (unsigned char)((player_id >> 16) & 0xFF);
    buf[8] = (unsigned char)((player_id >> 24) & 0xFF);
    server_broadcast_room(s, room_idx, (const char *)buf, 9);
}

/* Send PUSH_DENIED: [CH_PUSH][PUSH_DENIED][0 LE4][KeyX(4)][KeyY(4)][KeyZ(4)] */
static void send_push_denied(Server *s, const Addr *addr, const char *key_xyz) {
    unsigned char buf[OL_HEADER_SIZE + 12];
    memset(buf, 0, sizeof(buf));
    buf[0] = CH_PUSH;
    buf[1] = PUSH_DENIED;
    memcpy(buf + OL_HEADER_SIZE, key_xyz, 12);
    server_send(s, addr, (const char *)buf, sizeof(buf));
}

/* Send SRV_DOOR_DENY: [0x2B][0x00000000][key_len(1)][key ASCII] */
static void send_door_deny(Server *s, const Addr *addr, const char *key) {
    unsigned char buf[262];
    SRV_HDR_INIT(buf, SRV_DOOR_DENY);
    int klen = (int)strlen(key);
    if (klen > 255) klen = 255;
    buf[5] = (unsigned char)klen;
    memcpy(buf + 6, key, klen);
    server_send(s, addr, (const char *)buf, 6 + klen);
}

// ---------------------------------------------------------------------------
// Door snapshots
// ---------------------------------------------------------------------------

DoorSnapshot *door_find(Server *s, int room_idx, const char *key) {
    for (int i = 0; i < MAX_DOOR_SNAPSHOTS; i++) {
        DoorSnapshot *d = &s->doors[i];
        if (d->used && d->room_idx == room_idx && strcmp(d->key, key) == 0)
            return d;
    }
    return NULL;
}

DoorSnapshot *door_alloc(Server *s, int room_idx, const char *key) {
    DoorSnapshot *d = door_find(s, room_idx, key);
    if (d) return d;
    for (int i = 0; i < MAX_DOOR_SNAPSHOTS; i++) {
        if (!s->doors[i].used) {
            memset(&s->doors[i], 0, sizeof(s->doors[i]));
            s->doors[i].used = 1;
            s->doors[i].room_idx = room_idx;
            strncpy(s->doors[i].key, key, MAX_DOOR_KEY - 1);
            return &s->doors[i];
        }
    }
    return NULL;
}

// Release door authority held by a specific player in a room.
void door_release_authority(Server *s, int room_idx, int player_id) {
    for (int i = 0; i < MAX_DOOR_SNAPSHOTS; i++) {
        DoorSnapshot *d = &s->doors[i];
        if (d->used && d->room_idx == room_idx && d->authority_player_id == player_id)
            d->authority_player_id = 0;
    }
}

// ---------------------------------------------------------------------------
// Enemy snapshots
// ---------------------------------------------------------------------------

EnemySnapshot *enemy_find(Server *s, int room_idx, const char *name) {
    for (int i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
        EnemySnapshot *e = &s->enemies[i];
        if (e->used && e->room_idx == room_idx && strcmp(e->name, name) == 0)
            return e;
    }
    return NULL;
}

EnemySnapshot *enemy_alloc(Server *s, int room_idx, const char *name, int owner_player_id) {
    EnemySnapshot *e = enemy_find(s, room_idx, name);
    if (e) {
        e->owner_player_id = owner_player_id;
        return e;
    }
    for (int i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
        if (!s->enemies[i].used) {
            memset(&s->enemies[i], 0, sizeof(s->enemies[i]));
            s->enemies[i].used = 1;
            s->enemies[i].room_idx = room_idx;
            s->enemies[i].owner_player_id = owner_player_id;
            strncpy(s->enemies[i].name, name, MAX_ENEMY_NAME - 1);
            return &s->enemies[i];
        }
    }
    return NULL;
}

void enemy_remove(Server *s, int room_idx, const char *name) {
    EnemySnapshot *e = enemy_find(s, room_idx, name);
    if (e) memset(e, 0, sizeof(*e));
}

void enemy_remove_all_for_player(Server *s, int room_idx, int player_id) {
    for (int i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
        EnemySnapshot *e = &s->enemies[i];
        if (e->used && e->room_idx == room_idx && e->owner_player_id == player_id)
            memset(e, 0, sizeof(*e));
    }
}

// ---------------------------------------------------------------------------
// Pickup snapshots
// ---------------------------------------------------------------------------

PickupSnapshot *pickup_find(Server *s, int room_idx, const char *key) {
    for (int i = 0; i < MAX_PICKUP_SNAPSHOTS; i++) {
        PickupSnapshot *p = &s->pickups[i];
        if (p->used && p->room_idx == room_idx && strcmp(p->key, key) == 0)
            return p;
    }
    return NULL;
}

PickupSnapshot *pickup_alloc(Server *s, int room_idx, const char *key) {
    PickupSnapshot *p = pickup_find(s, room_idx, key);
    if (p) return p;
    for (int i = 0; i < MAX_PICKUP_SNAPSHOTS; i++) {
        if (!s->pickups[i].used) {
            memset(&s->pickups[i], 0, sizeof(s->pickups[i]));
            s->pickups[i].used = 1;
            s->pickups[i].room_idx = room_idx;
            strncpy(s->pickups[i].key, key, MAX_PICKUP_KEY - 1);
            return &s->pickups[i];
        }
    }
    return NULL;
}

PushSnapshot *push_find(Server *s, int room_idx, const char *key) {
    for (int i = 0; i < MAX_PUSH_SNAPSHOTS; i++) {
        PushSnapshot *p = &s->pushables[i];
        if (p->used && p->room_idx == room_idx && strcmp(p->key, key) == 0)
            return p;
    }
    return NULL;
}

PushSnapshot *push_alloc(Server *s, int room_idx, const char *key) {
    PushSnapshot *p = push_find(s, room_idx, key);
    if (p) return p;
    for (int i = 0; i < MAX_PUSH_SNAPSHOTS; i++) {
        if (!s->pushables[i].used) {
            memset(&s->pushables[i], 0, sizeof(s->pushables[i]));
            s->pushables[i].used = 1;
            s->pushables[i].room_idx = room_idx;
            strncpy(s->pushables[i].key, key, MAX_PUSH_KEY - 1);
            return &s->pushables[i];
        }
    }
    return NULL;
}

void push_release_owner(Server *s, int room_idx, int player_id) {
    for (int i = 0; i < MAX_PUSH_SNAPSHOTS; i++) {
        PushSnapshot *ps = &s->pushables[i];
        if (ps->used && ps->room_idx == room_idx && ps->owner_player_id == player_id)
            ps->owner_player_id = 0;
    }
}

// ---------------------------------------------------------------------------
// Snapshot drip-feed queue
// ---------------------------------------------------------------------------

// Enqueue one snapshot packet for drip-feed delivery to a player.
// Silently drops if the queue is full (caller already logged a warning at join).
void server_snap_enqueue(Player *p, const char *data, int len) {
    if (len <= 0 || len > SNAP_PKT_MAX) return;
    int next = (p->snap_head + 1) % SNAP_QUEUE_MAX;
    if (next == p->snap_tail) return; // queue full — drop
    memcpy(p->snap_queue[p->snap_head].data, data, len);
    p->snap_queue[p->snap_head].len = len;
    p->snap_head = next;
}

// Send up to SNAP_DRIP_PER_TICK queued snapshots per player every SNAP_DRIP_INTERVAL.
// Called from server_run each iteration; time-gated because an iteration runs for
// every incoming packet, which would otherwise tie the drip rate to server load.
void server_drain_snaps(Server *s) {
    double now = mono_now();
    if (now < s->next_snap_drain) return;
    s->next_snap_drain = now + SNAP_DRIP_INTERVAL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (!p->used || p->snap_head == p->snap_tail) continue;
        int sent = 0;
        // Always reliable, even for packets that normally use the state lane:
        // a newcomer must not miss the only copy of an enemy position.
        while (p->snap_head != p->snap_tail && sent < SNAP_DRIP_PER_TICK
               && ol_conn_reliable_room(&p->conn) > 0) {
            SnapEntry *e = &p->snap_queue[p->snap_tail];
            ol_conn_send(&p->conn, OL_LANE_RELIABLE, e->data, e->len);
            p->snap_tail = (p->snap_tail + 1) % SNAP_QUEUE_MAX;
            sent++;
        }
    }
}

// Queue all player STATE snapshots and world snapshots for drip-feed delivery to a newcomer.
void send_snapshots_to_newcomer(Server *s, Player *newcomer) {
    // Reset drip queue for this player (may have stale data from previous join)
    newcomer->snap_head = 0;
    newcomer->snap_tail = 0;

    // Player state snapshots (binary STATE packets from other players)
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (!p->used || p == newcomer || p->room_idx != newcomer->room_idx || !p->in_world)
            continue;
        if (p->state_snap_len > 0)
            server_snap_enqueue(newcomer, (const char *)p->state_snap, p->state_snap_len);
        if (p->matinee_snap_len > 0)
            server_snap_enqueue(newcomer, (const char *)p->matinee_snap, p->matinee_snap_len);
    }
    // Door snapshots: DOOR_LOCK (if held), DOOR_STATE, DOOR_ANGLE
    for (int i = 0; i < MAX_DOOR_SNAPSHOTS; i++) {
        DoorSnapshot *d = &s->doors[i];
        if (!d->used || d->room_idx != newcomer->room_idx) continue;
        if (d->authority_player_id != 0 && d->authority_player_id != newcomer->id && d->lock_len > 0) {
            Player *auth = server_find_player_by_id(s, d->authority_player_id);
            if (auth && auth->used)
                server_snap_enqueue(newcomer, d->lock_pkt, d->lock_len);
        }
        if (d->state_len > 0) server_snap_enqueue(newcomer, d->state_pkt, d->state_len);
        if (d->angle_len > 0) server_snap_enqueue(newcomer, d->angle_pkt, d->angle_len);
    }
    // Enemy snapshots: skip enemies owned by newcomer
    for (int i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
        EnemySnapshot *e = &s->enemies[i];
        if (!e->used || e->room_idx != newcomer->room_idx) continue;
        if (e->owner_player_id == newcomer->id) continue;
        if (e->spawn_len > 0) server_snap_enqueue(newcomer, e->spawn_pkt, e->spawn_len);
        if (e->smt_len   > 0) server_snap_enqueue(newcomer, e->smt_pkt,   e->smt_len);
        if (e->anim_len  > 0) server_snap_enqueue(newcomer, e->anim_pkt,  e->anim_len);
        if (e->loc_len   > 0) server_snap_enqueue(newcomer, e->loc_pkt,   e->loc_len);
    }
    // Pushable snapshots — always send with bPushing=0 (offset 26) so newcomers
    // don't start a looping sound for a push that is no longer active.
    {
        int i;
        for (i = 0; i < MAX_PUSH_SNAPSHOTS; i++) {
            PushSnapshot *ps = &s->pushables[i];
            if (!ps->used || ps->room_idx != newcomer->room_idx) continue;
            if (ps->pkt_len > 0) {
                char tmp[MAX_PUSH_SNAP_DATA];
                memcpy(tmp, ps->pkt, ps->pkt_len);
                if (ps->pkt_len > 26) tmp[26] = 0; /* clear bPushing */
                server_snap_enqueue(newcomer, tmp, ps->pkt_len);
            }
        }
    }
    // Pickup snapshots
    for (int i = 0; i < MAX_PICKUP_SNAPSHOTS; i++) {
        PickupSnapshot *p = &s->pickups[i];
        if (!p->used || p->room_idx != newcomer->room_idx) continue;
        if (p->pkt_len > 0) server_snap_enqueue(newcomer, p->pkt, p->pkt_len);
    }
}

// ---------------------------------------------------------------------------
// Enemy AI authority: exactly one client in a room simulates enemies
// ---------------------------------------------------------------------------

static void send_sim_owner(Player *p, int owner_id) {
    unsigned char msg[OL_HEADER_SIZE + 4];
    memset(msg, 0, sizeof(msg));
    msg[0] = CH_SESS;
    msg[1] = SESS_SIM_OWNER;
    msg[OL_HEADER_SIZE]     = (unsigned char)(owner_id & 0xFF);
    msg[OL_HEADER_SIZE + 1] = (unsigned char)((owner_id >> 8) & 0xFF);
    msg[OL_HEADER_SIZE + 2] = (unsigned char)((owner_id >> 16) & 0xFF);
    msg[OL_HEADER_SIZE + 3] = (unsigned char)((owner_id >> 24) & 0xFF);
    player_send(p, (const char *)msg, sizeof(msg));
}

static void sim_set_owner(Server *s, int room_idx, int new_owner) {
    Room *room = &s->rooms[room_idx];
    int i;
    if (room->sim_owner == new_owner) return;
    // The old owner's enemies stop existing here; the new owner announces its own.
    if (room->sim_owner != 0)
        enemy_remove_all_for_player(s, room_idx, room->sim_owner);
    room->sim_owner = new_owner;
    server_log(s, "Room '%s' enemy AI owner: %d", room->code, new_owner);
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->room_idx == room_idx)
            send_sim_owner(p, new_owner);
    }
}

static void player_clear_world_snaps(Player *p);

static Player *sim_node(Server *s, int room_idx) {
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->is_sim && p->room_idx == room_idx)
            return p;
    }
    return NULL;
}

// Who can take over from exclude_id: the simulator if it is in the world, else a player, or 0.
static int sim_next_owner(Server *s, int room_idx, int exclude_id) {
    const Player *node = sim_node(s, room_idx);
    int i;
    if (node && node->in_world && node->id != exclude_id)
        return node->id;
    for (i = 0; i < MAX_CLIENTS; i++) {
        const Player *p = &s->players[i];
        if (p->used && p->room_idx == room_idx && p->in_world && p->id != exclude_id)
            return p->id;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

void server_disconnect(Server *s, Player *p) {
    int  room_idx = p->room_idx;
    int  pid      = p->id;
    int  was_sim  = p->is_sim;
    char ip[MAX_IP];
    char nick[MAX_NICK];
    strncpy(ip,   p->ip,   sizeof(ip)   - 1); ip[sizeof(ip)-1]     = '\0';
    strncpy(nick, p->nick, sizeof(nick) - 1); nick[sizeof(nick)-1] = '\0';

    if (s->rooms[room_idx].sim_owner == pid)
        sim_set_owner(s, room_idx, sim_next_owner(s, room_idx, pid));

    // Release any door authority this player held
    door_release_authority(s, room_idx, pid);
    // Remove all enemy snapshots owned by this player
    enemy_remove_all_for_player(s, room_idx, pid);
    // Release any pushable ownership this player held
    push_release_owner(s, room_idx, pid);

    ol_conn_free(&p->conn);
    memset(p, 0, sizeof(*p));   // mark as free

    // Notify remaining players
    if (!was_sim)
        send_disconnect_notify(s, room_idx, pid);

    // Updated online count
    int count = server_room_player_count(s, room_idx);
    broadcast_online_count(s, room_idx, count);

    // Clear all snapshots when the room becomes empty
    if (count == 0) {
        Room *room = &s->rooms[room_idx];
        Player *node = sim_node(s, room_idx);
        server_clear_room_snapshots(s, room_idx);
        room->world_persist[0] = '\0';
        room->world_cp[0] = '\0';
        // The simulator waits for the next player's world.
        if (node) {
            node->in_world = 0;
            player_clear_world_snaps(node);
        }
    }

    server_log(s, "[%s] ID=%d ('%s') disconnected (%d left in room)", ip, pid, nick, count);
    history_push(s, "[%s] disconnected", nick);
}

// ---------------------------------------------------------------------------
// HELLO rate limiter — prevents db_save DoS from unauthenticated senders.
// Simple fixed-window per-IP: max 5 HELLO attempts per 10-second window.
// ---------------------------------------------------------------------------

#define HELLO_RL_MAX      5
#define HELLO_RL_WINDOW   10.0
#define HELLO_RL_BUCKETS  64

typedef struct {
    char   ip[MAX_IP];
    int    count;
    double window_start;
} HelloBucket;

static HelloBucket hello_rl[HELLO_RL_BUCKETS];

// Returns 1 if allowed, 0 if rate-limited.
static int hello_check_rate(const char *ip) {
    double now = mono_now();
    // Hash IP to bucket (djb2-style)
    unsigned h = 5381;
    for (const char *p = ip; *p; p++) h = ((h << 5) + h) ^ (unsigned char)*p;
    int slot = (int)(h % HELLO_RL_BUCKETS);

    HelloBucket *b = &hello_rl[slot];
    // Reset window if IP changed or window expired
    if (b->ip[0] == '\0' || strcmp(b->ip, ip) != 0 ||
        now - b->window_start >= HELLO_RL_WINDOW) {
        strncpy(b->ip, ip, MAX_IP - 1);
        b->ip[MAX_IP - 1] = '\0';
        b->count = 1;
        b->window_start = now;
        return 1;
    }
    b->count++;
    return b->count <= HELLO_RL_MAX;
}

// ---------------------------------------------------------------------------
// HELLO handshake
// ---------------------------------------------------------------------------

static void send_world_msg(Player *p, unsigned char type, const Room *room);

static void handle_hs_hello(Server *s, const char *data, int len, const Addr *addr) {
    uint8_t out[OL_HS_CHALLENGE_BYTES];
    // Smaller than OL_HS_HELLO_BYTES would make the challenge an amplifier.
    if (len < OL_HS_HELLO_BYTES || (unsigned char)data[1] != OL_HS_VERSION) return;
    ol_hs_server_challenge(&s->hs, &addr->sa, sizeof(addr->sa), (uint32_t)time(NULL), out);
    server_send_raw(s, addr, (const char *)out, sizeof(out));
}

static void handle_hs_auth(Server *s, const char *data, int len, const Addr *addr) {
    // Static so a burst of attempts does not put this on the stack over and over.
    static OlHsAuth auth;
    if (!ol_hs_server_auth(&s->hs, &addr->sa, sizeof(addr->sa), (uint32_t)time(NULL),
                           (const uint8_t *)data, len, &auth))
        return;
    const uint8_t *result_key = auth.result_key;
    const char *code = auth.room;

    if (!code[0]) {
        send_hello_fail(s, addr, result_key, "invalid room");
        return;
    }

    char client_ip[MAX_IP];
    addr_ip_str(addr, client_ip, sizeof(client_ip));

    // Bounds password guessing per address.
    if (!hello_check_rate(client_ip)) return;

    if (db_find_ban(&s->db, client_ip)) {
        send_hello_fail(s, addr, result_key, "banned");
        return;
    }

    Room *room = server_find_room(s, code);
    if (!room) {
        send_hello_fail(s, addr, result_key, "unknown room");
        return;
    }
    int room_idx = (int)(room - s->rooms);

    {
        DBRoom *dr_check = db_find_room(&s->db, code);
        if (dr_check && db_find_room_ban(dr_check, client_ip)) {
            send_hello_fail(s, addr, result_key, "banned from room");
            return;
        }
    }

    const int is_sim = auth.role == OL_ROLE_SIM;
    if (is_sim) {
        // Whoever owns the AI decides what enemies do to players, so a room password is not enough.
        Player *node = sim_node(s, room_idx);
        if (!s->sim_secret[0] || !ol_hs_proof_ok_secret(&auth, s->sim_secret)) {
            server_log(s, "[%s] refused as simulator: wrong secret", client_ip);
            send_hello_fail(s, addr, result_key, "simulator not allowed");
            return;
        }
        if (node && memcmp(node->hs_client_pub, auth.client_pub, 32) != 0) {
            send_hello_fail(s, addr, result_key, "room already has a simulator");
            return;
        }
    } else if (room->password[0] && !room_password_ok(room, &auth)) {
        send_hello_fail(s, addr, result_key, "wrong password");
        return;
    }

    Player *pl = NULL;
    uint8_t session_pub[32];
    for (int i = 0; i < MAX_CLIENTS && !pl; i++) {
        Player *p = &s->players[i];
        if (p->used && memcmp(p->hs_client_pub, auth.client_pub, 32) == 0) {
            // Our answer got lost and the client repeated itself: same session, same keys.
            p->addr = *addr;
            send_ready(s, addr, result_key, p->hs_session_pub, p->id, p->session_token, p->conn.conn_id);
            return;
        }
    }

    if (!ol_hs_server_session(&auth, session_pub)) return;

    // The token is the only way to take over a session that is already in use.
    if (auth.has_token) {
        pl = server_find_player_by_token(s, room_idx, auth.token);
        if (pl)
            server_log(s, "[%s] ID=%d resumed its session (port %d->%d)", client_ip, pl->id,
                       ntohs(pl->addr.sa.sin_port), ntohs(addr->sa.sin_port));
    }
    // Earlier attempt from this address whose answer never arrived: nothing runs on it yet.
    if (!pl) {
        Player *p = server_find_player_by_addr(s, addr);
        if (p && p->room_idx == room_idx && !p->conn.have_counter)
            pl = p;
    }
    if (pl) {
        int count;
        pl->addr = *addr;
        pl->is_sim = is_sim;
        memcpy(pl->hs_client_pub, auth.client_pub, 32);
        memcpy(pl->hs_session_pub, session_pub, 32);
        count = server_room_player_count(s, pl->room_idx);
        // The client starts a fresh transport session for every handshake.
        ol_conn_reset(&pl->conn, gen_conn_id());
        ol_conn_set_keys(&pl->conn, auth.s2c_key, auth.c2s_key);
        send_ready(s, addr, result_key, session_pub, pl->id, pl->session_token, pl->conn.conn_id);
        send_online_count(s, addr, count);
        if (room->sim_owner != 0)
            send_sim_owner(pl, room->sim_owner);
        // The client reports its world next (SESS_ENTER) and gets the snapshots then.
        pl->in_world = 0;
        if (is_sim && room->world_persist[0])
            send_world_msg(pl, SESS_TRAVEL, room);
        return;
    }

    if (total_clients(s) >= MAX_CLIENTS) {
        send_hello_fail(s, addr, result_key, "server full");
        return;
    }

    pl = alloc_player(s);
    if (!pl) {
        send_hello_fail(s, addr, result_key, "server full");
        return;
    }

    memset(pl, 0, sizeof(*pl));
    pl->used      = 1;
    pl->id        = next_player_id(s);
    pl->room_idx  = (int)(room - s->rooms);
    pl->addr      = *addr;
    pl->last_seen = mono_now();
    pl->pkt_window = pl->last_seen;
    addr_ip_str(addr, pl->ip, sizeof(pl->ip));
    snprintf(pl->nick, sizeof(pl->nick), "Player%d", pl->id);
    pl->is_sim    = is_sim;
    memcpy(pl->hs_client_pub, auth.client_pub, 32);
    memcpy(pl->hs_session_pub, session_pub, 32);
    gen_session_token(pl->session_token);
    ol_conn_reset(&pl->conn, gen_conn_id());
    ol_conn_set_keys(&pl->conn, auth.s2c_key, auth.c2s_key);

    int count = server_room_player_count(s, pl->room_idx);
    server_log(s, "[%s:%d] ID=%d joined room '%s' (%d players)",
               pl->ip, ntohs(addr->sa.sin_port), pl->id, code, count);
    history_push(s, "[%s] joined room %s", pl->nick, code);

    // Notify existing players of new count
    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *other = &s->players[i];
        if (other->used && other != pl && other->room_idx == pl->room_idx)
            send_online_count(s, &other->addr, count);
    }

    s->stats.auth_ok++;
    send_ready(s, addr, result_key, session_pub, pl->id, pl->session_token, pl->conn.conn_id);
    send_online_count(s, addr, count);
    // Known before the client loads a map, so it does not spawn enemies of its own.
    if (room->sim_owner != 0)
        send_sim_owner(pl, room->sim_owner);
    if (is_sim) {
        server_log(s, "Room '%s' simulator: ID=%d", room->code, pl->id);
        if (room->world_persist[0])
            send_world_msg(pl, SESS_TRAVEL, room);
    }
}

// ---------------------------------------------------------------------------
// Packet dispatch
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Session: which world each player is in
// ---------------------------------------------------------------------------

// Lengths include what fits in MAX_WORLD_NAME; returns the new offset or -1 if malformed.
static int read_world_str(const char *data, int len, int off, char out[MAX_WORLD_NAME]) {
    int n;
    if (off >= len) return -1;
    n = (unsigned char)data[off++];
    if (n >= MAX_WORLD_NAME || off + n > len) return -1;
    memcpy(out, data + off, n);
    out[n] = '\0';
    return off + n;
}

static int world_name_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
    }
    return *a == *b;
}

static int write_world_msg(unsigned char *buf, unsigned char type, const Room *room) {
    int n = OL_HEADER_SIZE, cp_len = (int)strlen(room->world_cp), persist_len = (int)strlen(room->world_persist);
    memset(buf, 0, OL_HEADER_SIZE);
    buf[0] = CH_SESS;
    buf[1] = type;
    buf[n++] = (unsigned char)(room->epoch & 0xFF);
    buf[n++] = (unsigned char)(room->epoch >> 8);
    buf[n++] = (unsigned char)cp_len;
    memcpy(buf + n, room->world_cp, cp_len);
    n += cp_len;
    buf[n++] = (unsigned char)persist_len;
    memcpy(buf + n, room->world_persist, persist_len);
    return n + persist_len;
}

static void send_world_msg(Player *p, unsigned char type, const Room *room) {
    unsigned char buf[OL_HEADER_SIZE + 4 + 2 * MAX_WORLD_NAME];
    player_send(p, (const char *)buf, write_world_msg(buf, type, room));
}

static void player_clear_world_snaps(Player *p) {
    p->state_snap_len = 0;
    p->matinee_snap_len = 0;
    p->snap_head = 0;
    p->snap_tail = 0;
}

static void session_join(Server *s, Player *pl) {
    Room *room = &s->rooms[pl->room_idx];
    unsigned char end[OL_HEADER_SIZE + 2];
    pl->in_world = 1;
    pl->hero_known = 0;  // a new spawn point is not movement
    if (room->sim_owner == 0)
        sim_set_owner(s, pl->room_idx, pl->id);
    else
        send_sim_owner(pl, room->sim_owner);
    // (Re)entering means the hero is not holding anything any more.
    door_release_authority(s, pl->room_idx, pl->id);
    push_release_owner(s, pl->room_idx, pl->id);
    send_world_msg(pl, SESS_WORLD, room);
    send_snapshots_to_newcomer(s, pl);
    memset(end, 0, sizeof(end));
    end[0] = CH_SESS;
    end[1] = SESS_BASELINE_END;
    end[OL_HEADER_SIZE] = (unsigned char)(room->epoch & 0xFF);
    end[OL_HEADER_SIZE + 1] = (unsigned char)(room->epoch >> 8);
    server_snap_enqueue(pl, (const char *)end, sizeof(end));
}

// Replaces the world: everything known about the old one is dropped and all other
// players are told to follow. The new epoch makes their late packets harmless.
static void session_new_world(Server *s, Player *pl, const char *cp, const char *persist) {
    Room *room = &s->rooms[pl->room_idx];
    int i;
    Player *node = sim_node(s, pl->room_idx);
    server_clear_room_snapshots(s, pl->room_idx);
    // A new world starts with the simulator in charge, even while it is still loading.
    if (node)
        sim_set_owner(s, pl->room_idx, node->id);
    strncpy(room->world_cp, cp, MAX_WORLD_NAME - 1);
    room->world_cp[MAX_WORLD_NAME - 1] = '\0';
    strncpy(room->world_persist, persist, MAX_WORLD_NAME - 1);
    room->world_persist[MAX_WORLD_NAME - 1] = '\0';
    if (++room->epoch == 0) room->epoch = 1;
    server_log(s, "Room '%s' world: %s cp=%s epoch=%d", room->code, persist, cp, (int)room->epoch);
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (!p->used || p->room_idx != pl->room_idx) continue;
        player_clear_world_snaps(p);
        if (p != pl) {
            p->in_world = 0;
            send_world_msg(p, SESS_TRAVEL, room);
        }
    }
    session_join(s, pl);
}

static int session_others_in_world(const Server *s, const Player *pl) {
    int i, n = 0;
    for (i = 0; i < MAX_CLIENTS; i++) {
        const Player *p = &s->players[i];
        if (p->used && p != pl && p->room_idx == pl->room_idx && p->in_world && !p->is_sim) n++;
    }
    return n;
}

static void session_enter(Server *s, Player *pl, const char *data, int len) {
    Room *room = &s->rooms[pl->room_idx];
    char cp[MAX_WORLD_NAME], persist[MAX_WORLD_NAME];
    int off = OL_HEADER_SIZE + 3, others;
    uint16_t epoch;
    unsigned char flags;

    if (len < off) return;
    epoch = (uint16_t)((unsigned char)data[OL_HEADER_SIZE] | ((unsigned char)data[OL_HEADER_SIZE + 1] << 8));
    flags = (unsigned char)data[OL_HEADER_SIZE + 2];
    off = read_world_str(data, len, off, cp);
    if (off < 0) return;
    off = read_world_str(data, len, off, persist);
    if (off < 0 || !persist[0]) return;

    // The simulator follows the players and never changes the world for them.
    if (pl->is_sim) {
        if (!room->world_persist[0]) return;
        if (epoch == room->epoch && world_name_eq(persist, room->world_persist))
            session_join(s, pl);
        else
            send_world_msg(pl, SESS_TRAVEL, room);
        return;
    }

    others = session_others_in_world(s, pl);
    if (!room->world_persist[0]
        || (others == 0 && !world_name_eq(persist, room->world_persist))
        || ((flags & SESS_ENTER_RESET) && (epoch != 0 || others == 0))) {
        session_new_world(s, pl, cp, persist);
    } else if (world_name_eq(persist, room->world_persist) || epoch == room->epoch) {
        session_join(s, pl);
    } else if (epoch == 0) {
        // A fresh connection joins the running world instead of replacing it.
        pl->in_world = 0;
        send_world_msg(pl, SESS_TRAVEL, room);
    }
    // Otherwise the client is behind: its SESS_TRAVEL is already on the way.
}

static void session_checkpoint(Server *s, Player *pl, const char *data, int len) {
    Room *room = &s->rooms[pl->room_idx];
    char cp[MAX_WORLD_NAME], persist[MAX_WORLD_NAME];
    int off = read_world_str(data, len, OL_HEADER_SIZE, cp);
    if (off < 0 || !pl->in_world || pl->is_sim) return;
    off = read_world_str(data, len, off, persist);
    if (off < 0 || !persist[0]) return;

    if (world_name_eq(persist, room->world_persist)) {
        strncpy(room->world_cp, cp, MAX_WORLD_NAME - 1);
        room->world_cp[MAX_WORLD_NAME - 1] = '\0';
    } else {
        session_new_world(s, pl, cp, persist);
    }
}

static void notify_player_left(Server *s, const Player *pl) {
    unsigned char msg[OL_HEADER_SIZE + 4];
    int i;
    memset(msg, 0, sizeof(msg));
    msg[0] = CH_SESS;
    msg[1] = SESS_PLAYER_LEFT;
    msg[OL_HEADER_SIZE]     = (unsigned char)(pl->id & 0xFF);
    msg[OL_HEADER_SIZE + 1] = (unsigned char)((pl->id >> 8) & 0xFF);
    msg[OL_HEADER_SIZE + 2] = (unsigned char)((pl->id >> 16) & 0xFF);
    msg[OL_HEADER_SIZE + 3] = (unsigned char)((pl->id >> 24) & 0xFF);
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p != pl && p->room_idx == pl->room_idx)
            player_send(p, (const char *)msg, sizeof(msg));
    }
}

static void session_leave(Server *s, Player *pl) {
    if (!pl->in_world) return;
    pl->in_world = 0;
    if (s->rooms[pl->room_idx].sim_owner == pl->id)
        sim_set_owner(s, pl->room_idx, sim_next_owner(s, pl->room_idx, pl->id));
    door_release_authority(s, pl->room_idx, pl->id);
    push_release_owner(s, pl->room_idx, pl->id);
    enemy_remove_all_for_player(s, pl->room_idx, pl->id);
    player_clear_world_snaps(pl);
    if (!pl->is_sim)
        notify_player_left(s, pl);
}

static void handle_session(Server *s, Player *pl, unsigned char ptype, const char *data, int len) {
    switch (ptype) {
        case SESS_ENTER:      session_enter(s, pl, data, len); break;
        case SESS_CHECKPOINT: session_checkpoint(s, pl, data, len); break;
        case SESS_LEAVE:      session_leave(s, pl); break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// Trigger arbiter
// ---------------------------------------------------------------------------

static TriggerState *trigger_find_or_alloc(Server *s, int room_idx, uint64_t hash) {
    TriggerState *free_slot = NULL;
    int i;
    for (i = 0; i < MAX_TRIGGERS; i++) {
        TriggerState *t = &s->triggers[i];
        if (t->used) {
            if (t->room_idx == room_idx && t->path_hash == hash) return t;
        } else if (!free_slot) {
            free_slot = t;
        }
    }
    if (free_slot) {
        free_slot->used = 1;
        free_slot->room_idx = room_idx;
        free_slot->path_hash = hash;
        free_slot->count = 0;
        free_slot->last_fire = 0.0;
    }
    return free_slot;
}

// Decides one use of a limited world object. kind keeps triggers, CSAs and pickups
// apart. Returns 1 and the new use count if the sender gets it.
static uint64_t arbiter_hash(unsigned char kind, const unsigned char *path, int path_len) {
    uint64_t hash = 1469598103934665603ULL ^ kind;  /* FNV-1a */
    int i;
    for (i = 0; i < path_len; i++) {
        hash ^= path[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int arbiter_allow(Server *s, Player *pl, unsigned char kind, int max_count,
                         const unsigned char *path, int path_len, int *count) {
    TriggerState *t;
    double now = mono_now();

    *count = 1;
    t = trigger_find_or_alloc(s, pl->room_idx, arbiter_hash(kind, path, path_len));
    if (!t) return 1;  // table full: fail open rather than block the story

    if (max_count > 0 && t->count >= max_count) return 0;
    if (max_count == 0 && t->count > 0 && now - t->last_fire < TRIGGER_REPEAT_WINDOW) return 0;
    t->count++;
    t->last_fire = now;
    *count = t->count;
    return 1;
}

static void send_to_world(Server *s, const Player *pl, const char *data, int len) {
    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->room_idx == pl->room_idx && p->in_world)
            player_send(p, data, len);
    }
}

// [header][maxCount(1)][pathLen(1)][path]: fire for everyone or refuse the sender.
static void handle_trigger_fire(Server *s, Player *pl, const char *data, int len) {
    const unsigned char *u = (const unsigned char *)data;
    int path_len, count;

    if (len < OL_HEADER_SIZE + 2) return;
    path_len = u[OL_HEADER_SIZE + 1];
    if (path_len == 0 || OL_HEADER_SIZE + 2 + path_len > len) return;

    if (arbiter_allow(s, pl, 0, u[OL_HEADER_SIZE], u + OL_HEADER_SIZE + 2, path_len, &count)) {
        history_push(s, "[%s] Trigger %.*s", pl->nick, path_len > 80 ? 80 : path_len, data + OL_HEADER_SIZE + 2);
        send_to_world(s, pl, data, len);
    } else {
        unsigned char deny[OL_HEADER_SIZE + 1 + 255];
        memset(deny, 0, OL_HEADER_SIZE);
        deny[0] = CH_WORLD;
        deny[1] = WORLD_TRIGGER_DENIED;
        deny[OL_HEADER_SIZE] = (unsigned char)path_len;
        memcpy(deny + OL_HEADER_SIZE + 1, data + OL_HEADER_SIZE + 2, path_len);
        player_send(pl, (const char *)deny, OL_HEADER_SIZE + 1 + path_len);
    }
}

// [header][kind(1)][maxCount(1)][pathLen(1)][path]: the grant goes to everyone so losers
// learn the object is used before they hear their own refusal.
static void handle_claim(Server *s, Player *pl, const char *data, int len) {
    const unsigned char *u = (const unsigned char *)data;
    unsigned char out[OL_HEADER_SIZE + 3 + 255 + 1];
    int path_len, count, msg_len;

    if (len < OL_HEADER_SIZE + 3) return;
    path_len = u[OL_HEADER_SIZE + 2];
    if (path_len == 0 || OL_HEADER_SIZE + 3 + path_len > len) return;
    if (u[OL_HEADER_SIZE] != CLAIM_CSA && u[OL_HEADER_SIZE] != CLAIM_PICKUP) return;

    msg_len = OL_HEADER_SIZE + 3 + path_len;
    if (arbiter_allow(s, pl, u[OL_HEADER_SIZE], u[OL_HEADER_SIZE + 1],
                      u + OL_HEADER_SIZE + 3, path_len, &count)) {
        memcpy(out, data, msg_len);
        out[msg_len] = (unsigned char)(count > 255 ? 255 : count);
        send_to_world(s, pl, (const char *)out, msg_len + 1);
    } else {
        memset(out, 0, OL_HEADER_SIZE);
        out[0] = CH_WORLD;
        out[1] = WORLD_CLAIM_DENIED;
        out[OL_HEADER_SIZE] = u[OL_HEADER_SIZE];
        out[OL_HEADER_SIZE + 1] = (unsigned char)path_len;
        memcpy(out + OL_HEADER_SIZE + 2, u + OL_HEADER_SIZE + 3, path_len);
        player_send(pl, (const char *)out, OL_HEADER_SIZE + 2 + path_len);
    }
}

// Same layout as WORLD_CLAIM. The claimant could not start the granted action (the player
// looked away while waiting), so it must become available again or a key item would be lost.
static void handle_claim_release(Server *s, Player *pl, const char *data, int len) {
    const unsigned char *u = (const unsigned char *)data;
    unsigned char out[OL_HEADER_SIZE + 3 + 255 + 1];
    TriggerState *t;
    int path_len, msg_len;

    if (len < OL_HEADER_SIZE + 3) return;
    path_len = u[OL_HEADER_SIZE + 2];
    if (path_len == 0 || OL_HEADER_SIZE + 3 + path_len > len) return;

    t = trigger_find_or_alloc(s, pl->room_idx, arbiter_hash(u[OL_HEADER_SIZE], u + OL_HEADER_SIZE + 3, path_len));
    if (!t) return;
    if (t->count > 0) t->count--;

    msg_len = OL_HEADER_SIZE + 3 + path_len;
    memcpy(out, data, msg_len);
    out[msg_len] = (unsigned char)(t->count > 255 ? 255 : t->count);
    send_to_world(s, pl, (const char *)out, msg_len + 1);
}

// ---------------------------------------------------------------------------
// Checks on what clients claim
//
// Movement and health stay on the client, which runs regeneration, Kismet damage and
// everything else that changes them. Values that would harm a receiver are dropped;
// implausible ones are only counted and logged, a laggy player must not get jerked around.
// ---------------------------------------------------------------------------

#define HERO_OFF_SMT        24
#define HERO_OFF_HEALTH     32
#define HERO_STATE_MIN      63     // DecodeBinaryState in HeroChannel.cpp
#define HERO_SMT_MAX        100    // ESpecialMoveType in OLPawn.uc
#define HERO_HEALTH_MAX     200
#define HERO_HEALTH_JUMP    60     // more than regeneration or a pickup gives in one update
#define HERO_SPEED_MAX      1500.f // uu/s, well above sprinting
#define HERO_SPEED_SLACK    300.f  // uu, tolerated jitter between two updates
#define WORLD_COORD_MAX     1.0e6f
#define HITS_PER_SECOND     8
#define HIT_ENEMY_RANGE     3000.f // uu, generous: positions of both sides lag

static int read_i32(const char *p) {
    const unsigned char *b = (const unsigned char *)p;
    return (int)((uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
}

static float read_f32(const char *p) {
    float f;
    memcpy(&f, p, sizeof(f));  // both ends are little endian
    return f;
}

static int coord_valid(float f) {
    // Also false for NaN.
    return f > -WORLD_COORD_MAX && f < WORLD_COORD_MAX;
}

static void hero_violation(Server *s, Player *pl, const char *what) {
    double now = mono_now();
    pl->violations++;
    s->stats.hero_violations++;
    if (now >= pl->next_violation_log) {
        pl->next_violation_log = now + 5.0;
        server_log(s, "[%s] ID=%d ('%s') %s (%u so far)", pl->ip, pl->id, pl->nick, what, pl->violations);
    }
}

static int hero_state_accept(Server *s, Player *pl, const char *data, int len) {
    const char *state = data + OL_HEADER_SIZE;
    double now = mono_now();
    float pos[3];
    int i, smt, health;

    if (len - OL_HEADER_SIZE < HERO_STATE_MIN) {
        hero_violation(s, pl, "sent a truncated state");
        return 0;
    }
    for (i = 0; i < 3; i++) {
        pos[i] = read_f32(state + i * 4);
        if (!coord_valid(pos[i])) {
            hero_violation(s, pl, "sent an invalid position");
            return 0;
        }
    }
    smt = (unsigned char)state[HERO_OFF_SMT];
    health = (short)((unsigned char)state[HERO_OFF_HEALTH] | ((unsigned char)state[HERO_OFF_HEALTH + 1] << 8));
    if (smt > HERO_SMT_MAX || health > HERO_HEALTH_MAX) {
        hero_violation(s, pl, "sent impossible values");
        return 0;
    }

    if (pl->hero_known) {
        // Special moves, cutscenes and respawns move the hero legitimately.
        if (smt == 0 && health > 0) {
            float dx = pos[0] - pl->hero_pos[0], dy = pos[1] - pl->hero_pos[1], dz = pos[2] - pl->hero_pos[2];
            float allowed = HERO_SPEED_MAX * (float)(now - pl->hero_time) + HERO_SPEED_SLACK;
            if (dx * dx + dy * dy + dz * dz > allowed * allowed)
                hero_violation(s, pl, "moved faster than possible");
        }
        if (pl->hero_health > 0 && health - pl->hero_health > HERO_HEALTH_JUMP)
            hero_violation(s, pl, "gained health too fast");
    }
    memcpy(pl->hero_pos, pos, sizeof(pos));
    pl->hero_time = now;
    pl->hero_health = health;
    pl->hero_known = 1;
    return 1;
}

static int enemy_near(Server *s, int room_idx, const float pos[3], float range) {
    int i;
    for (i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
        const EnemySnapshot *e = &s->enemies[i];
        // loc_pkt: [header][name_len(1)][name][0][X][Y][Z]...
        int at;
        if (!e->used || e->room_idx != room_idx || e->loc_len <= OL_HEADER_SIZE) continue;
        at = OL_HEADER_SIZE + 1 + (unsigned char)e->loc_pkt[OL_HEADER_SIZE] + 1;
        if (at + 12 > e->loc_len) continue;
        {
            float dx = read_f32(e->loc_pkt + at) - pos[0];
            float dy = read_f32(e->loc_pkt + at + 4) - pos[1];
            float dz = read_f32(e->loc_pkt + at + 8) - pos[2];
            if (dx * dx + dy * dy + dz * dz <= range * range) return 1;
        }
    }
    return 0;
}

// [header][target_id LE4][event_type(1)]... The sender is already known to be the AI owner.
// A false refusal costs one missed hit, a false acceptance lets a player owner hurt anyone.
static int player_event_accept(Server *s, Player *pl, const char *data, int len) {
    Player *target = NULL;
    double now = mono_now();
    int target_id, i;

    if (len < OL_HEADER_SIZE + 5) return 0;
    target_id = read_i32(data + OL_HEADER_SIZE);
    for (i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (p->used && p->id == target_id && p->room_idx == pl->room_idx && p->in_world && !p->is_sim)
            target = p;
    }
    if (!target) {
        s->stats.events_dropped++;
        return 0;
    }
    if (now - target->hits_window >= 1.0) {
        target->hits_window = now;
        target->hits_this_second = 0;
    }
    if (++target->hits_this_second > HITS_PER_SECOND) {
        s->stats.events_dropped++;
        hero_violation(s, pl, "sent too many player events");
        return 0;
    }
    // The simulator holds the server's secret; only a player acting as owner gets checked.
    if (!pl->is_sim && target->hero_known && !enemy_near(s, pl->room_idx, target->hero_pos, HIT_ENEMY_RANGE)) {
        s->stats.events_dropped++;
        hero_violation(s, pl, "reported an attack with no enemy nearby");
        return 0;
    }
    return 1;
}

// [header][name_len(1)][name][0][X][Y][Z]...
static int enemy_loc_valid(const char *data, int len) {
    int at, i;
    if (len <= OL_HEADER_SIZE) return 0;
    at = OL_HEADER_SIZE + 1 + (unsigned char)data[OL_HEADER_SIZE] + 1;
    if (at + 12 > len) return 0;
    for (i = 0; i < 3; i++)
        if (!coord_valid(read_f32(data + at + i * 4))) return 0;
    return 1;
}

// One message from an established session: [channel(1)][type(1)][player_id LE4][payload...]
// The transport already identified the sender, so the player_id field is overwritten.
static void handle_message(Server *s, Player *pl, char *data, int len) {
    const Addr *addr = &pl->addr;
    if (pl->pending_disconnect) return;
    if (len >= 6 && (unsigned char)data[0] <= OL_CHANNEL_MAX) {
        unsigned char channel, ptype;
        int sender_slot;
        const char *room;

        channel = (unsigned char)data[0];
        ptype   = (unsigned char)data[1];
        data[2] = (char)(pl->id & 0xFF);
        data[3] = (char)((pl->id >> 8) & 0xFF);
        data[4] = (char)((pl->id >> 16) & 0xFF);
        data[5] = (char)((pl->id >> 24) & 0xFF);
        if (!check_rate(pl)) return;

        if (channel == CH_SESS) {
            handle_session(s, pl, ptype, data, len);
            return;
        }
        // The simulator speaks only for enemies; its own hero does not exist for anyone.
        if (pl->is_sim && channel != CH_SRV && channel != CH_ENEMY
            && !(channel == CH_HERO && ptype == HERO_PLAYER_EVENT)
            && !(channel == CH_WORLD && ptype == WORLD_DISCONNECT))
            return;
        // World traffic only flows between players in the current world.
        if (channel != CH_SRV && !pl->in_world
            && !(channel == CH_WORLD && ptype == WORLD_DISCONNECT))
            return;

        {
            Room *sim_room = &s->rooms[pl->room_idx];
            // Enemies and what they do to players come only from the AI owner.
            if ((channel == CH_ENEMY || (channel == CH_HERO && ptype == HERO_PLAYER_EVENT))
                && sim_room->sim_owner != pl->id)
                return;
            // A dying owner reloads a checkpoint, which would reset every enemy for everyone.
            if (channel == CH_HERO && ptype == HERO_PLAYER_LIFECYCLE && len > OL_HEADER_SIZE
                && data[OL_HEADER_SIZE] == 0 && sim_room->sim_owner == pl->id) {
                int next_owner = sim_next_owner(s, pl->room_idx, pl->id);
                if (next_owner != 0)
                    sim_set_owner(s, pl->room_idx, next_owner);
            }
        }

        // CH_SRV: HELLO and PING
        if (channel == CH_SRV) {
            if (ptype == SRV_HELLO && len >= 8) {
                unsigned char nick_len = (unsigned char)data[6];
                int max_nick = len - 7;
                char clean[MAX_NICK];
                int ci = 0, i;
                memset(clean, 0, sizeof(clean));
                if (nick_len > max_nick) nick_len = (unsigned char)max_nick;
                if (nick_len > MAX_NICK - 1) nick_len = MAX_NICK - 1;
                for (i = 0; i < nick_len && ci < MAX_NICK - 1; i++) {
                    char c = data[7 + i];
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_')
                        clean[ci++] = c;
                }
                if (!clean[0]) snprintf(clean, sizeof(clean), "Player%d", pl->id);
                memcpy(pl->nick, clean, MAX_NICK - 1);
                pl->nick[MAX_NICK - 1] = '\0';
                server_log(s, "[%s] ID=%d identified as '%s'", pl->ip, pl->id, pl->nick);
                history_push(s, "[%s] identified", pl->nick);
            } else if (ptype == SRV_PING) {
                player_send(pl, data, len);
            }
            return;
        }

        if (channel == CH_HERO && ptype == HERO_STATE && !hero_state_accept(s, pl, data, len))
            return;
        if (channel == CH_HERO && ptype == HERO_PLAYER_EVENT && !player_event_accept(s, pl, data, len))
            return;
        if (channel == CH_ENEMY && ptype == ENEMY_LOC && !enemy_loc_valid(data, len))
            return;

        // CH_HERO: STATE snapshot
        if (channel == CH_HERO && ptype == HERO_STATE) {
            int snap_len = len < (int)sizeof(pl->state_snap) ? len : (int)sizeof(pl->state_snap);
            memcpy(pl->state_snap, data, snap_len);
            pl->state_snap_len = snap_len;
        }

        // CH_WORLD: special types
        if (channel == CH_WORLD) {
            if (ptype == WORLD_MATINEE_STATE) {
                // Only for joining players: a running game starts matinees through triggers.
                // A count of 0 means nothing is playing any more.
                int snap_len = len < (int)sizeof(pl->matinee_snap) ? len : (int)sizeof(pl->matinee_snap);
                if (len > OL_HEADER_SIZE && data[OL_HEADER_SIZE] != 0) {
                    memcpy(pl->matinee_snap, data, snap_len);
                    pl->matinee_snap_len = snap_len;
                } else {
                    pl->matinee_snap_len = 0;
                }
                return;
            }
            if (ptype == WORLD_ITEM_CONSUME && len > OL_HEADER_SIZE + 1) {
                // Replayed after the pickups, so a returning player does not keep a used item.
                int name_len = (unsigned char)data[OL_HEADER_SIZE];
                if (OL_HEADER_SIZE + 1 + name_len <= len && name_len + 9 < MAX_PICKUP_KEY) {
                    char key[MAX_PICKUP_KEY];
                    PickupSnapshot *p;
                    memcpy(key, "consume:", 8);
                    memcpy(key + 8, data + OL_HEADER_SIZE + 1, name_len);
                    key[8 + name_len] = '\0';
                    p = pickup_alloc(s, pl->room_idx, key);
                    if (p && len <= MAX_PICKUP_SNAP_DATA) {
                        memcpy(p->pkt, data, len);
                        p->pkt_len = len;
                    }
                }
            }
            if (ptype == WORLD_DISCONNECT) {
                pl->pending_disconnect = 1;
                return;
            }
            if (ptype == WORLD_TRIGGER_FIRE) {
                handle_trigger_fire(s, pl, data, len);
                return;
            }
            if (ptype == WORLD_CLAIM) {
                handle_claim(s, pl, data, len);
                return;
            }
            if (ptype == WORLD_CLAIM_RELEASE) {
                handle_claim_release(s, pl, data, len);
                return;
            }
            if (ptype == WORLD_REQUEST_ENEMIES) {
                int i;
                for (i = 0; i < MAX_ENEMY_SNAPSHOTS; i++) {
                    EnemySnapshot *e = &s->enemies[i];
                    if (!e->used || e->room_idx != pl->room_idx) continue;
                    if (e->owner_player_id == pl->id) continue;
                    if (e->spawn_len > 0) server_snap_enqueue(pl, e->spawn_pkt, e->spawn_len);
                    if (e->smt_len > 0)   server_snap_enqueue(pl, e->smt_pkt,   e->smt_len);
                    if (e->anim_len > 0)  server_snap_enqueue(pl, e->anim_pkt,  e->anim_len);
                    if (e->loc_len > 0)   server_snap_enqueue(pl, e->loc_pkt,   e->loc_len);
                }
                return;
            }
            if (ptype == WORLD_REQUEST_DOORS) {
                int i;
                for (i = 0; i < MAX_DOOR_SNAPSHOTS; i++) {
                    DoorSnapshot *d = &s->doors[i];
                    if (!d->used || d->room_idx != pl->room_idx) continue;
                    if (d->state_len > 0) server_snap_enqueue(pl, d->state_pkt, d->state_len);
                    if (d->angle_len > 0) server_snap_enqueue(pl, d->angle_pkt, d->angle_len);
                }
                return;
            }
            if (ptype == WORLD_REQUEST_PUSHABLES) {
                int i;
                for (i = 0; i < MAX_PUSH_SNAPSHOTS; i++) {
                    PushSnapshot *ps = &s->pushables[i];
                    if (!ps->used || ps->room_idx != pl->room_idx) continue;
                    if (ps->pkt_len > 0) {
                        char tmp[MAX_PUSH_SNAP_DATA];
                        memcpy(tmp, ps->pkt, ps->pkt_len);
                        if (ps->pkt_len > 26) tmp[26] = 0; /* clear bPushing */
                        server_snap_enqueue(pl, tmp, ps->pkt_len);
                    }
                }
                return;
            }
        }

        // CH_DOOR: door snapshots — payload at data[6+]: [X I32][Y I32][Z I32][...]
        if (channel == CH_DOOR && len >= 18) {
            int dx = read_i32(data + 6);
            int dy = read_i32(data + 10);
            int dz = read_i32(data + 14);
            char key[MAX_DOOR_KEY];
            snprintf(key, sizeof(key), "%d,%d,%d", dx, dy, dz);

            if (ptype == DOOR_LOCK) {
                DoorSnapshot *d = door_find(s, pl->room_idx, key);
                if (d && d->authority_player_id != 0 && d->authority_player_id != pl->id) {
                    send_door_deny(s, &pl->addr, key);
                    return;
                }
                d = door_alloc(s, pl->room_idx, key);
                if (d) {
                    int store = len < MAX_DOOR_SNAP_DATA ? len : MAX_DOOR_SNAP_DATA - 1;
                    d->authority_player_id = pl->id;
                    memcpy(d->lock_pkt, data, store);
                    d->lock_len = store;
                }
            } else if (ptype == DOOR_UNLOCK) {
                DoorSnapshot *d = door_find(s, pl->room_idx, key);
                if (d && d->authority_player_id == pl->id) {
                    d->authority_player_id = 0;
                    d->lock_len = 0;
                }
            } else if (ptype == DOOR_STATE) {
                DoorSnapshot *d = door_alloc(s, pl->room_idx, key);
                if (d) {
                    int store = len < MAX_DOOR_SNAP_DATA ? len : MAX_DOOR_SNAP_DATA - 1;
                    memcpy(d->state_pkt, data, store);
                    d->state_len = store;
                }
            } else if (ptype == DOOR_OPEN || ptype == DOOR_CLOSE) {
                DoorSnapshot *d = door_alloc(s, pl->room_idx, key);
                if (d) {
                    int store = len < MAX_DOOR_SNAP_DATA ? len : MAX_DOOR_SNAP_DATA - 1;
                    memcpy(d->state_pkt, data, store);
                    d->state_len = store;
                    d->angle_len = 0;
                }
            } else if (ptype == DOOR_ANGLE) {
                DoorSnapshot *d = door_alloc(s, pl->room_idx, key);
                if (d) {
                    int store = len < MAX_DOOR_SNAP_DATA ? len : MAX_DOOR_SNAP_DATA - 1;
                    memcpy(d->angle_pkt, data, store);
                    d->angle_len = store;
                }
            }
        }

        // CH_PUSH: pushable snapshot — payload at data[6+]: [KeyX(4)][KeyY(4)][KeyZ(4)][DispX1000(4)][Seq(4)][bPushing(1)]
        // The first player pushing owns the object until they stop; others get PUSH_DENIED.
        if (channel == CH_PUSH && ptype == PUSH_STATE && len >= 27) {
            int px = read_i32(data + 6);
            int py = read_i32(data + 10);
            int pz = read_i32(data + 14);
            char pkey[MAX_PUSH_KEY];
            snprintf(pkey, sizeof(pkey), "%d,%d,%d", px, py, pz);
            {
                PushSnapshot *ps = push_alloc(s, pl->room_idx, pkey);
                if (ps) {
                    int store = len < MAX_PUSH_SNAP_DATA ? len : MAX_PUSH_SNAP_DATA - 1;
                    if (data[26]) {
                        if (ps->owner_player_id != 0 && ps->owner_player_id != pl->id) {
                            send_push_denied(s, &pl->addr, data + OL_HEADER_SIZE);
                            return;
                        }
                        ps->owner_player_id = pl->id;
                    } else if (ps->owner_player_id == pl->id) {
                        ps->owner_player_id = 0;
                    }
                    memcpy(ps->pkt, data, store);
                    ps->pkt_len = store;
                }
            }
        }

        // CH_WORLD: PICKUP_KISMET snapshot — payload at data[6+]: [strLen(1)][path bytes]
        if (channel == CH_WORLD && ptype == WORLD_PICKUP_KISMET && len >= 8) {
            int plen = (int)(unsigned char)data[6];
            int pbytes = len - 7;
            char key[MAX_PICKUP_KEY];
            memset(key, 0, sizeof(key));
            if (plen > pbytes) plen = pbytes;
            if (plen > MAX_PICKUP_KEY - 1) plen = MAX_PICKUP_KEY - 1;
            memcpy(key, data + 7, plen);
            if (key[0]) {
                PickupSnapshot *p = pickup_alloc(s, pl->room_idx, key);
                if (p) {
                    int store = len < MAX_PICKUP_SNAP_DATA ? len : MAX_PICKUP_SNAP_DATA - 1;
                    memcpy(p->pkt, data, store);
                    p->pkt_len = store;
                }
            }
        }

        // CH_WORLD: PICKUP_STATE snapshot — payload at data[6+]: [X I32][Y I32][Z I32]
        if (channel == CH_WORLD && ptype == WORLD_PICKUP_STATE && len >= 18) {
            int px = read_i32(data + 6);
            int py = read_i32(data + 10);
            int pz = read_i32(data + 14);
            char key[MAX_PICKUP_KEY];
            snprintf(key, sizeof(key), "%d,%d,%d", px, py, pz);
            {
                PickupSnapshot *p = pickup_alloc(s, pl->room_idx, key);
                if (p) {
                    int store = len < MAX_PICKUP_SNAP_DATA ? len : MAX_PICKUP_SNAP_DATA - 1;
                    memcpy(p->pkt, data, store);
                    p->pkt_len = store;
                }
            }
        }

        // CH_ENEMY: snapshots — payload at data[6+]: [name_len(1)][name bytes][...]
        if (channel == CH_ENEMY && len >= 8) {
            unsigned char nlen = (unsigned char)data[6];
            int max_n = len - 7;
            char ename[MAX_ENEMY_NAME];
            memset(ename, 0, sizeof(ename));
            if (nlen > max_n) nlen = (unsigned char)max_n;
            if (nlen > MAX_ENEMY_NAME - 1) nlen = MAX_ENEMY_NAME - 1;
            memcpy(ename, data + 7, nlen);

            if (ptype == ENEMY_LOC) {
                EnemySnapshot *e = enemy_find(s, pl->room_idx, ename);
                if (e) {
                    int store = len < MAX_ENEMY_SNAP_DATA ? len : MAX_ENEMY_SNAP_DATA - 1;
                    memcpy(e->loc_pkt, data, store);
                    e->loc_len = store;
                }
            } else if (ptype == ENEMY_SPAWN) {
                EnemySnapshot *e = enemy_alloc(s, pl->room_idx, ename, pl->id);
                if (e) {
                    int store = len < MAX_ENEMY_SNAP_DATA ? len : MAX_ENEMY_SNAP_DATA - 1;
                    memcpy(e->spawn_pkt, data, store);
                    e->spawn_len = store;
                    e->smt_len = 0;
                    e->loc_len = 0;
                    e->anim_len = 0;
                }
            } else if (ptype == ENEMY_DEL) {
                enemy_remove(s, pl->room_idx, ename);
            } else if (ptype == ENEMY_ANIM) {
                EnemySnapshot *e = enemy_find(s, pl->room_idx, ename);
                int flags_off = 7 + nlen;
                if (e && flags_off < len) {
                    if (data[flags_off] & ENEMY_ANIM_STOP) {
                        e->anim_len = 0;
                    } else if (len <= MAX_ENEMY_SNAP_DATA) {
                        memcpy(e->anim_pkt, data, len);
                        e->anim_len = len;
                    }
                }
            } else if (ptype == ENEMY_SMT) {
                int smt_off = 7 + nlen;
                unsigned char smt_type = (smt_off < len) ? (unsigned char)data[smt_off] : 0;
                int is_transient = (smt_type >= 77 && smt_type <= 93);
                EnemySnapshot *e = enemy_find(s, pl->room_idx, ename);
                if (e) {
                    if (is_transient) {
                        e->smt_len = 0;
                    } else {
                        int store = len < MAX_ENEMY_SNAP_DATA ? len : MAX_ENEMY_SNAP_DATA - 1;
                        memcpy(e->smt_pkt, data, store);
                        e->smt_len = store;
                    }
                }
            }
        }

        // GUI events + history
        sender_slot = (int)(pl - s->players);
        room = s->rooms[pl->room_idx].code;
        if (channel == CH_HERO) {
            switch (ptype) {
                case HERO_STATE: gui_push_event(s, sender_slot, GUIPKT_LOC); break;
                case HERO_SMT_TYPE: {
                    int smt_type = (len > 6) ? (unsigned char)data[6] : -1;
                    gui_push_event(s, sender_slot, GUIPKT_SMT);
                    history_push(s, "[%s@%s] SMT %d", pl->nick, room, smt_type);
                    break;
                }
                case HERO_PLAYER_LIFECYCLE: {
                    gui_push_event(s, sender_slot, GUIPKT_RESPAWN);
                    history_push(s, "[%s@%s] Lifecycle", pl->nick, room);
                    break;
                }
                default: break;
            }
        } else if (channel == CH_DOOR) {
            gui_push_event(s, sender_slot, GUIPKT_DOOR);
            history_push(s, "[%s@%s] Door 0x%02x", pl->nick, room, ptype);
        } else if (channel == CH_ENEMY) {
            switch (ptype) {
                case ENEMY_SPAWN: {
                    char ename2[MAX_ENEMY_NAME];
                    memset(ename2, 0, sizeof(ename2));
                    if (len >= 8) {
                        unsigned char nl2 = (unsigned char)data[6];
                        int mn2 = len - 7; if (nl2 > mn2) nl2 = (unsigned char)mn2;
                        if (nl2 > MAX_ENEMY_NAME - 1) nl2 = MAX_ENEMY_NAME - 1;
                        memcpy(ename2, data + 7, nl2);
                    }
                    history_push(s, "[%s@%s] EnemySpawn %s", pl->nick, room, ename2);
                    break;
                }
                case ENEMY_DEL: {
                    char ename2[MAX_ENEMY_NAME];
                    memset(ename2, 0, sizeof(ename2));
                    if (len >= 8) {
                        unsigned char nl2 = (unsigned char)data[6];
                        int mn2 = len - 7; if (nl2 > mn2) nl2 = (unsigned char)mn2;
                        if (nl2 > MAX_ENEMY_NAME - 1) nl2 = MAX_ENEMY_NAME - 1;
                        memcpy(ename2, data + 7, nl2);
                    }
                    history_push(s, "[%s@%s] EnemyDel %s", pl->nick, room, ename2);
                    break;
                }
                case ENEMY_SMT: {
                    char ename2[MAX_ENEMY_NAME];
                    int smt_type2 = -1;
                    memset(ename2, 0, sizeof(ename2));
                    gui_push_event(s, sender_slot, GUIPKT_ENPC_SMT);
                    if (len >= 8) {
                        unsigned char nl2 = (unsigned char)data[6];
                        int mn2 = len - 7; if (nl2 > mn2) nl2 = (unsigned char)mn2;
                        if (nl2 > MAX_ENEMY_NAME - 1) nl2 = MAX_ENEMY_NAME - 1;
                        memcpy(ename2, data + 7, nl2);
                        { int smt_off2 = 7 + nl2; if (smt_off2 < len) smt_type2 = (unsigned char)data[smt_off2]; }
                    }
                    history_push(s, "[%s@%s] EnemySMT %s #%d", pl->nick, room, ename2, smt_type2);
                    break;
                }
                default: break;
            }
        }

        // Relay as-is — receivers parse the binary payload themselves
        server_relay(s, pl, data, len);
    }
}

typedef struct {
    Server *s;
    Player *pl;
    const Addr *from;
} TransportCtx;

static void transport_deliver(void *user, int lane, uint8_t *msg, int len) {
    TransportCtx *ctx = (TransportCtx *)user;
    (void)lane;
    // Only an authentic datagram gets here: conn_id alone must not redirect a session.
    ctx->pl->addr = *ctx->from;
    handle_message(ctx->s, ctx->pl, (char *)msg, len);
}

static void transport_send(void *user, const uint8_t *datagram, int len) {
    TransportCtx *ctx = (TransportCtx *)user;
    ctx->pl->tx_bytes += (uint64_t)len;
    server_send_raw(ctx->s, &ctx->pl->addr, (const char *)datagram, len);
}

static Player *find_player_by_conn_id(Server *s, uint64_t conn_id) {
    int i;
    if (conn_id == 0) return NULL;
    for (i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used && s->players[i].conn.conn_id == conn_id)
            return &s->players[i];
    return NULL;
}

void handle_packet(Server *s, const char *data, int len, const Addr *addr) {
    if (len <= 0) return;
    s->stats.rx_bytes += (uint64_t)len;
    s->stats.rx_packets++;

    if ((unsigned char)data[0] == OL_MAGIC) {
        TransportCtx ctx;
        uint64_t conn_id;
        double now = mono_now();
        if (!ol_peek_conn_id((const uint8_t *)data, len, &conn_id)) return;
        ctx.s = s;
        ctx.from = addr;
        ctx.pl = find_player_by_conn_id(s, conn_id);
        if (!ctx.pl) {
            s->stats.bad_datagrams++;
            return;
        }
        if (!ol_conn_on_datagram(&ctx.pl->conn, now, (const uint8_t *)data, len, transport_deliver, &ctx)) {
            s->stats.bad_datagrams++;
            return;
        }
        ctx.pl->rx_bytes += (uint64_t)len;
        // Follows NAT rebinding, also for a datagram that carried only acks.
        ctx.pl->addr = *addr;
        ctx.pl->last_seen = now;
        if (ctx.pl->pending_disconnect)
            server_disconnect(s, ctx.pl);
        return;
    }

    // Only the handshake is accepted outside a session.
    if ((unsigned char)data[0] == OL_HS_HELLO && len >= 2)
        handle_hs_hello(s, data, len, addr);
    else if ((unsigned char)data[0] == OL_HS_AUTH)
        handle_hs_auth(s, data, len, addr);
}

// ---------------------------------------------------------------------------
// Background tasks
// ---------------------------------------------------------------------------

static void log_stats(Server *s) {
    double now = mono_now();
    int i, players = 0;
    if (now < s->next_stats_log) return;
    s->next_stats_log = now + 60.0;
    for (i = 0; i < MAX_CLIENTS; i++)
        if (s->players[i].used) players++;
    if (players == 0) return;
    server_log(s, "Stats: %d connected, in %.1f MB, out %.1f MB, joined %llu, refused %llu, bad datagrams %llu, violations %llu, events dropped %llu",
               players, (double)s->stats.rx_bytes / 1e6, (double)s->stats.tx_bytes / 1e6,
               (unsigned long long)s->stats.auth_ok, (unsigned long long)s->stats.auth_refused,
               (unsigned long long)s->stats.bad_datagrams, (unsigned long long)s->stats.hero_violations,
               (unsigned long long)s->stats.events_dropped);
}

void run_heartbeat(Server *s) {
    // No-op: server no longer sends heartbeat packets.
    // Client keepalive is maintained by the client's own tick sends.
    (void)s;
}

void run_timeout(Server *s) {
    double now = mono_now();
    if (now < s->next_timeout) return;
    s->next_timeout = now + HEARTBEAT_SEC;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        Player *p = &s->players[i];
        if (!p->used) continue;
        if (now - p->last_seen > TIMEOUT_SEC) {
            server_log(s, "[%s] ID=%d ('%s') timed out", p->ip, p->id, p->nick);
            history_push(s, "[%s] timed out", p->nick);
            server_disconnect(s, p);
        }
    }
}

// ---------------------------------------------------------------------------
// Init / run / shutdown
// ---------------------------------------------------------------------------

// Clients pin this key, so it has to survive restarts: "<database>.key", 64 hex digits.
// Without keys nobody could connect safely, so there is nothing to fall back to.
static void load_server_key(Server *s, const char *db_path) {
    char path[512], hex[65] = {0};
    uint8_t secret[32];
    int loaded = 0;
    FILE *f;
    snprintf(path, sizeof(path), "%s.key", db_path);
    f = fopen(path, "r");
    if (f) {
        loaded = fread(hex, 1, 64, f) == 64 && hex_decode(hex, secret, 32);
        fclose(f);
        if (!loaded)
            fprintf(stderr, "Server key file %s is damaged, generating a new one: clients will refuse this server\n", path);
    }
    if (!ol_hs_server_init(&s->hs, loaded ? secret : NULL)) {
        fprintf(stderr, "No secure random source\n");
        exit(1);
    }
    if (!loaded) {
#ifndef _WIN32
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        f = fd >= 0 ? fdopen(fd, "w") : NULL;
#else
        f = fopen(path, "w");
#endif
        if (f) {
            hex_encode(hex, s->hs.secret, 32);
            fwrite(hex, 1, 64, f);
            fclose(f);
        } else {
            fprintf(stderr, "Cannot save the server key to %s: clients will refuse this server after a restart\n", path);
        }
    }
    hex_encode(s->hs_pub_hex, s->hs.pub, 32);
}

void server_init(Server *s, uint16_t port, const char *name, const char *bind_ip, const char *db_path) {
    memset(s, 0, sizeof(*s));
    s->player_id_seq = 1000;
    strncpy(s->name, name ? name : "OLServer", sizeof(s->name) - 1);
    strncpy(s->bind_ip, bind_ip && bind_ip[0] ? bind_ip : DEFAULT_IP, MAX_IP - 1);
    s->port = port;
    db_init(&s->db, db_path ? db_path : "relay.json");

    platform_init();

    load_server_key(s, db_path ? db_path : "relay.json");
    {
        const char *sim_secret = getenv("OPENOL_SIM_SECRET");
        if (sim_secret)
            strncpy(s->sim_secret, sim_secret, sizeof(s->sim_secret) - 1);
    }

    s->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s->sock == INVALID_SOCK) {
#ifdef _WIN32
        FILE *_ef = fopen("startup_debug.txt", "a");
        if (_ef) { fprintf(_ef, "socket() failed: WSA error %d\n", WSAGetLastError()); fclose(_ef); }
#else
        perror("socket");
#endif
        exit(1);
    }

    // Non-blocking
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(s->sock, FIONBIO, &nb);
#else
    int flags = fcntl(s->sock, F_GETFL, 0);
    fcntl(s->sock, F_SETFL, flags | O_NONBLOCK);
#endif

    // SO_REUSEADDR
    int yes = 1;
    setsockopt(s->sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (strcmp(s->bind_ip, DEFAULT_IP) == 0 || !s->bind_ip[0])
        sa.sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, s->bind_ip, &sa.sin_addr);

    if (bind(s->sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
#ifdef _WIN32
        FILE *_ef = fopen("startup_debug.txt", "a");
        if (_ef) { fprintf(_ef, "bind() failed on %s:%d — WSA error %d\n", s->bind_ip, port, WSAGetLastError()); fclose(_ef); }
#else
        perror("bind");
#endif
        exit(1);
    }

    double now = mono_now();
    s->next_heartbeat = now + HEARTBEAT_SEC;
    s->next_timeout   = now + HEARTBEAT_SEC;
    s->next_stats_log = now + 60.0;

    history_push(s, "Listening on %s:%d  name='%s'", s->bind_ip, (int)s->port, s->name);
    history_push(s, "Server key: %s", s->hs_pub_hex);
    server_log(s, "Server key: %s", s->hs_pub_hex);
}

static void flush_players(Server *s) {
    double now = mono_now();
    int i;
    if (now < s->next_flush) return;
    s->next_flush = now + FLUSH_INTERVAL;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (s->players[i].used) {
            TransportCtx ctx;
            ctx.s = s;
            ctx.pl = &s->players[i];
            ctx.from = NULL;
            ol_conn_flush(&s->players[i].conn, now, transport_send, &ctx);
        }
    }
}

void server_poll(Server *s) {
    char buf[MAX_PACKET];
    fd_set rfds;
    struct timeval tv;
    int r;
    FD_ZERO(&rfds);
    FD_SET(s->sock, &rfds);
    tv.tv_sec  = 0;
    tv.tv_usec = (long)(FLUSH_INTERVAL * 1e6);
    r = select((int)s->sock + 1, &rfds, NULL, NULL, &tv);

    if (s->shutdown_requested) return;

    if (r > 0 && FD_ISSET(s->sock, &rfds)) {
        Addr from;
        socklen_t slen = sizeof(from.sa);
        int len = (int)recvfrom(s->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&from.sa, &slen);
        if (len > 0)
            handle_packet(s, buf, len, &from);
    }

    run_heartbeat(s);
    run_timeout(s);
    log_stats(s);
    server_drain_snaps(s);
    flush_players(s);
}

void server_free_sessions(Server *s) {
    int i;
    for (i = 0; i < MAX_CLIENTS; i++)
        ol_conn_free(&s->players[i].conn);
}

void server_run(Server *s) {
    while (!s->shutdown_requested)
        server_poll(s);
    server_free_sessions(s);
}

void server_shutdown(Server *s) {
    if (s->sock != INVALID_SOCK) {
        sock_close(s->sock);
        s->sock = INVALID_SOCK;
    }
    platform_cleanup();
}
