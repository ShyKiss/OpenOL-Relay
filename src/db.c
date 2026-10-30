/*=============================================================================
    db.c - in-memory database with JSON persistence
=============================================================================*/
#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif
#include "db.h"
#include "relay_compat.h"  /* snprintf polyfill — after winsock2 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void now_str(char *buf, int len) {
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void scpy(char *dst, const char *src, int dstlen) {
    if (!src) { dst[0] = '\0'; return; }
    strncpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';
}

// ---------------------------------------------------------------------------
// JSON writer
// ---------------------------------------------------------------------------

static void jw_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        if      (*s == '"')  fputs("\\\"", f);
        else if (*s == '\\') fputs("\\\\", f);
        else if (*s == '\n') fputs("\\n",  f);
        else if (*s == '\r') fputs("\\r",  f);
        else if (*s == '\t') fputs("\\t",  f);
        else                 fputc(*s, f);
    }
    fputc('"', f);
}

static void jw_kv(FILE *f, const char *indent, const char *key, const char *val, int comma) {
    fputs(indent, f);
    jw_str(f, key);
    fputs(": ", f);
    jw_str(f, val);
    if (comma) fputc(',', f);
    fputc('\n', f);
}

static void jw_ban(FILE *f, const char *indent, const DBBan *b, int comma) {
    fprintf(f, "%s{\n", indent);
    char ind2[32]; snprintf(ind2, sizeof(ind2), "%s  ", indent);
    jw_kv(f, ind2, "ip",        b->ip,        1);
    jw_kv(f, ind2, "nick",      b->nick,      1);
    jw_kv(f, ind2, "reason",    b->reason,    1);
    jw_kv(f, ind2, "banned_at", b->banned_at, 0);
    fprintf(f, "%s}%s\n", indent, comma ? "," : "");
}

// ---------------------------------------------------------------------------
// JSON parser
// ---------------------------------------------------------------------------

typedef struct { const char *p; const char *end; } JP;

static void jp_ws(JP *j) {
    while (j->p < j->end && ((unsigned char)*j->p <= ' ')) j->p++;
}

static int jp_char(JP *j, char c) {
    jp_ws(j);
    if (j->p >= j->end || *j->p != c) return 0;
    j->p++; return 1;
}

static int jp_str(JP *j, char *buf, int len) {
    jp_ws(j);
    if (j->p >= j->end || *j->p != '"') return 0;
    j->p++;
    int i = 0;
    while (j->p < j->end && *j->p != '"') {
        char c;
        if (*j->p == '\\') {
            j->p++;
            if (j->p >= j->end) return 0;
            c = *j->p++;
            if      (c == '"')  c = '"';
            else if (c == '\\') c = '\\';
            else if (c == 'n')  c = '\n';
            else if (c == 'r')  c = '\r';
            else if (c == 't')  c = '\t';
        } else {
            c = *j->p++;
        }
        if (i < len - 1) buf[i++] = c;
    }
    buf[i] = '\0';
    if (j->p < j->end) j->p++; // closing "
    return 1;
}

static void jp_skip(JP *j);
static void jp_skip(JP *j) {
    jp_ws(j);
    if (j->p >= j->end) return;
    if (*j->p == '"') { char t[512]; jp_str(j, t, sizeof(t)); }
    else if (*j->p == '{') {
        j->p++;
        jp_ws(j);
        while (j->p < j->end && *j->p != '}') {
            char k[64]; jp_str(j, k, sizeof(k));
            jp_char(j, ':'); jp_skip(j); jp_ws(j);
            if (j->p < j->end && *j->p == ',') j->p++;
            jp_ws(j);
        }
        if (j->p < j->end) j->p++;
    } else if (*j->p == '[') {
        j->p++;
        jp_ws(j);
        while (j->p < j->end && *j->p != ']') {
            jp_skip(j); jp_ws(j);
            if (j->p < j->end && *j->p == ',') j->p++;
            jp_ws(j);
        }
        if (j->p < j->end) j->p++;
    } else {
        while (j->p < j->end && *j->p != ',' && *j->p != '}' &&
               *j->p != ']' && (unsigned char)*j->p > ' ')
            j->p++;
    }
}

// Parse object: calls cb(key, jp, ud) for each key-value pair.
typedef void (*jp_obj_cb)(const char *key, JP *j, void *ud);

static void jp_obj(JP *j, jp_obj_cb cb, void *ud) {
    if (!jp_char(j, '{')) return;
    jp_ws(j);
    while (j->p < j->end && *j->p != '}') {
        char key[64] = {0};
        if (!jp_str(j, key, sizeof(key))) break;
        if (!jp_char(j, ':')) break;
        cb(key, j, ud);
        jp_ws(j);
        if (j->p < j->end && *j->p == ',') j->p++;
        jp_ws(j);
    }
    jp_char(j, '}');
}

// Parse array: calls cb(jp, ud) for each element.
typedef void (*jp_arr_cb)(JP *j, void *ud);

static void jp_arr(JP *j, jp_arr_cb cb, void *ud) {
    if (!jp_char(j, '[')) return;
    jp_ws(j);
    while (j->p < j->end && *j->p != ']') {
        cb(j, ud);
        jp_ws(j);
        if (j->p < j->end && *j->p == ',') j->p++;
        jp_ws(j);
    }
    jp_char(j, ']');
}

// ---------------------------------------------------------------------------
// Parse ban object → DBBan
// ---------------------------------------------------------------------------

static void parse_ban_field(const char *key, JP *j, void *ud) {
    DBBan *b = (DBBan *)ud;
    if      (strcmp(key, "ip")        == 0) jp_str(j, b->ip,        DB_IP_LEN);
    else if (strcmp(key, "nick")      == 0) jp_str(j, b->nick,      DB_NICK_LEN);
    else if (strcmp(key, "reason")    == 0) jp_str(j, b->reason,    DB_REASON_LEN);
    else if (strcmp(key, "banned_at") == 0) jp_str(j, b->banned_at, DB_TIME_LEN);
    else jp_skip(j);
}

// ---------------------------------------------------------------------------
// Parse room object → DBRoom
// ---------------------------------------------------------------------------

static void parse_room_trusted_item(JP *j, void *ud) {
    DBRoom *r = (DBRoom *)ud;
    char ip[DB_IP_LEN] = {0};
    jp_str(j, ip, DB_IP_LEN);
    if (ip[0] && r->n_trusted < DB_MAX_TRUSTED)
        scpy(r->trusted[r->n_trusted++], ip, DB_IP_LEN);
}

static void parse_room_ban_item(JP *j, void *ud) {
    DBRoom *r = (DBRoom *)ud;
    if (r->n_bans >= DB_MAX_BANS) { jp_skip(j); return; }
    DBBan *b = &r->bans[r->n_bans];
    memset(b, 0, sizeof(*b));
    jp_obj(j, parse_ban_field, b);
    if (b->ip[0]) r->n_bans++;
}

static void parse_room_field(const char *key, JP *j, void *ud) {
    DBRoom *r = (DBRoom *)ud;
    if      (strcmp(key, "code")     == 0) jp_str(j, r->code,     DB_ROOM_CODE_LEN);
    else if (strcmp(key, "password") == 0) jp_str(j, r->password, DB_PASSWORD_LEN);
    else if (strcmp(key, "trusted")  == 0) jp_arr(j, parse_room_trusted_item, r);
    else if (strcmp(key, "bans")     == 0) jp_arr(j, parse_room_ban_item, r);
    else jp_skip(j);
}

static void parse_room_item(JP *j, void *ud) {
    DB *db = (DB *)ud;
    if (db->n_rooms >= DB_MAX_ROOMS) { jp_skip(j); return; }
    DBRoom *r = &db->rooms[db->n_rooms];
    memset(r, 0, sizeof(*r));
    jp_obj(j, parse_room_field, r);
    if (r->code[0]) db->n_rooms++;
}

// ---------------------------------------------------------------------------
// Parse global bans
// ---------------------------------------------------------------------------

static void parse_global_ban_item(JP *j, void *ud) {
    DB *db = (DB *)ud;
    if (db->n_bans >= DB_MAX_BANS) { jp_skip(j); return; }
    DBBan *b = &db->bans[db->n_bans];
    memset(b, 0, sizeof(*b));
    jp_obj(j, parse_ban_field, b);
    if (b->ip[0]) db->n_bans++;
}

static void parse_config_field(const char *key, JP *j, void *ud) {
    DBConfig *c = (DBConfig *)ud;
    char tmp[64];
    if      (strcmp(key, "name")        == 0) jp_str(j, c->name,    DB_NAME_LEN);
    else if (strcmp(key, "ip")          == 0) jp_str(j, c->bind_ip, DB_IP_BIND_LEN);
    else if (strcmp(key, "port")        == 0) { jp_str(j, tmp, sizeof(tmp)); c->port = (uint16_t)atoi(tmp); }
    else jp_skip(j);
}

static void parse_root_field(const char *key, JP *j, void *ud) {
    DB *db = (DB *)ud;
    if      (strcmp(key, "config") == 0) jp_obj(j, parse_config_field, &db->config);
    else if (strcmp(key, "rooms")  == 0) jp_arr(j, parse_room_item,       db);
    else if (strcmp(key, "bans")   == 0) jp_arr(j, parse_global_ban_item, db);
    else jp_skip(j);
}

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

static int db_load(DB *db) {
    FILE *f = fopen(db->path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz <= 0) { fclose(f); return 0; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);

    JP j = { buf, buf + sz };
    jp_obj(&j, parse_root_field, db);
    free(buf);
    return 1;
}

int db_save(DB *db) {
    char tmp[DB_PATH_LEN + 4];
    snprintf(tmp, sizeof(tmp), "%s.tmp", db->path);
    FILE *f = fopen(tmp, "w");
    if (!f) return 0;

    fprintf(f, "{\n");

    // config
    {
        DBConfig *c = &db->config;
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", c->port);
        fprintf(f, "  \"config\": {\n");
        jw_kv(f, "    ", "name",        c->name,    1);
        jw_kv(f, "    ", "ip",          c->bind_ip, 1);
        jw_kv(f, "    ", "port",        port_str,   0);
        fprintf(f, "  },\n");
    }

    // rooms
    fprintf(f, "  \"rooms\": [\n");
    for (int i = 0; i < db->n_rooms; i++) {
        DBRoom *r = &db->rooms[i];
        int last_room = (i == db->n_rooms - 1);
        fprintf(f, "    {\n");
        jw_kv(f, "      ", "code",     r->code,     1);
        jw_kv(f, "      ", "password", r->password, 1);

        // trusted
        fprintf(f, "      \"trusted\": [");
        for (int t = 0; t < r->n_trusted; t++) {
            jw_str(f, r->trusted[t]);
            if (t < r->n_trusted - 1) fputc(',', f);
        }
        fprintf(f, "],\n");

        // per-room bans
        fprintf(f, "      \"bans\": [\n");
        for (int b = 0; b < r->n_bans; b++)
            jw_ban(f, "        ", &r->bans[b], b < r->n_bans - 1);
        fprintf(f, "      ]\n");

        fprintf(f, "    }%s\n", last_room ? "" : ",");
    }
    fprintf(f, "  ],\n");

    // global bans
    fprintf(f, "  \"bans\": [\n");
    for (int i = 0; i < db->n_bans; i++)
        jw_ban(f, "    ", &db->bans[i], i < db->n_bans - 1);
    fprintf(f, "  ]\n");

    fprintf(f, "}\n");
    fclose(f);

#ifdef _WIN32
    remove(db->path);
#endif
    if (rename(tmp, db->path) != 0) { remove(tmp); return 0; }
    return 1;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void db_init(DB *db, const char *path) {
    memset(db, 0, sizeof(*db));
    scpy(db->path, path, DB_PATH_LEN);

    // Defaults (overwritten by db_load if file exists)
    scpy(db->config.name,    "OLServer", DB_NAME_LEN);
    scpy(db->config.bind_ip, "0.0.0.0",  DB_IP_BIND_LEN);
    db->config.port        = 7777;

    db_load(db);
}

// ---------------------------------------------------------------------------
// Rooms
// ---------------------------------------------------------------------------

DBRoom *db_find_room(DB *db, const char *code) {
    for (int i = 0; i < db->n_rooms; i++)
        if (strcmp(db->rooms[i].code, code) == 0)
            return &db->rooms[i];
    return NULL;
}

DBRoom *db_add_room(DB *db, const char *code, const char *password) {
    DBRoom *r = db_find_room(db, code);
    if (r) return r;
    if (db->n_rooms >= DB_MAX_ROOMS) return NULL;
    r = &db->rooms[db->n_rooms++];
    memset(r, 0, sizeof(*r));
    scpy(r->code,     code,     DB_ROOM_CODE_LEN);
    scpy(r->password, password, DB_PASSWORD_LEN);
    return r;
}

int db_update_room_password(DB *db, const char *code, const char *password) {
    DBRoom *r = db_find_room(db, code);
    if (!r) r = db_add_room(db, code, password);
    if (!r) return 0;
    scpy(r->password, password, DB_PASSWORD_LEN);
    return 1;
}

// ---------------------------------------------------------------------------
// Trusted IPs (per room)
// ---------------------------------------------------------------------------

int db_is_trusted(DBRoom *r, const char *ip) {
    for (int i = 0; i < r->n_trusted; i++)
        if (strcmp(r->trusted[i], ip) == 0) return 1;
    return 0;
}

int db_add_trusted(DBRoom *r, const char *ip) {
    if (db_is_trusted(r, ip)) return 1;
    if (r->n_trusted >= DB_MAX_TRUSTED) return 0;
    scpy(r->trusted[r->n_trusted++], ip, DB_IP_LEN);
    return 1;
}

int db_remove_trusted(DBRoom *r, const char *ip) {
    for (int i = 0; i < r->n_trusted; i++) {
        if (strcmp(r->trusted[i], ip) == 0) {
            memmove(r->trusted[i], r->trusted[i + 1],
                    (r->n_trusted - i - 1) * DB_IP_LEN);
            r->n_trusted--;
            return 1;
        }
    }
    return 0;
}

void db_clear_trusted(DBRoom *r) {
    r->n_trusted = 0;
    memset(r->trusted, 0, sizeof(r->trusted));
}

// ---------------------------------------------------------------------------
// Global bans
// ---------------------------------------------------------------------------

DBBan *db_find_ban(DB *db, const char *ip) {
    for (int i = 0; i < db->n_bans; i++)
        if (strcmp(db->bans[i].ip, ip) == 0) return &db->bans[i];
    return NULL;
}

DBBan *db_add_ban(DB *db, const char *ip, const char *nick, const char *reason) {
    DBBan *b = db_find_ban(db, ip);
    if (!b) {
        if (db->n_bans >= DB_MAX_BANS) return NULL;
        b = &db->bans[db->n_bans++];
        memset(b, 0, sizeof(*b));
    }
    scpy(b->ip,     ip,                  DB_IP_LEN);
    scpy(b->nick,   nick   ? nick   : "", DB_NICK_LEN);
    scpy(b->reason, reason ? reason : "", DB_REASON_LEN);
    now_str(b->banned_at, DB_TIME_LEN);
    return b;
}

int db_remove_ban(DB *db, const char *ip) {
    for (int i = 0; i < db->n_bans; i++) {
        if (strcmp(db->bans[i].ip, ip) == 0) {
            memmove(&db->bans[i], &db->bans[i + 1],
                    (db->n_bans - i - 1) * sizeof(DBBan));
            db->n_bans--;
            return 1;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Per-room bans
// ---------------------------------------------------------------------------

DBBan *db_find_room_ban(DBRoom *r, const char *ip) {
    for (int i = 0; i < r->n_bans; i++)
        if (strcmp(r->bans[i].ip, ip) == 0) return &r->bans[i];
    return NULL;
}

DBBan *db_add_room_ban(DBRoom *r, const char *ip, const char *nick, const char *reason) {
    DBBan *b = db_find_room_ban(r, ip);
    if (!b) {
        if (r->n_bans >= DB_MAX_BANS) return NULL;
        b = &r->bans[r->n_bans++];
        memset(b, 0, sizeof(*b));
    }
    scpy(b->ip,     ip,                  DB_IP_LEN);
    scpy(b->nick,   nick   ? nick   : "", DB_NICK_LEN);
    scpy(b->reason, reason ? reason : "", DB_REASON_LEN);
    now_str(b->banned_at, DB_TIME_LEN);
    return b;
}

int db_remove_room_ban(DBRoom *r, const char *ip) {
    for (int i = 0; i < r->n_bans; i++) {
        if (strcmp(r->bans[i].ip, ip) == 0) {
            memmove(&r->bans[i], &r->bans[i + 1],
                    (r->n_bans - i - 1) * sizeof(DBBan));
            r->n_bans--;
            return 1;
        }
    }
    return 0;
}
