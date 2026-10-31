/*=============================================================================
    ol_transport.c - see ol_transport.h
=============================================================================*/
#include "ol_transport.h"
#include "openol_protocol.h"
#include "third_party/monocypher/monocypher.h"
#include <stdlib.h>
#include <string.h>

#define OL_COUNTER_AT  9
#define OL_MAC_AT      13
#define OL_SEALED_AT   29

#define OL_RTO_INITIAL 0.2
#define OL_RTO_MIN     0.05
#define OL_RTO_MAX     1.0

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p) | ((uint32_t)get16(p + 2) << 16); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }
static uint64_t get64(const uint8_t *p) { return (uint64_t)get32(p) | ((uint64_t)get32(p + 4) << 32); }

/* Wrapping distance a - b. */
static int id_diff(uint16_t a, uint16_t b) { return (int)(int16_t)(uint16_t)(a - b); }

void ol_conn_free(OlConn *c) {
    int i;
    for (i = 0; i < OL_QUEUE_SIZE; i++) {
        free(c->q[i].data);
        c->q[i].data = NULL;
    }
    for (i = 0; i < OL_WINDOW; i++) {
        free(c->in_buf[i]);
        c->in_buf[i] = NULL;
    }
}

void ol_conn_reset(OlConn *c, uint64_t conn_id) {
    ol_conn_free(c);
    memset(c, 0, sizeof(*c));
    c->conn_id = conn_id;
    c->rto = OL_RTO_INITIAL;
}

void ol_conn_set_keys(OlConn *c, const uint8_t send_key[32], const uint8_t recv_key[32]) {
    memcpy(c->send_key, send_key, 32);
    memcpy(c->recv_key, recv_key, 32);
    c->keyed = 1;
}

int ol_conn_reliable_room(const OlConn *c) { return OL_QUEUE_SIZE - c->out_count; }
int ol_conn_reliable_pending(const OlConn *c) { return c->out_count; }

int ol_conn_send(OlConn *c, int lane, const void *msg, int len) {
    if (len <= 0 || len > OL_MAX_MSG) return 0;

    if (lane == OL_LANE_STATE) {
        if (c->state_len + 2 + len > OL_STATE_BUF) return 0;
        put16(c->state_buf + c->state_len, (uint16_t)len);
        memcpy(c->state_buf + c->state_len + 2, msg, len);
        c->state_len += 2 + len;
        return 1;
    } else {
        OlOutMsg *m;
        uint8_t *copy;
        if (c->out_count >= OL_QUEUE_SIZE) return 0;
        copy = (uint8_t *)malloc(len);
        if (!copy) return 0;
        memcpy(copy, msg, len);
        m = &c->q[(c->out_head + c->out_count) % OL_QUEUE_SIZE];
        m->data = copy;
        m->len = (uint16_t)len;
        m->attempts = 0;
        m->last_sent = 0.0;
        c->out_count++;
        return 1;
    }
}

static int write_header(OlConn *c, uint8_t *p) {
    uint32_t bits = 0;
    int i;
    for (i = 0; i < 32; i++) {
        uint16_t id = (uint16_t)(c->in_next + 1 + i);
        if (c->in_got[id % OL_WINDOW]) bits |= (uint32_t)1 << i;
    }
    p[0] = OL_MAGIC;
    put64(p + 1, c->conn_id);
    put16(p + OL_SEALED_AT, c->send_seq++);
    put16(p + OL_SEALED_AT + 2, c->in_next);
    put32(p + OL_SEALED_AT + 4, bits);
    return OL_HEADER_BYTES;
}

/* Keys are per session and direction, so the counter alone makes the nonce unique. */
static void make_nonce(uint8_t nonce[24], uint32_t counter) {
    memset(nonce, 0, 24);
    put32(nonce, counter);
}

static void seal(OlConn *c, uint8_t *p, int n) {
    uint8_t nonce[24];
    uint32_t counter = c->send_counter++;
    put32(p + OL_COUNTER_AT, counter);
    make_nonce(nonce, counter);
    crypto_aead_lock(p + OL_SEALED_AT, p + OL_MAC_AT, c->send_key, nonce,
                     p, OL_MAC_AT, p + OL_SEALED_AT, n - OL_SEALED_AT);
}

/* Decrypts in place. Replay state changes only after the datagram proved authentic. */
static int unseal(OlConn *c, uint8_t *p, int n, const uint8_t *data) {
    uint8_t nonce[24];
    uint32_t counter = get32(data + OL_COUNTER_AT);
    uint32_t behind = 0;

    if (c->have_counter && counter <= c->recv_counter) {
        behind = c->recv_counter - counter;
        if (behind >= 64 || (c->recv_window >> behind) & 1) return 0;
    }
    make_nonce(nonce, counter);
    if (crypto_aead_unlock(p + OL_SEALED_AT, data + OL_MAC_AT, c->recv_key, nonce,
                           data, OL_MAC_AT, data + OL_SEALED_AT, n - OL_SEALED_AT) != 0)
        return 0;

    if (!c->have_counter) {
        c->have_counter = 1;
        c->recv_counter = counter;
        c->recv_window = 1;
    } else if (counter > c->recv_counter) {
        uint32_t ahead = counter - c->recv_counter;
        c->recv_window = ahead >= 64 ? 0 : c->recv_window << ahead;
        c->recv_window |= 1;
        c->recv_counter = counter;
    } else {
        c->recv_window |= (uint64_t)1 << behind;
    }
    return 1;
}

void ol_conn_flush(OlConn *c, double now, OlSendFn send, void *user) {
    int state_pos = 0;
    int next = 0;  /* position in the reliable queue */
    int limit = c->out_count < OL_WINDOW ? c->out_count : OL_WINDOW;

    if (!c->keyed) return;

    for (;;) {
        uint8_t p[OL_MAX_DATAGRAM];
        int n = write_header(c, p);
        int added = 0;

        while (state_pos < c->state_len) {
            int len = get16(c->state_buf + state_pos);
            if (n + 3 + len > OL_MAX_DATAGRAM) break;
            p[n] = OL_LANE_STATE;
            put16(p + n + 1, (uint16_t)len);
            memcpy(p + n + 3, c->state_buf + state_pos + 2, len);
            n += 3 + len;
            state_pos += 2 + len;
            added++;
        }

        while (next < limit) {
            OlOutMsg *m = &c->q[(c->out_head + next) % OL_QUEUE_SIZE];
            if (m->data) {
                /* Exponential backoff so a dead link does not flood. */
                int shift = m->attempts > 4 ? 4 : m->attempts;
                double wait = m->attempts ? c->rto * (double)(1 << (shift - 1)) : 0.0;
                if (!m->attempts || now - m->last_sent >= wait) {
                    if (n + 5 + m->len > OL_MAX_DATAGRAM) break;
                    p[n] = OL_LANE_RELIABLE;
                    put16(p + n + 1, (uint16_t)(c->out_base + next));
                    put16(p + n + 3, m->len);
                    memcpy(p + n + 5, m->data, m->len);
                    n += 5 + m->len;
                    if (m->attempts) c->retransmits++;
                    m->attempts++;
                    m->last_sent = now;
                    added++;
                }
            }
            next++;
        }

        if (!added && !c->ack_dirty) {
            /* Nothing to say: the header was built but never sent. */
            c->send_seq--;
            break;
        }
        seal(c, p, n);
        send(user, p, n);
        c->ack_dirty = 0;
        if (state_pos >= c->state_len && next >= limit) break;
    }
    c->state_len = 0;
}

static void ack_one(OlConn *c, int offset, double now) {
    OlOutMsg *m = &c->q[(c->out_head + offset) % OL_QUEUE_SIZE];
    if (!m->data) return;
    /* Only an unambiguous first transmission gives a valid round-trip sample. */
    if (m->attempts == 1) {
        double rtt = now - m->last_sent;
        c->srtt = c->srtt > 0.0 ? c->srtt * 0.875 + rtt * 0.125 : rtt;
        c->rto = c->srtt * 2.0;
        if (c->rto < OL_RTO_MIN) c->rto = OL_RTO_MIN;
        if (c->rto > OL_RTO_MAX) c->rto = OL_RTO_MAX;
    }
    free(m->data);
    m->data = NULL;
}

static void process_acks(OlConn *c, uint16_t ack_next, uint32_t bits, double now) {
    int upto = id_diff(ack_next, c->out_base);
    int i;
    if (upto < 0 || upto > c->out_count) return;  /* stale or bogus */

    for (i = 0; i < upto; i++) ack_one(c, i, now);
    for (i = 0; i < 32; i++) {
        int off = upto + 1 + i;
        if ((bits >> i) & 1 && off < c->out_count) ack_one(c, off, now);
    }
    while (c->out_count > 0 && !c->q[c->out_head].data) {
        c->out_head = (uint16_t)((c->out_head + 1) % OL_QUEUE_SIZE);
        c->out_base++;
        c->out_count--;
    }
}

static void receive_reliable(OlConn *c, uint16_t id, const uint8_t *bytes, int len,
                             OlDeliverFn deliver, void *user) {
    int ahead = id_diff(id, c->in_next);
    int slot = id % OL_WINDOW;
    c->ack_dirty = 1;
    if (ahead < 0 || ahead >= OL_WINDOW || c->in_got[slot]) return;

    c->in_buf[slot] = (uint8_t *)malloc(len);
    if (!c->in_buf[slot]) return;
    memcpy(c->in_buf[slot], bytes, len);
    c->in_len[slot] = (uint16_t)len;
    c->in_got[slot] = 1;

    for (;;) {
        uint8_t *msg;
        int msg_len;
        slot = c->in_next % OL_WINDOW;
        if (!c->in_got[slot]) break;
        msg = c->in_buf[slot];
        msg_len = c->in_len[slot];
        c->in_buf[slot] = NULL;
        c->in_got[slot] = 0;
        c->in_next++;
        deliver(user, OL_LANE_RELIABLE, msg, msg_len);
        free(msg);
    }
}

int ol_peek_conn_id(const uint8_t *data, int len, uint64_t *out) {
    if (len < OL_HEADER_BYTES || data[0] != OL_MAGIC) return 0;
    *out = get64(data + 1);
    return 1;
}

int ol_conn_on_datagram(OlConn *c, double now, const uint8_t *packet, int len,
                        OlDeliverFn deliver, void *user) {
    uint8_t data[OL_MAX_DATAGRAM];
    uint64_t conn_id;
    uint16_t seq;
    int fresh, off;

    if (!c->keyed || len > OL_MAX_DATAGRAM) return 0;
    if (!ol_peek_conn_id(packet, len, &conn_id) || conn_id != c->conn_id) return 0;
    if (!unseal(c, data, len, packet)) return 0;

    seq = get16(data + OL_SEALED_AT);
    process_acks(c, get16(data + OL_SEALED_AT + 2), get32(data + OL_SEALED_AT + 4), now);

    fresh = !c->have_recv || id_diff(seq, c->recv_seq) > 0;
    if (fresh) {
        c->recv_seq = seq;
        c->have_recv = 1;
    }

    off = OL_HEADER_BYTES;
    while (off < len) {
        int lane = data[off];
        if (lane == OL_LANE_STATE) {
            int msg_len;
            uint8_t tmp[OL_MAX_DATAGRAM];
            if (off + 3 > len) break;
            msg_len = get16(data + off + 1);
            if (msg_len <= 0 || msg_len > OL_MAX_MSG || off + 3 + msg_len > len) break;
            if (fresh) {
                memcpy(tmp, data + off + 3, msg_len);
                deliver(user, OL_LANE_STATE, tmp, msg_len);
            }
            off += 3 + msg_len;
        } else if (lane == OL_LANE_RELIABLE) {
            uint16_t id;
            int msg_len;
            if (off + 5 > len) break;
            id = get16(data + off + 1);
            msg_len = get16(data + off + 3);
            if (msg_len <= 0 || msg_len > OL_MAX_MSG || off + 5 + msg_len > len) break;
            receive_reliable(c, id, data + off + 5, msg_len, deliver, user);
            off += 5 + msg_len;
        } else {
            break;
        }
    }
    return 1;
}

int ol_lane_for(uint8_t channel, uint8_t type) {
    if (channel == CH_HERO && (type == HERO_STATE || type == HERO_HEAD_ROT)) return OL_LANE_STATE;
    if (channel == CH_ENEMY && type == ENEMY_LOC) return OL_LANE_STATE;
    if (channel == CH_SRV && type == SRV_PING) return OL_LANE_STATE;
    return OL_LANE_RELIABLE;
}
