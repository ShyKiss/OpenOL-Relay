/*=============================================================================
    ol_transport.h - reliable UDP transport shared by the client and the relay.

    Datagram (at most OL_MAX_DATAGRAM bytes):
      [OL_MAGIC(1)][conn_id LE8][counter LE4][mac 16]
      sealed: [seq LE2][ack_next LE2][ack_bits LE4]
              { [lane(1)][msg_id LE2, reliable lane only][len LE2][bytes] } * N

    XChaCha20-Poly1305, one key per direction, the clear part is authenticated too.
    A datagram that fails the check changes nothing, and each counter value is
    accepted once. A connection without keys neither sends nor accepts anything.

    OL_LANE_STATE    unreliable, messages from older datagrams are dropped
    OL_LANE_RELIABLE reliable and ordered

    ack_next is the next reliable msg_id the peer expects; bit i of ack_bits
    means ack_next + 1 + i has already arrived. No engine dependencies, the
    embedded relay and the game link the same object from openol_relay.lib.
=============================================================================*/
#pragma once

#include <stdint.h>

#ifdef _MSC_VER
#  pragma pack(push, 8)
#endif

#define OL_MAGIC          0xF3
#define OL_MAX_DATAGRAM   1200
#define OL_HEADER_BYTES   37
#define OL_MAX_MSG        (OL_MAX_DATAGRAM - OL_HEADER_BYTES - 5)
#define OL_QUEUE_SIZE     512   /* queued reliable messages per connection */
#define OL_WINDOW         128   /* reliable messages in flight, and reorder buffer size */
#define OL_STATE_BUF      8192  /* unreliable bytes queued between flushes */

#define OL_LANE_STATE     0
#define OL_LANE_RELIABLE  1

typedef struct {
    uint8_t *data;       /* NULL once acknowledged */
    uint16_t len;
    uint16_t attempts;
    double   last_sent;
} OlOutMsg;

typedef struct {
    uint64_t conn_id;
    double   srtt;
    double   rto;

    /* Outgoing reliable queue: q[out_head] holds msg_id out_base. */
    OlOutMsg q[OL_QUEUE_SIZE];
    uint16_t out_head;
    uint16_t out_count;
    uint16_t out_base;

    /* Incoming reliable reorder buffer, indexed by msg_id % OL_WINDOW. */
    uint8_t *in_buf[OL_WINDOW];
    uint16_t in_len[OL_WINDOW];
    uint8_t  in_got[OL_WINDOW];
    uint16_t in_next;

    uint16_t send_seq;
    uint16_t recv_seq;
    uint8_t  have_recv;
    uint8_t  ack_dirty;

    uint8_t  send_key[32];
    uint8_t  recv_key[32];
    uint8_t  keyed;
    uint8_t  have_counter;
    uint32_t send_counter;
    uint32_t recv_counter;             /* highest accepted */
    uint64_t recv_window;              /* bit i: recv_counter - i was accepted */

    uint8_t  state_buf[OL_STATE_BUF];  /* { [len LE2][bytes] } * N */
    int      state_len;
} OlConn;

typedef void (*OlDeliverFn)(void *user, int lane, uint8_t *msg, int len);
typedef void (*OlSendFn)(void *user, const uint8_t *datagram, int len);

/* A zeroed OlConn is valid to reset or free. */
void ol_conn_reset(OlConn *c, uint64_t conn_id);
void ol_conn_free(OlConn *c);

/* Must follow every reset: the keys go away with it. */
void ol_conn_set_keys(OlConn *c, const uint8_t send_key[32], const uint8_t recv_key[32]);

/* Returns 1 if queued, 0 if the message is too large or the queue is full. */
int  ol_conn_send(OlConn *c, int lane, const void *msg, int len);
/* Reliable messages that can still be queued. */
int  ol_conn_reliable_room(const OlConn *c);
/* Reliable messages not yet acknowledged. */
int  ol_conn_reliable_pending(const OlConn *c);

/* Sends queued state, due reliable messages and acks. */
void ol_conn_flush(OlConn *c, double now, OlSendFn send, void *user);

/* Handles one datagram. Returns 1 if it is authentic and new, 0 if it was ignored. */
int  ol_conn_on_datagram(OlConn *c, double now, const uint8_t *data, int len,
                         OlDeliverFn deliver, void *user);

/* Reads conn_id from a datagram without touching any connection. Returns 0 if malformed. */
int  ol_peek_conn_id(const uint8_t *data, int len, uint64_t *out);

/* Which lane a [channel][type]... message travels on. */
int  ol_lane_for(uint8_t channel, uint8_t type);

#ifdef _MSC_VER
#  pragma pack(pop)
#endif
