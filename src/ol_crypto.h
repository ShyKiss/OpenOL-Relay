/*=============================================================================
    ol_crypto.h - connection handshake, shared by the client and the relay.

      C->S HS_HELLO      [type][version][zero padding to OL_HS_HELLO_BYTES]
      S->C HS_CHALLENGE  [type][version][server_pub 32][cookie 16]
      C->S HS_AUTH       [type][version][client_pub 32][cookie 16][mac 16][sealed]
                           sealed = [role(1)][proof 32][has_token(1)][token 32]
                                    [room_len(1)][room]
      S->C HS_RESULT     [type][version][session_pub 32][mac 16]
                         [sealed SRV_READY or SRV_HELLO_FAIL]

    A challenge is never larger than the hello, so the relay cannot be used to
    amplify a spoofed source. The cookie proves the client owns its address before
    the server spends time on X25519, and needs no state on the server.

    The server key is long-lived and the client pins it (see FMpConnection), so only
    the real server can open AUTH, which holds the proof that the client knows the
    room password or the simulator secret. Session keys also mix in a one-time server
    key: a stolen server key does not open recorded traffic.

    Rooms store ol_password_key(), never the password. That value is enough to join
    the room if stolen, but it does not reveal a password reused elsewhere.

    Limit: the first connection to an unknown server trusts whatever key arrives,
    unless the key was configured in advance. A man in the middle at that moment
    can read that session and try to guess the password offline.
=============================================================================*/
#pragma once

#include <stdint.h>

#ifdef _MSC_VER
#  pragma pack(push, 8)
#endif

#define OL_HS_VERSION       1
#define OL_HS_HELLO_BYTES   64
#define OL_HS_CHALLENGE_BYTES 50
#define OL_HS_AUTH_MAX      256
#define OL_HS_RESULT_MAX    372
#define OL_HS_ROOM_MAX      64

#define OL_ROLE_PLAYER 0
#define OL_ROLE_SIM    1

/* Fills out from the OS generator. Returns 0 on failure: never use the bytes then. */
int ol_random(uint8_t *out, unsigned len);

/* Client ------------------------------------------------------------------- */

typedef struct {
    uint8_t c2s_key[32];    /* valid after ol_hs_client_result opened an SRV_READY */
    uint8_t s2c_key[32];
    uint8_t result_key[32];
    uint8_t secret[32];
    uint8_t root[32];
} OlHsClient;

/* The server key inside a challenge of OL_HS_CHALLENGE_BYTES; check it before answering. */
const uint8_t *ol_hs_challenge_key(const uint8_t *challenge);

void ol_hs_client_hello(uint8_t out[OL_HS_HELLO_BYTES]);

/* Answers a challenge with a new key pair. token may be NULL. Returns the length
   of the AUTH packet in out[OL_HS_AUTH_MAX], or 0 if the challenge is invalid.
   secret is the room password, or the simulator secret for OL_ROLE_SIM. */
int ol_hs_client_auth(OlHsClient *hs, const uint8_t *challenge, int len, const char *room,
                      const char *secret, int role, const uint8_t *token, uint8_t *out);

/* Opens HS_RESULT into msg[OL_HS_RESULT_MAX]. Returns its length, 0 if not authentic. */
int ol_hs_client_result(OlHsClient *hs, const uint8_t *data, int len, uint8_t *msg);

/* Server ------------------------------------------------------------------- */

typedef struct {
    uint8_t secret[32];
    uint8_t pub[32];
    uint8_t cookie_key[32];
} OlHsServer;

typedef struct {
    int     role;
    int     has_token;
    char    room[OL_HS_ROOM_MAX];
    uint8_t token[32];
    uint8_t client_pub[32];
    uint8_t c2s_key[32];    /* set by ol_hs_server_session */
    uint8_t s2c_key[32];
    uint8_t result_key[32];
    uint8_t root[32];
    uint8_t cookie[16];
    uint8_t proof[32];
} OlHsAuth;

/* Uses secret, or generates a new key if it is NULL. Returns 0 if the OS generator failed. */
int  ol_hs_server_init(OlHsServer *hs, const uint8_t *secret);

/* who identifies the sender's address and port. Returns the bytes written to out. */
int  ol_hs_server_challenge(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                            uint8_t out[OL_HS_CHALLENGE_BYTES]);

/* Returns 1 and fills auth if the cookie is current and the packet authentic. */
int  ol_hs_server_auth(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                       const uint8_t *data, int len, OlHsAuth *auth);

/* Whether the client knows the simulator secret. */
int  ol_hs_proof_ok_secret(const OlHsAuth *auth, const char *secret);
/* Whether the client knows the password behind this ol_password_key(). */
int  ol_hs_proof_ok_key(const OlHsAuth *auth, const uint8_t key[32]);

/* Creates the session keys for an accepted client. Returns 0 if the OS generator failed. */
int  ol_hs_server_session(OlHsAuth *auth, uint8_t session_pub[32]);

/* Seals msg into out[OL_HS_RESULT_MAX]. session_pub is NULL when refusing.
   Returns the packet length, 0 if msg is too long. */
int  ol_hs_server_result(const uint8_t result_key[32], const uint8_t *session_pub,
                         const void *msg, int msg_len, uint8_t *out);

/* Slow on purpose (about 16 MB and 3 passes). Bound to the server key, so the same password
   gives a different value on another server. Returns 0 if memory ran out. */
int  ol_password_key(const uint8_t server_pub[32], const char *password, uint8_t out[32]);

#ifdef _MSC_VER
#  pragma pack(pop)
#endif
