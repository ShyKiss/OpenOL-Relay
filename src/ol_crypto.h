/*=============================================================================
    ol_crypto.h - connection handshake, shared by the client and the relay.

      C->S HS_HELLO      [type][version][zero padding to OL_HS_HELLO_BYTES]
      S->C HS_CHALLENGE  [type][version][server_pub 32][cookie 16]
      C->S HS_AUTH       [type][version][client_pub 32][cookie 16][mac 16][sealed]
                           sealed = [role(1)][proof 32][has_token(1)][token 32]
                                    [room_len(1)][room]
      S->C HS_RESULT     [type][version][mac 16][sealed SRV_READY or SRV_HELLO_FAIL]

    A challenge is never larger than the hello, so the relay cannot be used to
    amplify a spoofed source. The cookie proves the client owns its address before
    the server spends time on X25519, and needs no state on the server.

    The proof shows the client knows the room password (or the simulator secret)
    without sending it. Limit: the server key is not authenticated, so an active
    man in the middle can read a session and try to guess a weak password offline.
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
#define OL_HS_RESULT_MAX    340
#define OL_HS_ROOM_MAX      64

#define OL_ROLE_PLAYER 0
#define OL_ROLE_SIM    1

/* Fills out from the OS generator. Returns 0 on failure: never use the bytes then. */
int ol_random(uint8_t *out, unsigned len);

/* Client ------------------------------------------------------------------- */

typedef struct {
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint8_t result_key[32];
} OlHsClient;

void ol_hs_client_hello(uint8_t out[OL_HS_HELLO_BYTES]);

/* Answers a challenge with a new key pair. token may be NULL. Returns the length
   of the AUTH packet in out[OL_HS_AUTH_MAX], or 0 if the challenge is invalid. */
int ol_hs_client_auth(OlHsClient *hs, const uint8_t *challenge, int len, const char *room,
                      const char *secret, int role, const uint8_t *token, uint8_t *out);

/* Opens HS_RESULT into msg[OL_HS_RESULT_MAX]. Returns its length, 0 if not authentic. */
int ol_hs_client_result(const OlHsClient *hs, const uint8_t *data, int len, uint8_t *msg);

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
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint8_t result_key[32];
    uint8_t root[32];
    uint8_t cookie[16];
    uint8_t proof[32];
} OlHsAuth;

/* Returns 0 if the OS generator failed. */
int  ol_hs_server_init(OlHsServer *hs);

/* who identifies the sender's address and port. Returns the bytes written to out. */
int  ol_hs_server_challenge(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                            uint8_t out[OL_HS_CHALLENGE_BYTES]);

/* Returns 1 and fills auth if the cookie is current and the packet authentic. */
int  ol_hs_server_auth(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                       const uint8_t *data, int len, OlHsAuth *auth);

/* Whether the client knows secret. */
int  ol_hs_proof_ok(const OlHsAuth *auth, const char *secret);

/* Seals msg into out[OL_HS_RESULT_MAX]. Returns the packet length, 0 if msg is too long. */
int  ol_hs_server_result(const uint8_t result_key[32], const void *msg, int msg_len, uint8_t *out);

#ifdef _MSC_VER
#  pragma pack(pop)
#endif
