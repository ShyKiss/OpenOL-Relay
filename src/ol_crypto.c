/*=============================================================================
    ol_crypto.c - see ol_crypto.h
=============================================================================*/
#include "ol_crypto.h"
#include "openol_protocol.h"
#include "third_party/monocypher/monocypher.h"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

/* A cookie stays valid for one to two of these periods. */
#define OL_COOKIE_PERIOD 30

#define OL_CHAL_PUB   2
#define OL_CHAL_COOKIE (OL_CHAL_PUB + 32)
#define OL_AUTH_PUB   2
#define OL_AUTH_COOKIE (OL_AUTH_PUB + 32)
#define OL_AUTH_MAC   (OL_AUTH_COOKIE + 16)
#define OL_AUTH_SEALED (OL_AUTH_MAC + 16)
#define OL_RESULT_MAC 2
#define OL_RESULT_SEALED (OL_RESULT_MAC + 16)
/* role + proof + has_token + token + room_len */
#define OL_AUTH_FIXED (1 + 32 + 1 + 32 + 1)

int ol_random(uint8_t *out, unsigned len) {
#ifdef _WIN32
    typedef BOOLEAN (APIENTRY *RtlGenRandomFn)(PVOID, ULONG);
    RtlGenRandomFn gen = NULL;
    HMODULE lib = LoadLibraryA("advapi32.dll");
    if (lib) gen = (RtlGenRandomFn)GetProcAddress(lib, "SystemFunction036");
    return gen && gen(out, len);
#else
    size_t got = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { got = fread(out, 1, len, f); fclose(f); }
    return got == len;
#endif
}

static void derive_key(uint8_t out[32], const uint8_t root[32], const char *label) {
    crypto_blake2b_keyed(out, 32, root, 32, (const uint8_t *)label, strlen(label));
}

/* Both sides mix in the two public keys, so each session gets its own keys. */
static void derive_session(const uint8_t shared[32], const uint8_t client_pub[32], const uint8_t server_pub[32],
                           uint8_t root[32], uint8_t auth_key[32], uint8_t c2s[32], uint8_t s2c[32], uint8_t result[32]) {
    uint8_t in[96];
    memcpy(in, shared, 32);
    memcpy(in + 32, client_pub, 32);
    memcpy(in + 64, server_pub, 32);
    crypto_blake2b(root, 32, in, sizeof(in));
    derive_key(auth_key, root, "openol auth");
    derive_key(c2s, root, "openol c2s");
    derive_key(s2c, root, "openol s2c");
    derive_key(result, root, "openol result");
    crypto_wipe(in, sizeof(in));
}

static void make_proof(uint8_t out[32], const uint8_t root[32], const uint8_t cookie[16], const char *secret) {
    uint8_t key[32];
    uint8_t in[48];
    crypto_blake2b(key, 32, (const uint8_t *)secret, strlen(secret));
    memcpy(in, root, 32);
    memcpy(in + 32, cookie, 16);
    crypto_blake2b_keyed(out, 32, key, 32, in, sizeof(in));
    crypto_wipe(key, sizeof(key));
    crypto_wipe(in, sizeof(in));
}

/* The keys are single-use or the message is an exact retransmission. */
static const uint8_t k_zero_nonce[24] = {0};

/* --- client --- */

void ol_hs_client_hello(uint8_t out[OL_HS_HELLO_BYTES]) {
    memset(out, 0, OL_HS_HELLO_BYTES);
    out[0] = OL_HS_HELLO;
    out[1] = OL_HS_VERSION;
}

int ol_hs_client_auth(OlHsClient *hs, const uint8_t *challenge, int len, const char *room,
                      const char *secret, int role, const uint8_t *token, uint8_t *out) {
    uint8_t priv[32], pub[32], shared[32], root[32], auth_key[32];
    uint8_t *plain = out + OL_AUTH_SEALED;
    int room_len = (int)strlen(room);
    int plain_len = OL_AUTH_FIXED + room_len;

    if (len != OL_HS_CHALLENGE_BYTES || challenge[0] != OL_HS_CHALLENGE || challenge[1] != OL_HS_VERSION) return 0;
    if (room_len >= OL_HS_ROOM_MAX || OL_AUTH_SEALED + plain_len > OL_HS_AUTH_MAX) return 0;
    if (!ol_random(priv, sizeof(priv))) return 0;

    crypto_x25519_public_key(pub, priv);
    crypto_x25519(shared, priv, challenge + OL_CHAL_PUB);
    derive_session(shared, pub, challenge + OL_CHAL_PUB, root, auth_key, hs->c2s_key, hs->s2c_key, hs->result_key);

    out[0] = OL_HS_AUTH;
    out[1] = OL_HS_VERSION;
    memcpy(out + OL_AUTH_PUB, pub, 32);
    memcpy(out + OL_AUTH_COOKIE, challenge + OL_CHAL_COOKIE, 16);

    plain[0] = (uint8_t)role;
    make_proof(plain + 1, root, challenge + OL_CHAL_COOKIE, secret);
    plain[33] = token ? 1 : 0;
    if (token) memcpy(plain + 34, token, 32);
    else       memset(plain + 34, 0, 32);
    plain[66] = (uint8_t)room_len;
    memcpy(plain + OL_AUTH_FIXED, room, room_len);

    crypto_aead_lock(plain, out + OL_AUTH_MAC, auth_key, k_zero_nonce, out, OL_AUTH_MAC, plain, plain_len);

    crypto_wipe(priv, sizeof(priv));
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(root, sizeof(root));
    crypto_wipe(auth_key, sizeof(auth_key));
    return OL_AUTH_SEALED + plain_len;
}

int ol_hs_client_result(const OlHsClient *hs, const uint8_t *data, int len, uint8_t *msg) {
    int msg_len = len - OL_RESULT_SEALED;
    if (msg_len <= 0 || msg_len > OL_HS_RESULT_MAX) return 0;
    if (data[0] != OL_HS_RESULT || data[1] != OL_HS_VERSION) return 0;
    if (crypto_aead_unlock(msg, data + OL_RESULT_MAC, hs->result_key, k_zero_nonce,
                           data, OL_RESULT_MAC, data + OL_RESULT_SEALED, msg_len) != 0)
        return 0;
    return msg_len;
}

/* --- server --- */

int ol_hs_server_init(OlHsServer *hs) {
    if (!ol_random(hs->secret, 32) || !ol_random(hs->cookie_key, 32)) return 0;
    crypto_x25519_public_key(hs->pub, hs->secret);
    return 1;
}

static void make_cookie(const OlHsServer *hs, const void *who, int who_len, uint32_t period, uint8_t out[16]) {
    uint8_t in[64];
    if (who_len > 60) who_len = 60;
    memcpy(in, who, who_len);
    in[who_len]     = (uint8_t)period;
    in[who_len + 1] = (uint8_t)(period >> 8);
    in[who_len + 2] = (uint8_t)(period >> 16);
    in[who_len + 3] = (uint8_t)(period >> 24);
    crypto_blake2b_keyed(out, 16, hs->cookie_key, 32, in, who_len + 4);
}

int ol_hs_server_challenge(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                           uint8_t out[OL_HS_CHALLENGE_BYTES]) {
    out[0] = OL_HS_CHALLENGE;
    out[1] = OL_HS_VERSION;
    memcpy(out + OL_CHAL_PUB, hs->pub, 32);
    make_cookie(hs, who, who_len, time_sec / OL_COOKIE_PERIOD, out + OL_CHAL_COOKIE);
    return OL_HS_CHALLENGE_BYTES;
}

int ol_hs_server_auth(const OlHsServer *hs, const void *who, int who_len, uint32_t time_sec,
                      const uint8_t *data, int len, OlHsAuth *auth) {
    uint8_t expected[16], shared[32], auth_key[32];
    uint8_t plain[OL_HS_AUTH_MAX];
    uint32_t period = time_sec / OL_COOKIE_PERIOD;
    int plain_len = len - OL_AUTH_SEALED;
    int room_len, ok;

    if (plain_len < OL_AUTH_FIXED || len > OL_HS_AUTH_MAX) return 0;
    if (data[0] != OL_HS_AUTH || data[1] != OL_HS_VERSION) return 0;

    make_cookie(hs, who, who_len, period, expected);
    ok = crypto_verify16(expected, data + OL_AUTH_COOKIE) == 0;
    if (!ok) {
        make_cookie(hs, who, who_len, period - 1, expected);
        ok = crypto_verify16(expected, data + OL_AUTH_COOKIE) == 0;
    }
    if (!ok) return 0;

    memcpy(auth->client_pub, data + OL_AUTH_PUB, 32);
    memcpy(auth->cookie, data + OL_AUTH_COOKIE, 16);
    crypto_x25519(shared, hs->secret, auth->client_pub);
    derive_session(shared, auth->client_pub, hs->pub, auth->root, auth_key,
                   auth->c2s_key, auth->s2c_key, auth->result_key);
    ok = crypto_aead_unlock(plain, data + OL_AUTH_MAC, auth_key, k_zero_nonce,
                            data, OL_AUTH_MAC, data + OL_AUTH_SEALED, plain_len) == 0;
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(auth_key, sizeof(auth_key));
    if (!ok) return 0;

    room_len = plain[66];
    if (room_len >= OL_HS_ROOM_MAX || OL_AUTH_FIXED + room_len != plain_len) return 0;
    auth->role = plain[0];
    memcpy(auth->proof, plain + 1, 32);
    auth->has_token = plain[33] != 0;
    memcpy(auth->token, plain + 34, 32);
    memcpy(auth->room, plain + OL_AUTH_FIXED, room_len);
    auth->room[room_len] = '\0';
    return 1;
}

int ol_hs_proof_ok(const OlHsAuth *auth, const char *secret) {
    uint8_t expected[32];
    int ok;
    make_proof(expected, auth->root, auth->cookie, secret);
    ok = crypto_verify32(expected, auth->proof) == 0;
    crypto_wipe(expected, sizeof(expected));
    return ok;
}

int ol_hs_server_result(const uint8_t result_key[32], const void *msg, int msg_len, uint8_t *out) {
    if (msg_len <= 0 || msg_len > OL_HS_RESULT_MAX - OL_RESULT_SEALED) return 0;
    out[0] = OL_HS_RESULT;
    out[1] = OL_HS_VERSION;
    memcpy(out + OL_RESULT_SEALED, msg, msg_len);
    crypto_aead_lock(out + OL_RESULT_SEALED, out + OL_RESULT_MAC, result_key, k_zero_nonce,
                     out, OL_RESULT_MAC, out + OL_RESULT_SEALED, msg_len);
    return OL_RESULT_SEALED + msg_len;
}
