/*=============================================================================
    ol_crypto.c - see ol_crypto.h
=============================================================================*/
#include "ol_crypto.h"
#include "openol_protocol.h"
#include "third_party/monocypher/monocypher.h"
#include <stdio.h>
#include <stdlib.h>
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
#define OL_RESULT_PUB 2
#define OL_RESULT_MAC (OL_RESULT_PUB + 32)
#define OL_RESULT_SEALED (OL_RESULT_MAC + 16)

#define OL_ARGON2_BLOCKS 16384  /* 1 KB each */
#define OL_ARGON2_PASSES 3
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

static int is_zero32(const uint8_t v[32]) {
    static const uint8_t zero[32] = {0};
    return crypto_verify32(v, zero) == 0;
}

/* Both sides mix in the two public keys, so each handshake gets its own keys. */
static void derive_handshake(const uint8_t shared[32], const uint8_t client_pub[32], const uint8_t server_pub[32],
                             uint8_t root[32], uint8_t auth_key[32], uint8_t result[32]) {
    uint8_t in[96];
    memcpy(in, shared, 32);
    memcpy(in + 32, client_pub, 32);
    memcpy(in + 64, server_pub, 32);
    crypto_blake2b(root, 32, in, sizeof(in));
    derive_key(auth_key, root, "openol auth");
    derive_key(result, root, "openol result");
    crypto_wipe(in, sizeof(in));
}

/* Forward secrecy: session_shared comes from keys that exist for this session only. */
static void derive_session(const uint8_t root[32], const uint8_t session_shared[32], uint8_t c2s[32], uint8_t s2c[32]) {
    uint8_t in[64], key[32];
    memcpy(in, root, 32);
    memcpy(in + 32, session_shared, 32);
    crypto_blake2b(key, 32, in, sizeof(in));
    derive_key(c2s, key, "openol c2s");
    derive_key(s2c, key, "openol s2c");
    crypto_wipe(in, sizeof(in));
    crypto_wipe(key, sizeof(key));
}

static void make_proof_key(uint8_t out[32], const uint8_t root[32], const uint8_t cookie[16], const uint8_t key[32]) {
    uint8_t in[48];
    memcpy(in, root, 32);
    memcpy(in + 32, cookie, 16);
    crypto_blake2b_keyed(out, 32, key, 32, in, sizeof(in));
    crypto_wipe(in, sizeof(in));
}

static void secret_key(uint8_t out[32], const char *secret) {
    crypto_blake2b(out, 32, (const uint8_t *)secret, strlen(secret));
}

int ol_password_key(const uint8_t server_pub[32], const char *password, uint8_t out[32]) {
    crypto_argon2_config config;
    crypto_argon2_inputs inputs;
    void *work = malloc((size_t)OL_ARGON2_BLOCKS * 1024);
    if (!work) return 0;
    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = OL_ARGON2_BLOCKS;
    config.nb_passes = OL_ARGON2_PASSES;
    config.nb_lanes  = 1;
    inputs.pass = (const uint8_t *)password;
    inputs.pass_size = (uint32_t)strlen(password);
    inputs.salt = server_pub;
    inputs.salt_size = 32;
    crypto_argon2(out, 32, work, config, inputs, crypto_argon2_no_extras);
    free(work);
    return 1;
}

/* The keys are single-use or the message is an exact retransmission. */
static const uint8_t k_zero_nonce[24] = {0};

/* --- client --- */

const uint8_t *ol_hs_challenge_key(const uint8_t *challenge) {
    return challenge + OL_CHAL_PUB;
}

void ol_hs_client_hello(uint8_t out[OL_HS_HELLO_BYTES]) {
    memset(out, 0, OL_HS_HELLO_BYTES);
    out[0] = OL_HS_HELLO;
    out[1] = OL_HS_VERSION;
}

int ol_hs_client_auth(OlHsClient *hs, const uint8_t *challenge, int len, const char *room,
                      const char *secret, int role, const uint8_t *token, uint8_t *out) {
    uint8_t pub[32], shared[32], auth_key[32], key[32];
    uint8_t *plain = out + OL_AUTH_SEALED;
    int room_len = (int)strlen(room);
    int plain_len = OL_AUTH_FIXED + room_len;

    if (len != OL_HS_CHALLENGE_BYTES || challenge[0] != OL_HS_CHALLENGE || challenge[1] != OL_HS_VERSION) return 0;
    if (room_len >= OL_HS_ROOM_MAX || OL_AUTH_SEALED + plain_len > OL_HS_AUTH_MAX) return 0;
    if (!ol_random(hs->secret, 32)) return 0;

    crypto_x25519_public_key(pub, hs->secret);
    crypto_x25519(shared, hs->secret, challenge + OL_CHAL_PUB);
    if (is_zero32(shared)) return 0;  /* a low-order key would make the result predictable */
    derive_handshake(shared, pub, challenge + OL_CHAL_PUB, hs->root, auth_key, hs->result_key);

    if (role == OL_ROLE_SIM || !secret[0]) secret_key(key, secret);
    else if (!ol_password_key(challenge + OL_CHAL_PUB, secret, key)) return 0;

    out[0] = OL_HS_AUTH;
    out[1] = OL_HS_VERSION;
    memcpy(out + OL_AUTH_PUB, pub, 32);
    memcpy(out + OL_AUTH_COOKIE, challenge + OL_CHAL_COOKIE, 16);

    plain[0] = (uint8_t)role;
    make_proof_key(plain + 1, hs->root, challenge + OL_CHAL_COOKIE, key);
    crypto_wipe(key, sizeof(key));
    plain[33] = token ? 1 : 0;
    if (token) memcpy(plain + 34, token, 32);
    else       memset(plain + 34, 0, 32);
    plain[66] = (uint8_t)room_len;
    memcpy(plain + OL_AUTH_FIXED, room, room_len);

    crypto_aead_lock(plain, out + OL_AUTH_MAC, auth_key, k_zero_nonce, out, OL_AUTH_MAC, plain, plain_len);

    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(auth_key, sizeof(auth_key));
    return OL_AUTH_SEALED + plain_len;
}

int ol_hs_client_result(OlHsClient *hs, const uint8_t *data, int len, uint8_t *msg) {
    uint8_t shared[32];
    int msg_len = len - OL_RESULT_SEALED;
    if (msg_len <= 0 || msg_len > OL_HS_RESULT_MAX) return 0;
    if (data[0] != OL_HS_RESULT || data[1] != OL_HS_VERSION) return 0;
    if (crypto_aead_unlock(msg, data + OL_RESULT_MAC, hs->result_key, k_zero_nonce,
                           data, OL_RESULT_MAC, data + OL_RESULT_SEALED, msg_len) != 0)
        return 0;
    /* A refusal carries no session key. */
    if (!is_zero32(data + OL_RESULT_PUB)) {
        crypto_x25519(shared, hs->secret, data + OL_RESULT_PUB);
        if (is_zero32(shared)) return 0;
        derive_session(hs->root, shared, hs->c2s_key, hs->s2c_key);
        crypto_wipe(shared, sizeof(shared));
    }
    return msg_len;
}

/* --- server --- */

int ol_hs_server_init(OlHsServer *hs, const uint8_t *secret) {
    if (secret) memcpy(hs->secret, secret, 32);
    else if (!ol_random(hs->secret, 32)) return 0;
    if (!ol_random(hs->cookie_key, 32)) return 0;
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
    if (is_zero32(shared)) return 0;
    derive_handshake(shared, auth->client_pub, hs->pub, auth->root, auth_key, auth->result_key);
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

int ol_hs_proof_ok_key(const OlHsAuth *auth, const uint8_t key[32]) {
    uint8_t expected[32];
    int ok;
    make_proof_key(expected, auth->root, auth->cookie, key);
    ok = crypto_verify32(expected, auth->proof) == 0;
    crypto_wipe(expected, sizeof(expected));
    return ok;
}

int ol_hs_proof_ok_secret(const OlHsAuth *auth, const char *secret) {
    uint8_t key[32];
    int ok;
    secret_key(key, secret);
    ok = ol_hs_proof_ok_key(auth, key);
    crypto_wipe(key, sizeof(key));
    return ok;
}

int ol_hs_server_session(OlHsAuth *auth, uint8_t session_pub[32]) {
    uint8_t secret[32], shared[32];
    if (!ol_random(secret, sizeof(secret))) return 0;
    crypto_x25519_public_key(session_pub, secret);
    crypto_x25519(shared, secret, auth->client_pub);
    derive_session(auth->root, shared, auth->c2s_key, auth->s2c_key);
    crypto_wipe(secret, sizeof(secret));
    crypto_wipe(shared, sizeof(shared));
    return 1;
}

int ol_hs_server_result(const uint8_t result_key[32], const uint8_t *session_pub,
                        const void *msg, int msg_len, uint8_t *out) {
    if (msg_len <= 0 || msg_len > OL_HS_RESULT_MAX - OL_RESULT_SEALED) return 0;
    out[0] = OL_HS_RESULT;
    out[1] = OL_HS_VERSION;
    if (session_pub) memcpy(out + OL_RESULT_PUB, session_pub, 32);
    else             memset(out + OL_RESULT_PUB, 0, 32);
    memcpy(out + OL_RESULT_SEALED, msg, msg_len);
    crypto_aead_lock(out + OL_RESULT_SEALED, out + OL_RESULT_MAC, result_key, k_zero_nonce,
                     out, OL_RESULT_MAC, out + OL_RESULT_SEALED, msg_len);
    return OL_RESULT_SEALED + msg_len;
}
