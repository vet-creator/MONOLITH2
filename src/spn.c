#include "spn.h"
#include "gf.h"
#include "sha256.h"
#include <string.h>

/* Fixed 128-bit seed. (Ascii "0BSIDIAN.M0N0LTH" -- purely decorative bytes.) */
const uint8_t MONO_SEED[MONO_SEED_LEN] = {
    0x30,0x42,0x53,0x49,0x44,0x49,0x41,0x4e,
    0x2e,0x4d,0x30,0x4e,0x30,0x4c,0x54,0x48
};

static uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}
static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}

/* ---- derivation helpers -------------------------------------------------- */

/* h = SHA256( SEED || domain || tamper_le32 || ctr ) */
static void derive(uint8_t domain, uint32_t tamper, uint8_t ctr, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, MONO_SEED, MONO_SEED_LEN);
    sha256_update(&c, &domain, 1);
    uint8_t t[4]; st32(t, tamper);
    sha256_update(&c, t, 4);
    sha256_update(&c, &ctr, 1);
    sha256_final(&c, out);
}

static void build_permutation(mono_ctx *ctx) {
    /* Fisher-Yates over 0..31 driven by a SHA-256 keystream (domain 'P'). */
    for (int i = 0; i < MONO_BLOCK; i++) ctx->P[i] = (uint8_t)i;
    uint8_t stream[256]; int have = 0, ctr = 0, pos = 0;
    for (int i = MONO_BLOCK - 1; i > 0; i--) {
        uint32_t bound = (uint32_t)(i + 1);
        uint32_t limit = 256u - (256u % bound);   /* rejection threshold */
        uint32_t r;
        for (;;) {
            if (pos >= have) {
                derive('P', ctx->tamper, (uint8_t)ctr++, stream);
                have = 32; pos = 0;
            }
            r = stream[pos++];
            if (r < limit) break;
        }
        uint32_t j = r % bound;
        uint8_t tmp = ctx->P[i]; ctx->P[i] = ctx->P[j]; ctx->P[j] = tmp;
    }
    for (int i = 0; i < MONO_BLOCK; i++) ctx->Pinv[ctx->P[i]] = (uint8_t)i;
}

void mono_ctx_build(mono_ctx *ctx, uint32_t tamper) {
    gf_init();
    ctx->tamper = tamper;
    for (int r = 0; r <= MONO_R1; r++)
        derive('S', tamper, (uint8_t)r, ctx->SK[r]);       /* 32-byte keys */
    for (int r = 0; r < MONO_R2; r++) {
        uint8_t h[32];
        derive('F', tamper, (uint8_t)r, h);
        memcpy(ctx->FK[r], h, MONO_HALF);                  /* 16-byte keys */
    }
    build_permutation(ctx);
}

/* ---- SPN layer ----------------------------------------------------------- */

static void add_key(uint8_t s[32], const uint8_t k[32]) {
    for (int i = 0; i < 32; i++) s[i] ^= k[i];
}
static void sub_bytes(uint8_t s[32]) {
    for (int i = 0; i < 32; i++) s[i] = gf_sbox(s[i]);
}
static void inv_sub_bytes(uint8_t s[32]) {
    for (int i = 0; i < 32; i++) s[i] = gf_inv_sbox(s[i]);
}
static void apply_perm(uint8_t s[32], const uint8_t p[32]) {
    uint8_t t[32];
    for (int i = 0; i < 32; i++) t[i] = s[p[i]];
    memcpy(s, t, 32);
}

/* ---- Feistel layer (ARX round function) ---------------------------------- */

static void feistel_F(const uint8_t half[16], const uint8_t key[16], uint8_t out[16]) {
    uint32_t a=ld32(half), b=ld32(half+4), c=ld32(half+8), d=ld32(half+12);
    uint32_t k0=ld32(key), k1=ld32(key+4), k2=ld32(key+8), k3=ld32(key+12);
    a = rotl32(a + k0, 7);
    b = rotl32(b ^ a, 9);
    c = rotl32(c + b + k1, 13);
    d = rotl32(d ^ c ^ k2, 17);
    a = rotl32(a + d + k3, 3);
    b = rotl32(b ^ c, 11);
    c = c + a;
    d = d ^ b;
    st32(out, a); st32(out+4, b); st32(out+8, c); st32(out+12, d);
}

static void feistel_round(uint8_t s[32], const uint8_t key[16]) {
    uint8_t T[16], L[16], R[16];
    memcpy(L, s, 16); memcpy(R, s+16, 16);
    feistel_F(R, key, T);
    /* newL = R ; newR = L ^ T */
    memcpy(s, R, 16);
    for (int i = 0; i < 16; i++) s[16+i] = (uint8_t)(L[i] ^ T[i]);
}

static void feistel_round_inv(uint8_t s[32], const uint8_t key[16]) {
    uint8_t T[16], L[16], R[16];
    memcpy(L, s, 16); memcpy(R, s+16, 16);   /* L=Rprev, R=Lprev^F(Rprev) */
    feistel_F(L, key, T);
    /* Rprev = L ; Lprev = R ^ T */
    for (int i = 0; i < 16; i++) s[i] = (uint8_t)(R[i] ^ T[i]);
    memcpy(s+16, L, 16);
}

/* ---- per-operation primitives (used by the VM and the reference) --------- */

void mono_op_addkey(const mono_ctx *ctx, uint8_t s[32], int idx) { add_key(s, ctx->SK[idx]); }
void mono_op_sub(uint8_t s[32])                                  { sub_bytes(s); }
void mono_op_perm(const mono_ctx *ctx, uint8_t s[32])            { apply_perm(s, ctx->P); }
void mono_op_mix(uint8_t s[32])                                  { gf_mixcolumns(s); }
void mono_op_feistel(const mono_ctx *ctx, uint8_t s[32], int idx){ feistel_round(s, ctx->FK[idx]); }

/* ---- full pipeline ------------------------------------------------------- */

void mono_forward(const mono_ctx *ctx, uint8_t s[MONO_BLOCK]) {
    add_key(s, ctx->SK[0]);
    for (int r = 1; r <= MONO_R1; r++) {
        sub_bytes(s);
        apply_perm(s, ctx->P);
        gf_mixcolumns(s);
        add_key(s, ctx->SK[r]);
    }
    for (int r = 0; r < MONO_R2; r++)
        feistel_round(s, ctx->FK[r]);
}

void mono_inverse(const mono_ctx *ctx, uint8_t s[MONO_BLOCK]) {
    for (int r = MONO_R2 - 1; r >= 0; r--)
        feistel_round_inv(s, ctx->FK[r]);
    for (int r = MONO_R1; r >= 1; r--) {
        add_key(s, ctx->SK[r]);
        gf_inv_mixcolumns(s);
        apply_perm(s, ctx->Pinv);
        inv_sub_bytes(s);
    }
    add_key(s, ctx->SK[0]);
}
