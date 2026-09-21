#include "whitebox.h"
#include "gf.h"
#include "sha256.h"
#include <string.h>

/* ---- local helpers (independent of spn.c's private ones) ----------------- */

static uint8_t st32b(uint32_t v, int i) { return (uint8_t)(v >> (8*i)); }

/* h[0..31] = SHA256( SEED || domain || tamper_le32 || round_ctr ), matching
 * spn.c's construction bit-for-bit but with domains spn.c never uses, so the
 * two derivation streams can never collide. */
static void wderive(uint8_t domain, uint32_t tamper, uint8_t ctr, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c);
    sha256_update(&c, MONO_SEED, MONO_SEED_LEN);
    sha256_update(&c, &domain, 1);
    uint8_t t[4] = { st32b(tamper,0), st32b(tamper,1), st32b(tamper,2), st32b(tamper,3) };
    sha256_update(&c, t, 4);
    sha256_update(&c, &ctr, 1);
    sha256_final(&c, out);
}

/* Multiplicative inverse in GF(2^8) via x^254 (x^255=1 for x!=0), using only
 * the public gf_mul -- gf.c/gf.h stay untouched. */
static uint8_t gfx_inv(uint8_t x) {
    uint8_t result = 1, base = x;
    int e = 254;
    while (e) {
        if (e & 1) result = gf_mul(result, base);
        base = gf_mul(base, base);
        e >>= 1;
    }
    return result;
}

typedef struct { uint8_t c, m; } enc_t;

/* AES-style MixColumns matrix (matches gf_mixcolumns exactly). */
static const uint8_t MIXM[4][4] = {
    {2,3,1,1}, {1,2,3,1}, {1,1,2,3}, {3,1,1,2}
};

/* ---- build ----------------------------------------------------------------
 *
 * MID_ENC[r][i]      : encoding of the wire right after round r's SubBytes
 *                       (before Permute), for r = 1..R1.
 * ROUND_OUT_ENC[r][i]: encoding of the wire right after round r's
 *                       MixColumns+AddRoundKey (post-permute position i),
 *                       for r = 1..R1. ROUND_OUT_ENC[R1][*] is forced to the
 *                       identity so the network's final output is raw.
 */
void mono_wb_build(const mono_ctx *ctx, mono_wb *wb) {
    enc_t mid[MONO_R1 + 1][MONO_BLOCK];
    enc_t out[MONO_R1 + 1][MONO_BLOCK];

    for (int r = 1; r <= MONO_R1; r++) {
        uint8_t cbuf[32], mbuf[32];
        wderive('U', ctx->tamper, (uint8_t)r, cbuf);   /* MID scalars */
        wderive('V', ctx->tamper, (uint8_t)r, mbuf);   /* MID masks   */
        for (int i = 0; i < MONO_BLOCK; i++) {
            mid[r][i].c = cbuf[i] ? cbuf[i] : 1;
            mid[r][i].m = mbuf[i];
        }
        if (r < MONO_R1) {
            uint8_t cbuf2[32], mbuf2[32];
            wderive('X', ctx->tamper, (uint8_t)r, cbuf2);  /* OUT scalars */
            wderive('Y', ctx->tamper, (uint8_t)r, mbuf2);  /* OUT masks   */
            for (int i = 0; i < MONO_BLOCK; i++) {
                out[r][i].c = cbuf2[i] ? cbuf2[i] : 1;
                out[r][i].m = mbuf2[i];
            }
        } else {
            for (int i = 0; i < MONO_BLOCK; i++) { out[r][i].c = 1; out[r][i].m = 0; } /* identity */
        }
    }

    /* combined ARK+SUB tables */
    for (int r = 1; r <= MONO_R1; r++) {
        for (int i = 0; i < MONO_BLOCK; i++) {
            uint8_t dinv = 0, m_prev = 0;
            if (r > 1) { dinv = gfx_inv(out[r-1][i].c); m_prev = out[r-1][i].m; }
            for (int x = 0; x < 256; x++) {
                uint8_t true_in;
                if (r == 1) {
                    true_in = (uint8_t)(x ^ ctx->SK[0][i]);       /* fold initial whitening */
                } else {
                    true_in = gf_mul(dinv, (uint8_t)(x ^ m_prev));
                }
                uint8_t sboxed = gf_sbox(true_in);
                wb->CT[r][i][x] = (uint8_t)(gf_mul(mid[r][i].c, sboxed) ^ mid[r][i].m);
            }
        }
    }

    /* encoded MixColumns + AddRoundKey, per round per column */
    for (int r = 1; r <= MONO_R1; r++) {
        for (int col = 0; col < 8; col++) {
            int p0 = 4*col, p1 = p0+1, p2 = p0+2, p3 = p0+3;
            int posn[4] = { p0, p1, p2, p3 };
            enc_t in_enc[4], out_enc[4];
            for (int k = 0; k < 4; k++) {
                in_enc[k]  = mid[r][ ctx->P[posn[k]] ];   /* MIX_IN_ENC[p] = MID_ENC[P[p]] */
                out_enc[k] = out[r][ posn[k] ];
            }
            uint8_t d[4], e[4];
            for (int j = 0; j < 4; j++) {
                d[j] = gfx_inv(in_enc[j].c);
                e[j] = gf_mul(d[j], in_enc[j].m);
            }
            for (int a = 0; a < 4; a++) {
                uint8_t k0 = ctx->SK[r][posn[a]];
                for (int j = 0; j < 4; j++) k0 = (uint8_t)(k0 ^ gf_mul(MIXM[a][j], e[j]));
                for (int j = 0; j < 4; j++) {
                    uint8_t mprime = gf_mul(MIXM[a][j], d[j]);
                    wb->MFIN[r][col][a][j] = gf_mul(out_enc[a].c, mprime);
                }
                wb->KFIN[r][col][a] = (uint8_t)(gf_mul(out_enc[a].c, k0) ^ out_enc[a].m);
            }
        }
    }
}

void mono_wb_forward(const mono_ctx *ctx, const mono_wb *wb, uint8_t s[MONO_BLOCK]) {
    for (int r = 1; r <= MONO_R1; r++) {
        for (int i = 0; i < MONO_BLOCK; i++) s[i] = wb->CT[r][i][ s[i] ];
        mono_op_perm(ctx, s);
        for (int col = 0; col < 8; col++) {
            uint8_t *p = s + 4*col;
            uint8_t in0=p[0], in1=p[1], in2=p[2], in3=p[3];
            for (int a = 0; a < 4; a++) {
                uint8_t acc = wb->KFIN[r][col][a];
                acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][0], in0));
                acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][1], in1));
                acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][2], in2));
                acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][3], in3));
                p[a] = acc;
            }
        }
    }
}
