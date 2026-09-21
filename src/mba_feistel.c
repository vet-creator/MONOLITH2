#include "mba_feistel.h"
#include <string.h>

/* a ^ b == (a | b) - (a & b)   [standard identity] */
static uint32_t mba_xor32(uint32_t a, uint32_t b) {
    return (a | b) - (a & b);
}
/* a + b == (a | b) + (a & b)   [standard identity] */
static uint32_t mba_add32(uint32_t a, uint32_t b) {
    return (a | b) + (a & b);
}
static uint32_t mba_rotl32(uint32_t x, int r) {
    /* rotation isn't hidden by MBA (there's no useful equivalent that isn't
     * itself a rotation); the obfuscation target here is xor/add, which is
     * where the round function's data-dependent mixing lives. */
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

static void mba_feistel_F(const uint8_t half[16], const uint8_t key[16], uint8_t out[16]) {
    uint32_t a=ld32(half), b=ld32(half+4), c=ld32(half+8), d=ld32(half+12);
    uint32_t k0=ld32(key), k1=ld32(key+4), k2=ld32(key+8), k3=ld32(key+12);

    a = mba_rotl32(mba_add32(a, k0), 7);
    b = mba_rotl32(mba_xor32(b, a), 9);
    c = mba_rotl32(mba_add32(mba_add32(c, b), k1), 13);
    d = mba_rotl32(mba_xor32(mba_xor32(d, c), k2), 17);
    a = mba_rotl32(mba_add32(mba_add32(a, d), k3), 3);
    b = mba_rotl32(mba_xor32(b, c), 11);
    c = mba_add32(c, a);
    d = mba_xor32(d, b);

    st32(out, a); st32(out+4, b); st32(out+8, c); st32(out+12, d);
}

void mono_mba_feistel_round(uint8_t s[MONO_BLOCK], const uint8_t key[MONO_HALF]) {
    uint8_t T[16], L[16], R[16];
    memcpy(L, s, 16); memcpy(R, s+16, 16);
    mba_feistel_F(R, key, T);
    memcpy(s, R, 16);
    for (int i = 0; i < 16; i++) s[16+i] = mba_xor32(L[i], T[i]) & 0xff;
}
