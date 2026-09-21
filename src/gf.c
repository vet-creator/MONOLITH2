#include "gf.h"

static uint8_t Exp[512];
static uint8_t Log[256];
static uint8_t Sbox[256];
static uint8_t InvSbox[256];
static int     g_ready = 0;

static uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
}
static uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

void gf_init(void) {
    if (g_ready) return;
    /* generator g = 3 spans the multiplicative group */
    uint8_t x = 1;
    for (int i = 0; i < 255; i++) {
        Exp[i] = x;
        Log[x] = (uint8_t)i;
        x = (uint8_t)(xtime(x) ^ x);   /* multiply by 3 */
    }
    for (int i = 255; i < 512; i++) Exp[i] = Exp[i - 255];
    Log[0] = 0; /* unused sentinel */

    for (int i = 0; i < 256; i++) {
        uint8_t inv = (i == 0) ? 0 : Exp[(255 - Log[i]) % 255];
        uint8_t s = (uint8_t)(inv ^ rotl8(inv,1) ^ rotl8(inv,2) ^
                              rotl8(inv,3) ^ rotl8(inv,4) ^ 0x63);
        Sbox[i] = s;
    }
    for (int i = 0; i < 256; i++) InvSbox[Sbox[i]] = (uint8_t)i;
    g_ready = 1;
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return Exp[Log[a] + Log[b]];
}
uint8_t gf_sbox(uint8_t x)     { return Sbox[x]; }
uint8_t gf_inv_sbox(uint8_t x) { return InvSbox[x]; }

void gf_mixcolumns(uint8_t s[32]) {
    for (int c = 0; c < 8; c++) {
        uint8_t *p = s + 4*c;
        uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
        p[0] = (uint8_t)(gf_mul(a0,2)^gf_mul(a1,3)^a2^a3);
        p[1] = (uint8_t)(a0^gf_mul(a1,2)^gf_mul(a2,3)^a3);
        p[2] = (uint8_t)(a0^a1^gf_mul(a2,2)^gf_mul(a3,3));
        p[3] = (uint8_t)(gf_mul(a0,3)^a1^a2^gf_mul(a3,2));
    }
}

void gf_inv_mixcolumns(uint8_t s[32]) {
    for (int c = 0; c < 8; c++) {
        uint8_t *p = s + 4*c;
        uint8_t a0=p[0],a1=p[1],a2=p[2],a3=p[3];
        p[0] = (uint8_t)(gf_mul(a0,14)^gf_mul(a1,11)^gf_mul(a2,13)^gf_mul(a3,9));
        p[1] = (uint8_t)(gf_mul(a0,9)^gf_mul(a1,14)^gf_mul(a2,11)^gf_mul(a3,13));
        p[2] = (uint8_t)(gf_mul(a0,13)^gf_mul(a1,9)^gf_mul(a2,14)^gf_mul(a3,11));
        p[3] = (uint8_t)(gf_mul(a0,11)^gf_mul(a1,13)^gf_mul(a2,9)^gf_mul(a3,14));
    }
}
