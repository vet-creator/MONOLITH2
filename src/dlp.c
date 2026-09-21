#include "dlp.h"

/* Safe prime p=2q+1 (q, p both prime), g generates the order-q subgroup.
 * See dlp.h for what these are and how they were validated. */
const uint64_t MONO_DLP_P = 2251799813687339ULL;
const uint64_t MONO_DLP_Q = 1125899906843669ULL;
const uint64_t MONO_DLP_G = 1105198791862972ULL;

#if defined(__SIZEOF_INT128__)
/* Fast path: gcc/clang expose a native 128-bit type. This only speeds up
 * SOLVER-side work (Pollard's rho does tens of millions of mulmod64 calls);
 * the shipped challenge only ever does forward modexp (~48 mulmod64 calls
 * per check), which is negligibly fast either way. MSVC lacks __int128, so
 * it always takes the fully portable path below -- same results, just slower
 * on the (unused-at-runtime) solver-side rho search. */
void u128_mul64(uint64_t a, uint64_t b, uint64_t *hi_out, uint64_t *lo_out) {
    unsigned __int128 p = (unsigned __int128)a * (unsigned __int128)b;
    *hi_out = (uint64_t)(p >> 64);
    *lo_out = (uint64_t)p;
}
uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)(((unsigned __int128)a * (unsigned __int128)b) % m);
}
#else
void u128_mul64(uint64_t a, uint64_t b, uint64_t *hi_out, uint64_t *lo_out) {
    uint64_t a1 = a >> 32, a0 = (uint32_t)a;
    uint64_t b1 = b >> 32, b0 = (uint32_t)b;

    uint64_t t0 = a0 * b0;
    uint64_t t1 = a1 * b0;
    uint64_t t2 = a0 * b1;
    uint64_t t3 = a1 * b1;

    uint64_t mid = t1 + t2;
    uint64_t mid_carry = (mid < t1) ? 1u : 0u;   /* carry out of t1+t2 */

    uint64_t lo = t0 + (mid << 32);
    uint64_t lo_carry = (lo < t0) ? 1u : 0u;      /* carry out of the low add */

    uint64_t hi = t3 + (mid >> 32) + (mid_carry << 32) + lo_carry;

    *hi_out = hi;
    *lo_out = lo;
}

/* Reduce a 128-bit value (hi,lo) mod m, m in [1, 2^63), via binary long
 * division (double-and-add from the top bit down). O(128) uint64 ops,
 * no overflow anywhere since the running remainder never exceeds m-1. */
static uint64_t reduce128(uint64_t hi, uint64_t lo, uint64_t m) {
    uint64_t r = 0;
    for (int i = 63; i >= 0; i--) {
        uint64_t bit = (hi >> i) & 1u;
        r <<= 1;
        if (r >= m) r -= m;
        if (bit) { r += 1; if (r >= m) r -= m; }
    }
    for (int i = 63; i >= 0; i--) {
        uint64_t bit = (lo >> i) & 1u;
        r <<= 1;
        if (r >= m) r -= m;
        if (bit) { r += 1; if (r >= m) r -= m; }
    }
    return r;
}

uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t m) {
    a %= m; b %= m;
    uint64_t hi, lo;
    u128_mul64(a, b, &hi, &lo);
    return reduce128(hi, lo, m);
}
#endif /* __SIZEOF_INT128__ */

uint64_t modexp64(uint64_t base, uint64_t exp, uint64_t m) {
    uint64_t result = 1 % m;
    base %= m;
    while (exp) {
        if (exp & 1u) result = mulmod64(result, base, m);
        base = mulmod64(base, base, m);
        exp >>= 1;
    }
    return result;
}

uint64_t modinv64(uint64_t a, uint64_t m) {
    return modexp64(a, m - 2, m); /* Fermat, m prime */
}
