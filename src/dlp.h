/* Portable modular arithmetic mod a prime < 2^62, using only uint64_t.
 * No __int128 (MSVC has no such type) and no compiler-specific intrinsics --
 * plain, standard C11, so it builds identically with gcc, clang and MSVC. */
#ifndef MONO_DLP_H
#define MONO_DLP_H
#include <stdint.h>

/* The number-theoretic gate's public parameters: p = 2q+1 is a safe prime,
 * q is prime, g generates the order-q subgroup mod p. Fixed, non-secret, and
 * the SAME single source of truth for the shipped VM (forward: modexp only),
 * the generator (computes the embedded target), and the reference solver
 * (Pollard's rho -- needs q too, to close the loop after a collision).
 * Chosen and cross-validated against an independent arbitrary-precision
 * (Python) implementation, and proven solvable by an actual from-scratch
 * Pollard's-rho run, before shipping -- see README. */
extern const uint64_t MONO_DLP_P;
extern const uint64_t MONO_DLP_Q;
extern const uint64_t MONO_DLP_G;

/* Full 64x64 -> 128-bit unsigned product, as two uint64_t halves. */
void     u128_mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo);

/* (a*b) mod m, for any 64-bit a,b and m in [2, 2^62). Exact, no overflow. */
uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t m);

/* (base^exp) mod m via square-and-multiply. */
uint64_t modexp64(uint64_t base, uint64_t exp, uint64_t m);

/* Modular inverse of a mod m (m prime), via Fermat: a^(m-2) mod m. */
uint64_t modinv64(uint64_t a, uint64_t m);

#endif
