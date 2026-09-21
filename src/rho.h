/* Pollard's rho for the discrete-log problem in the order-q subgroup mod p.
 * This is a DESIGNER/SOLVER tool (proves + performs the hard inversion step);
 * it is never linked into the shipped monolith.exe. */
#ifndef MONO_RHO_H
#define MONO_RHO_H
#include <stdint.h>

/* Find x in [0, q) with g^x == y (mod p), given g has prime order q | (p-1).
 * Returns 1 and sets *x_out on success, 0 on (rare) failure -- caller should
 * retry (a fresh random walk start) on failure. */
int mono_rho_dlp(uint64_t p, uint64_t q, uint64_t g, uint64_t y, uint64_t *x_out);

#endif
