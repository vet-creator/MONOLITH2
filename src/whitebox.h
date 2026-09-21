/* Whitebox table-network evaluator for the SPN stage.
 *
 * Every internal wire (the value at one byte position, between one
 * table-lookup and the next) is masked: wire = c*true (GF(2^8) scalar mult)
 * XOR m. AddRoundKey+SubBytes for a round becomes ONE 256-entry lookup table
 * per byte position (decode-in -> xor key -> sbox -> encode-out): a debugger
 * single-stepping the evaluator never sees a raw SPN byte, a raw round-key
 * byte, or a raw S-box output -- only masked wires in, masked wires out.
 * Permute is free (it only relabels wires; encodings are chosen to match up
 * across the boundary). MixColumns (linear over GF(2^8)) + the following
 * AddRoundKey collapse into one randomized-looking 4x4 GF(2^8) matrix and a
 * constant per column, which still computes the exact same function.
 *
 * All encodings are derived from the same seed/tamper as everything else in
 * spn.c, so this needs no extra embedded data and inherits the same
 * tamper-evidence: patch the program, and these tables silently become wrong
 * too. The LAST round's output encoding is fixed to the identity, so the
 * network's final output is raw, ready for the next stage. */
#ifndef MONO_WHITEBOX_H
#define MONO_WHITEBOX_H
#include <stdint.h>
#include "spn.h"

typedef struct {
    uint8_t CT[MONO_R1 + 1][MONO_BLOCK][256];   /* combined ARK+SUB tables   */
    uint8_t MFIN[MONO_R1 + 1][8][4][4];          /* encoded MixColumns+ARK   */
    uint8_t KFIN[MONO_R1 + 1][8][4];
} mono_wb;

/* Derive every table from ctx (already built via mono_ctx_build). */
void mono_wb_build(const mono_ctx *ctx, mono_wb *wb);

/* In-place SPN evaluation via the table network. For every input this is
 * bit-identical to running add_key(SK0)+{sub_bytes,perm,mixcolumns,add_key}
 * x R1 from spn.c -- verified by exhaustive cross-testing, never by
 * assumption. */
void mono_wb_forward(const mono_ctx *ctx, const mono_wb *wb, uint8_t s[MONO_BLOCK]);

#endif
