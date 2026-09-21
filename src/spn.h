/* MONOLITH cipher core.
 *
 * A 256-bit block is pushed through two structurally different, individually
 * invertible transforms:
 *
 *   1. SPN   : R1 rounds of  AddRoundKey -> SubBytes -> Permute -> MixColumns
 *   2. Feistel (ARX round function) : R2 rounds
 *
 * There is no secret key -- the whole "key schedule" is DERIVED at runtime
 * from a fixed 128-bit seed together with a tamper-evidence constant that is
 * the hash of the (decrypted) bytecode. The challenge is therefore a fixed
 * bijection; exactly one 32-byte input maps to the embedded target. Recovering
 * it means reversing the whole chain -- nothing needs to be brute forced.
 */
#ifndef MONO_SPN_H
#define MONO_SPN_H
#include <stdint.h>

#define MONO_BLOCK 32          /* bytes (256-bit block)              */
#define MONO_HALF  16          /* Feistel half                      */
#define MONO_R1    12          /* SPN rounds                        */
#define MONO_R2    12          /* Feistel rounds                    */
#define MONO_SEED_LEN 16

/* The fixed 128-bit derivation seed. Changing it changes every derived
 * table/key and therefore the whole challenge. */
extern const uint8_t MONO_SEED[MONO_SEED_LEN];

typedef struct {
    uint8_t  P[MONO_BLOCK];        /* forward byte permutation          */
    uint8_t  Pinv[MONO_BLOCK];     /* inverse permutation               */
    uint8_t  SK[MONO_R1 + 1][MONO_BLOCK];  /* SPN round keys            */
    uint8_t  FK[MONO_R2][MONO_HALF];       /* Feistel round keys        */
    uint32_t tamper;               /* bytecode-derived constant         */
} mono_ctx;

/* Build all derived material for a given tamper constant. Idempotent w.r.t.
 * gf_init(). */
void mono_ctx_build(mono_ctx *ctx, uint32_t tamper);

/* In-place full pipeline over a 32-byte block. */
void mono_forward(const mono_ctx *ctx, uint8_t s[MONO_BLOCK]);
void mono_inverse(const mono_ctx *ctx, uint8_t s[MONO_BLOCK]);

/* Per-operation primitives -- the bytecode VM drives the pipeline through
 * exactly these, guaranteeing the interpreter and the reference agree. */
void mono_op_addkey  (const mono_ctx *ctx, uint8_t s[MONO_BLOCK], int idx);
void mono_op_sub     (uint8_t s[MONO_BLOCK]);
void mono_op_perm    (const mono_ctx *ctx, uint8_t s[MONO_BLOCK]);
void mono_op_mix     (uint8_t s[MONO_BLOCK]);
void mono_op_feistel (const mono_ctx *ctx, uint8_t s[MONO_BLOCK], int idx);

#endif
