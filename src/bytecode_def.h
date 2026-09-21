/* The PLAIN verification program for the MONOLITH VM (v2).
 *
 * This file is linked into the build tools (generator, solver, self-tests)
 * but deliberately NOT into the shipped challenge binary, so the clear-text
 * program never appears in monolith.exe -- only its encrypted form (emitted
 * into generated/mono_data.h) does.
 *
 * v2 pipeline, per opcode:
 *   OP_WSB r  : combined AddRoundKey+SubBytes table lookup, round r (whitebox)
 *   OP_PMT    : byte permutation (free under the wire encoding)
 *   OP_WMX r  : combined MixColumns+AddRoundKey via a per-column GF(2^8)
 *               matrix baked from that round's wire encodings (whitebox)
 *   OP_FEI r  : one MBA-obfuscated Feistel/ARX round, key index r
 *   OP_ENDX   : split state into a remainder (direct compare) and a scalar
 *               (checked via g^m mod p against an embedded target) -- the
 *               backward direction of the scalar check is a discrete-log
 *               problem, never brute-forceable at this size.
 */
#ifndef MONO_BYTECODE_DEF_H
#define MONO_BYTECODE_DEF_H
#include <stddef.h>
#include <stdint.h>

enum {
    OP_NOP  = 0x00,
    OP_WSB  = 0xA7,   /* + 1 immediate: round index 1..R1 */
    OP_PMT  = 0x3D,
    OP_WMX  = 0x6C,   /* + 1 immediate: round index 1..R1 */
    OP_FEI  = 0xF1,   /* + 1 immediate: round index 0..R2-1 */
    OP_ENDX = 0xE9
};

#define MONO_BC_MAX 512

/* Bytes of the 32-byte pipeline output used as the DLP scalar (the rest is
 * the directly-compared remainder). 6 bytes = 48 bits, kept strictly below
 * the DLP group order (see dlp.h) so the byte<->scalar mapping is a
 * bijection: no candidate information is lost by routing it through the
 * discrete-log check instead of a direct compare. */
#define MONO_SCALAR_BYTES 6
#define MONO_REMAINDER_BYTES (32 - MONO_SCALAR_BYTES)

/* Emit the clear-text program into out[] (>= MONO_BC_MAX). Returns length. */
size_t mono_bc_emit(uint8_t *out);
/* Program length. */
size_t mono_bc_len(void);

#endif
