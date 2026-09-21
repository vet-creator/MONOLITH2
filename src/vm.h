/* The MONOLITH bytecode VM (v2): decrypts the embedded program, derives the
 * whole key schedule + whitebox wire-encodings from a tamper-evidence hash of
 * that decrypted program, and interprets it (control-flow flattened) over
 * the 32-byte candidate. The final opcode splits the result into a directly
 * compared remainder and a discrete-log-gated scalar (see dlp.h). */
#ifndef MONO_VM_H
#define MONO_VM_H
#include <stddef.h>
#include <stdint.h>
#include "bytecode_def.h"   /* opcode enum + MONO_BC_MAX / MONO_*_BYTES */

/* Stream cipher used to hide the program in the binary. Key is seed-derived,
 * so this is obfuscation, not secrecy; encrypt and decrypt are the same op. */
void     mono_bc_crypt(uint8_t *data, size_t len);

/* Tamper constant = first 32 bits (LE) of SHA-256(clear-text program). */
uint32_t mono_bc_tamper_plain(const uint8_t *plain, size_t len);

/* What OP_ENDX checks the transformed state against. */
typedef struct {
    uint8_t  remainder[MONO_REMAINDER_BYTES];  /* direct byte compare        */
    uint64_t scalar_target;                    /* g^m mod p, m = scalar part */
} mono_target;

/* Run the program on `in`; return 1 iff it satisfies `target`. */
int      mono_vm_check(const uint8_t *enc, size_t len,
                       const uint8_t in[32], const mono_target *target);

/* Run the program on `state` in place up to (not including) OP_ENDX, leaving
 * the raw 32-byte pipeline output -- used only by the self-tests to compare
 * against the plain reference. */
void     mono_vm_transform(const uint8_t *enc, size_t len, uint8_t state[32]);

#endif
