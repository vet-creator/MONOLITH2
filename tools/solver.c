/* Reference solver (v2).
 *
 * Uses ONLY what is present in the shipped binary -- the encrypted program,
 * the remainder, and the discrete-log target -- exactly as an attacker who
 * has fully reversed the VM would:
 *
 *   1. decrypt the embedded program (key is seed-derived);
 *   2. hash it to recover the tamper constant;
 *   3. rebuild the derived key schedule (the whitebox/MBA obfuscation only
 *      changes HOW the shipped binary evaluates the pipeline, never WHAT it
 *      computes, so a privileged tool can just use the plain reference);
 *   4. solve the discrete-log gate via Pollard's rho to recover the 48-bit
 *      scalar half of the pipeline output;
 *   5. reassemble remainder+scalar into the full 32-byte pipeline output and
 *      invert the two-stage cipher to recover the flag.
 *
 * This exists to PROVE the challenge is solvable end-to-end and to give CI a
 * source of the correct flag. It does not read the clear-text program, the
 * secret flag, or the scalar -- every one of those is derived from what the
 * binary already carries. */
#include <stdio.h>
#include <string.h>
#include "spn.h"
#include "vm.h"
#include "dlp.h"
#include "rho.h"
#include "generated/mono_data.h"

int main(void) {
    /* (1) decrypt embedded program */
    uint8_t bc[MONO_ENC_BC_LEN];
    memcpy(bc, MONO_ENC_BC, MONO_ENC_BC_LEN);
    mono_bc_crypt(bc, MONO_ENC_BC_LEN);

    /* (2) tamper constant from the decrypted program */
    uint32_t tamper = mono_bc_tamper_plain(bc, MONO_ENC_BC_LEN);

    /* (3) rebuild schedule (plain reference -- provably equal to the
     * shipped whitebox/MBA evaluator, so this is all a solver ever needs) */
    mono_ctx ctx; mono_ctx_build(&ctx, tamper);

    /* (4) discrete-log gate: recover m with g^m == MONO_TARGET_R (mod p) */
    fprintf(stderr, "solver: running Pollard's rho on the discrete-log gate...\n");
    uint64_t m = 0;
    int rho_ok = mono_rho_dlp(MONO_DLP_P, MONO_DLP_Q, MONO_DLP_G, MONO_TARGET_R, &m);
    if (!rho_ok) {
        fprintf(stderr, "solver failed: Pollard's rho did not converge\n");
        return 2;
    }
    fprintf(stderr, "solver: recovered scalar m = %llu\n", (unsigned long long)m);

    /* (5) reassemble the 32-byte pipeline output and invert */
    uint8_t s[MONO_BLOCK];
    memcpy(s, MONO_TARGET_REMAINDER, MONO_REMAINDER_BYTES);
    for (int i = 0; i < MONO_SCALAR_BYTES; i++)
        s[MONO_REMAINDER_BYTES + i] = (uint8_t)(m >> (8 * (MONO_SCALAR_BYTES - 1 - i)));

    mono_inverse(&ctx, s);

    /* sanity: forward again must reproduce remainder + DLP target */
    uint8_t v[MONO_BLOCK];
    memcpy(v, s, MONO_BLOCK);
    mono_forward(&ctx, v);
    int rem_ok = (memcmp(v, MONO_TARGET_REMAINDER, MONO_REMAINDER_BYTES) == 0);
    uint64_t m_check = 0;
    for (int i = 0; i < MONO_SCALAR_BYTES; i++)
        m_check = (m_check << 8) | v[MONO_REMAINDER_BYTES + i];
    int scalar_ok = (modexp64(MONO_DLP_G, m_check, MONO_DLP_P) == MONO_TARGET_R);

    int printable = 1;
    for (int i = 0; i < MONO_BLOCK; i++)
        if (s[i] < 0x20 || s[i] > 0x7e) printable = 0;

    if (rem_ok && scalar_ok && printable) {
        printf("MONOLITH{");
        fwrite(s, 1, MONO_BLOCK, stdout);
        printf("}\n");
        return 0;
    }
    fprintf(stderr, "solver failed (rem_ok=%d scalar_ok=%d printable=%d)\n",
            rem_ok, scalar_ok, printable);
    return 1;
}
