#include "vm.h"
#include "spn.h"
#include "gf.h"
#include "whitebox.h"
#include "mba_feistel.h"
#include "dlp.h"
#include "sha256.h"
#include <string.h>

/* ---- program (de/en)cryption -------------------------------------------- */

static void bc_keystream(uint8_t *ks, size_t len) {
    size_t off = 0; uint8_t ctr = 0;
    while (off < len) {
        uint8_t blk[32];
        sha256_ctx c; sha256_init(&c);
        sha256_update(&c, MONO_SEED, MONO_SEED_LEN);
        uint8_t dom = 'B';
        sha256_update(&c, &dom, 1);
        sha256_update(&c, &ctr, 1);
        sha256_final(&c, blk);
        size_t take = len - off; if (take > 32) take = 32;
        memcpy(ks + off, blk, take);
        off += take; ctr++;
    }
}

void mono_bc_crypt(uint8_t *data, size_t len) {
    uint8_t ks[MONO_BC_MAX];
    if (len > MONO_BC_MAX) return;
    bc_keystream(ks, len);
    for (size_t i = 0; i < len; i++) data[i] ^= ks[i];
}

uint32_t mono_bc_tamper_plain(const uint8_t *plain, size_t len) {
    uint8_t h[32];
    sha256(plain, len, h);
    return (uint32_t)h[0] | ((uint32_t)h[1] << 8) |
           ((uint32_t)h[2] << 16) | ((uint32_t)h[3] << 24);
}

/* ---- obfuscation helpers ------------------------------------------------- */

static int opaque_true(uint32_t n) { return (int)(((n * (n + 1u)) & 1u) == 0u); }

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t x = (uint32_t)((a[i] | b[i]) - (a[i] & b[i])); /* == a^b */
        acc |= x;
    }
    return (int)((acc | (~acc + 1u)) >> 31 ^ 1u) & 1; /* 1 iff acc==0 */
}

static uint64_t load_scalar48(const uint8_t b[MONO_SCALAR_BYTES]) {
    uint64_t v = 0;
    for (int i = 0; i < MONO_SCALAR_BYTES; i++) v = (v << 8) | b[i];
    return v;
}

/* opcode -> dispatcher state */
static int decode(uint8_t op) {
    switch (op) {
        case OP_WSB:  return 2;
        case OP_PMT:  return 3;
        case OP_WMX:  return 4;
        case OP_FEI:  return 5;
        case OP_ENDX: return 6;
        default:      return 0;   /* NOP / unknown -> keep fetching */
    }
}

/* Apply round `r`'s encoded MixColumns+AddRoundKey (one round only -- the VM
 * drives rounds one opcode at a time, unlike mono_wb_forward's internal
 * per-round loop over the whole pipeline). */
static void wmx_round(const mono_wb *wb, int r, uint8_t s[32]) {
    for (int col = 0; col < 8; col++) {
        uint8_t *p = s + 4*col;
        uint8_t in0=p[0], in1=p[1], in2=p[2], in3=p[3];
        for (int a = 0; a < 4; a++) {
            uint8_t acc = wb->KFIN[r][col][a];
            acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][0], in0));
            acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][1], in1));
            acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][2], in2));
            acc = (uint8_t)(acc ^ gf_mul(wb->MFIN[r][col][a][3], in3));
            p[a] = acc;
        }
    }
}

/* ---- the interpreter (control-flow flattened) --------------------------- */

/* If `target` is non-NULL, returns 1/0 for match. If NULL, stops right before
 * OP_ENDX and leaves the raw 32-byte pipeline output in s[] (self-test use). */
static int run(const uint8_t *enc, size_t len, uint8_t s[32],
               const mono_target *target) {
    uint8_t bc[MONO_BC_MAX];
    if (len == 0 || len > MONO_BC_MAX) return 0;
    memcpy(bc, enc, len);
    mono_bc_crypt(bc, len);                       /* decrypt in place        */

    uint32_t tamper = mono_bc_tamper_plain(bc, len);
    mono_ctx ctx; mono_ctx_build(&ctx, tamper);    /* keys bound to program   */
    mono_wb  wb;  mono_wb_build(&ctx, &wb);        /* wire-encoded tables, same binding */

    size_t pc = 0;
    uint8_t imm = 0;
    int state = 1;                                 /* 1 = FETCH               */
    int result = 0;
    uint32_t guard = 0;

    while (state) {
        switch (state) {
            case 1: {                              /* FETCH + DECODE          */
                if (pc >= len) { state = 0; break; }
                uint8_t op = bc[pc++];
                if (opaque_true(guard)) guard += op; /* opaque no-op sink     */
                state = decode(op);
                break;
            }
            case 2:                                /* WSB imm                 */
                imm = bc[pc++];
                for (int i = 0; i < 32; i++) s[i] = wb.CT[imm][i][s[i]];
                state = 1; break;
            case 3:                                /* PMT                     */
                mono_op_perm(&ctx, s);
                state = 1; break;
            case 4:                                /* WMX imm                 */
                imm = bc[pc++];
                wmx_round(&wb, imm, s);
                state = 1; break;
            case 5:                                /* FEI imm                 */
                imm = bc[pc++];
                mono_mba_feistel_round(s, ctx.FK[imm]);
                state = 1; break;
            case 6: {                               /* ENDX                    */
                if (target) {
                    int rem_ok = ct_equal(s, target->remainder, MONO_REMAINDER_BYTES);
                    uint64_t m = load_scalar48(s + MONO_REMAINDER_BYTES);
                    uint64_t R = modexp64(MONO_DLP_G, m, MONO_DLP_P);
                    int dlp_ok = (R == target->scalar_target);
                    result = rem_ok && dlp_ok;
                }
                state = 0; break;
            }
            default:
                state = 0; break;
        }
    }
    (void)guard;
    return result;
}

int mono_vm_check(const uint8_t *enc, size_t len,
                  const uint8_t in[32], const mono_target *target) {
    uint8_t s[32];
    memcpy(s, in, 32);
    return run(enc, len, s, target);
}

void mono_vm_transform(const uint8_t *enc, size_t len, uint8_t state[32]) {
    (void)run(enc, len, state, NULL);
}
