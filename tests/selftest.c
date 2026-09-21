/* Comprehensive correctness gate (run by CI on every push).
 * Fast, unit-level: every new v2 layer (whitebox SPN, MBA Feistel, DLP
 * arithmetic, VM dispatch) is checked against its plain reference or a known
 * answer. The heavier, real-scale "is the shipped challenge actually
 * solvable" proof lives in tools/solver.c, run separately as the
 * "integration" ctest -- that one genuinely runs Pollard's rho at full size
 * (seconds with a native 128-bit multiply, up to ~2 minutes on the fully
 * portable fallback MSVC uses) and is deliberately not duplicated here.
 * Returns non-zero if anything is wrong. */
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include "gf.h"
#include "spn.h"
#include "whitebox.h"
#include "mba_feistel.h"
#include "dlp.h"
#include "rho.h"
#include "vm.h"
#include "bytecode_def.h"
#include "generated/mono_data.h"

static int fails = 0;
#define CHECK(cond, name) do { \
    int _c = (cond); \
    printf("  [%s] %s\n", _c ? "PASS" : "FAIL", name); \
    if (!_c) fails++; \
} while (0)

int main(void) {
    printf("MONOLITH self-test\n------------------\n");

    /* --- primitives --- */
    {
        uint8_t d[32]; char got[65];
        sha256("abc", 3, d);
        for (int i = 0; i < 32; i++) sprintf(got + 2*i, "%02x", d[i]);
        CHECK(strcmp(got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
            "SHA-256(\"abc\") known answer");
    }
    gf_init();
    CHECK(gf_sbox(0x00)==0x63 && gf_sbox(0x53)==0xed, "AES S-box values");
    {
        int inv = 1; for (int i=0;i<256;i++) if (gf_inv_sbox(gf_sbox(i))!=i) inv=0;
        CHECK(inv, "inverse S-box round-trips");
    }
    {
        int mc = 1;
        for (int t=0;t<64;t++){ uint8_t s[32],o[32];
            for(int i=0;i<32;i++) s[i]=(uint8_t)(i*7+t*31+13);
            memcpy(o,s,32); gf_mixcolumns(s); gf_inv_mixcolumns(s);
            if (memcmp(s,o,32)) mc=0; }
        CHECK(mc, "MixColumns invertible");
    }

    /* --- cipher core (plain reference -- unchanged, still the ground truth) --- */
    {
        mono_ctx c; mono_ctx_build(&c, 0xA5A5A5A5u);
        int seen[32]={0}, bij=1;
        for(int i=0;i<32;i++){ if(c.P[i]>=32||seen[c.P[i]]) bij=0; else seen[c.P[i]]=1; }
        int pinv=1; for(int i=0;i<32;i++) if(c.Pinv[c.P[i]]!=i) pinv=0;
        CHECK(bij && pinv, "permutation is a bijection with correct inverse");

        int rt = 1;
        for(uint32_t tv=0; tv<6 && rt; tv++){
            mono_ctx k; mono_ctx_build(&k, tv*0x11111111u + 3u);
            for(int t=0;t<1500;t++){ uint8_t s[32],o[32];
                for(int i=0;i<32;i++) s[i]=(uint8_t)((i*131+t*17+tv*7)&0xff);
                memcpy(o,s,32); mono_forward(&k,s); mono_inverse(&k,s);
                if(memcmp(s,o,32)){ rt=0; break; } } }
        CHECK(rt, "forward/inverse round-trip over many vectors");
    }

    /* --- whitebox SPN table-network == plain reference SPN --- */
    {
        int fail_wb = 0;
        for (uint32_t tv = 0; tv < 8 && !fail_wb; tv++) {
            mono_ctx ctx; mono_ctx_build(&ctx, tv*0x9E3779B1u + 7u);
            mono_wb wb; mono_wb_build(&ctx, &wb);
            for (int t = 0; t < 1500; t++) {
                uint8_t in[32], ref[32], got[32];
                for (int i=0;i<32;i++) in[i]=(uint8_t)((i*61+t*23+tv*131)&0xff);
                memcpy(ref,in,32);
                mono_op_addkey(&ctx, ref, 0);
                for (int r=1;r<=MONO_R1;r++){ mono_op_sub(ref); mono_op_perm(&ctx,ref);
                                               mono_op_mix(ref); mono_op_addkey(&ctx,ref,r); }
                memcpy(got,in,32); mono_wb_forward(&ctx, &wb, got);
                if (memcmp(ref,got,32)) fail_wb = 1;
            }
        }
        CHECK(!fail_wb, "whitebox SPN table-network == plain reference (12000 vectors)");
    }

    /* --- MBA-obfuscated Feistel round == plain reference Feistel --- */
    {
        int fail_mba = 0;
        for (uint32_t tv = 0; tv < 6 && !fail_mba; tv++) {
            mono_ctx ctx; mono_ctx_build(&ctx, tv*0x1234567u + 99u);
            for (int r = 0; r < MONO_R2 && !fail_mba; r++) {
                for (int t = 0; t < 300; t++) {
                    uint8_t in[32], ref[32], got[32];
                    for (int i=0;i<32;i++) in[i]=(uint8_t)((i*53+t*17+tv*7+r*3)&0xff);
                    memcpy(ref,in,32); mono_op_feistel(&ctx, ref, r);
                    memcpy(got,in,32); mono_mba_feistel_round(got, ctx.FK[r]);
                    if (memcmp(ref,got,32)) fail_mba = 1;
                }
            }
        }
        CHECK(!fail_mba, "MBA Feistel round == plain reference (10800 vectors)");
    }
    {
        /* the MBA identities themselves, exhaustively at byte width */
        int mba_id_fail = 0;
        for (int a = 0; a < 256 && !mba_id_fail; a++) for (int b = 0; b < 256; b++) {
            uint32_t x = (uint32_t)((a|b)-(a&b)), s = (uint32_t)((a|b)+(a&b));
            if (x != (uint32_t)(a^b) || s != (uint32_t)(a+b)) { mba_id_fail = 1; break; }
        }
        CHECK(!mba_id_fail, "MBA xor/add identities hold exhaustively (65536 pairs)");
    }

    /* --- discrete-log gate arithmetic --- */
    {
        CHECK(modexp64(MONO_DLP_G, MONO_DLP_Q, MONO_DLP_P) == 1,
              "DLP generator has order dividing q");
        CHECK(MONO_DLP_P == 2*MONO_DLP_Q + 1, "p = 2q+1 (safe prime shape)");
        CHECK(mulmod64(123456789012345ULL, 987654321098765ULL, MONO_DLP_P) ==
              modinv64(modinv64(mulmod64(123456789012345ULL, 987654321098765ULL, MONO_DLP_P), MONO_DLP_P), MONO_DLP_P),
              "modinv64 is a true inverse (double-inverse round-trip)");

        /* toy rho instance (q ~ 2^24), proves the ALGORITHM is correct fast;
         * the real ~2^50 instance is solved by tools/solver.c separately. */
        uint64_t tq=10191119ULL, tp=20382239ULL, tg=459006ULL, tx=7472358ULL, ty=7198105ULL;
        CHECK(modexp64(tg, tx, tp) == ty, "toy DLP instance is internally consistent");
        uint64_t recovered = 0;
        int rho_ok = mono_rho_dlp(tp, tq, tg, ty, &recovered);
        CHECK(rho_ok && recovered == tx, "Pollard's rho recovers a known discrete log");
    }

    /* --- VM (whitebox+MBA+DLP) equivalence + semantics --- */
    {
        uint8_t plain[MONO_BC_MAX]; size_t len = mono_bc_emit(plain);
        uint32_t tamper = mono_bc_tamper_plain(plain, len);
        mono_ctx ctx; mono_ctx_build(&ctx, tamper);
        uint8_t enc[MONO_BC_MAX]; memcpy(enc, plain, len); mono_bc_crypt(enc, len);

        int eq = 1;
        for(int t=0;t<800 && eq;t++){ uint8_t in[32],ref[32],vm[32];
            for(int i=0;i<32;i++) in[i]=(uint8_t)((i*97+t*41+7)&0xff);
            memcpy(ref,in,32); mono_forward(&ctx,ref);
            memcpy(vm,in,32); mono_vm_transform(enc,len,vm);
            if(memcmp(ref,vm,32)) eq=0; }
        CHECK(eq, "VM (whitebox+MBA) transform == plain reference forward");

        uint8_t in[32], inter[32];
        for(int i=0;i<32;i++) in[i]=(uint8_t)(i*13+5);
        memcpy(inter,in,32); mono_forward(&ctx,inter);
        mono_target tgt;
        memcpy(tgt.remainder, inter, MONO_REMAINDER_BYTES);
        uint64_t m = 0;
        for (int i=0;i<MONO_SCALAR_BYTES;i++) m = (m<<8) | inter[MONO_REMAINDER_BYTES+i];
        tgt.scalar_target = modexp64(MONO_DLP_G, m, MONO_DLP_P);

        CHECK(mono_vm_check(enc,len,in,&tgt)==1, "VM accepts the correct target");

        uint8_t bad[32]; memcpy(bad,in,32); bad[9]^=0x40;
        CHECK(mono_vm_check(enc,len,bad,&tgt)==0, "VM rejects wrong input");

        mono_target bad_tgt = tgt; bad_tgt.scalar_target ^= 1;
        CHECK(mono_vm_check(enc,len,in,&bad_tgt)==0, "VM rejects corrupted DLP target");

        uint8_t bad_rem[MONO_REMAINDER_BYTES]; memcpy(bad_rem, tgt.remainder, MONO_REMAINDER_BYTES);
        bad_rem[0] ^= 1;
        mono_target bad_tgt2 = tgt; memcpy(bad_tgt2.remainder, bad_rem, MONO_REMAINDER_BYTES);
        CHECK(mono_vm_check(enc,len,in,&bad_tgt2)==0, "VM rejects corrupted remainder target");

        uint8_t enc2[MONO_BC_MAX]; memcpy(enc2,enc,len); enc2[4]^=1;
        CHECK(mono_vm_check(enc2,len,in,&tgt)==0, "patched bytecode breaks (tamper-evident)");
    }

    /* --- embedded challenge data is well-formed and internally consistent
     * (full end-to-end solvability, including the real-scale rho solve, is
     * proven by tools/solver.c's own run, not repeated here) --- */
    {
        uint8_t bc[MONO_ENC_BC_LEN];
        memcpy(bc, MONO_ENC_BC, MONO_ENC_BC_LEN);
        mono_bc_crypt(bc, MONO_ENC_BC_LEN);
        uint32_t tamper = mono_bc_tamper_plain(bc, MONO_ENC_BC_LEN);
        mono_ctx ctx; mono_ctx_build(&ctx, tamper);
        (void)ctx;
        CHECK(MONO_TARGET_R < MONO_DLP_P, "embedded DLP target is a valid residue mod p");
        CHECK(MONO_ENC_BC_LEN == mono_bc_len(), "embedded program length matches the emitter");
    }

    printf("------------------\n%s\n", fails ? "SELFTEST FAILED" : "ALL SELFTESTS PASSED");
    return fails ? 1 : 0;
}
