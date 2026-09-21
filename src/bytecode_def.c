#include "bytecode_def.h"
#include "spn.h"

/* Program (v2):
 *   (WSB r, PMT, WMX r)   for r = 1 .. R1
 *   (FEI r)               for r = 0 .. R2-1
 *   ENDX
 */
size_t mono_bc_emit(uint8_t *o) {
    size_t n = 0;
    for (int r = 1; r <= MONO_R1; r++) {
        o[n++] = OP_WSB; o[n++] = (uint8_t)r;
        o[n++] = OP_PMT;
        o[n++] = OP_WMX; o[n++] = (uint8_t)r;
    }
    for (int r = 0; r < MONO_R2; r++) {
        o[n++] = OP_FEI; o[n++] = (uint8_t)r;
    }
    o[n++] = OP_ENDX;
    return n;
}

size_t mono_bc_len(void) {
    uint8_t tmp[MONO_BC_MAX];
    return mono_bc_emit(tmp);
}
