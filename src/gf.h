/* GF(2^8) arithmetic with the AES reduction polynomial 0x11B.
 * Tables are built at runtime (nothing static to grep in the binary). */
#ifndef MONO_GF_H
#define MONO_GF_H
#include <stdint.h>

void     gf_init(void);              /* build log/antilog + S-boxes; idempotent */
uint8_t  gf_mul(uint8_t a, uint8_t b);
uint8_t  gf_sbox(uint8_t x);
uint8_t  gf_inv_sbox(uint8_t x);
void     gf_mixcolumns(uint8_t s[32]);      /* 8 columns of 4 bytes */
void     gf_inv_mixcolumns(uint8_t s[32]);

#endif
