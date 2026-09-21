/* Minimal, self-contained SHA-256 (FIPS 180-4). Used for all key/table
 * derivation and for the tamper-evidence hash. */
#ifndef MONO_SHA256_H
#define MONO_SHA256_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;      /* message length in bytes */
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t n, uint8_t out[32]);

#endif
