#include "rho.h"
#include "dlp.h"
#include <stdlib.h>
#include <time.h>

/* splitmix64 -- small, solid, self-contained PRNG (solver tool only). */
static uint64_t sm_state;
static void     rng_seed(uint64_t s) { sm_state = s ? s : 0x9E3779B97F4A7C15ULL; }
static uint64_t rng_next(void) {
    uint64_t z = (sm_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t modsub(uint64_t a, uint64_t b, uint64_t m) {
    return (a >= b) ? (a - b) : (a + m - b);
}

typedef struct { uint64_t a, b, v; } rho_state;

static rho_state rho_step(rho_state s, uint64_t p, uint64_t q, uint64_t g, uint64_t y) {
    switch (s.v % 3) {
        case 0: {
            /* a*=2, b*=2 (mod q): cheap shift + single conditional subtract --
             * NOT a full mulmod64, which would cost ~100x more for no reason. */
            s.a <<= 1; if (s.a >= q) s.a -= q;
            s.b <<= 1; if (s.b >= q) s.b -= q;
            s.v = mulmod64(s.v, s.v, p);
            break;
        }
        case 1:
            s.a += 1; if (s.a >= q) s.a -= q;
            s.v = mulmod64(s.v, g, p);
            break;
        default:
            s.b += 1; if (s.b >= q) s.b -= q;
            s.v = mulmod64(s.v, y, p);
            break;
    }
    return s;
}

int mono_rho_dlp(uint64_t p, uint64_t q, uint64_t g, uint64_t y, uint64_t *x_out) {
    rng_seed((uint64_t)time(NULL) ^ 0xD1CE1234ULL);

    const long long budget_restarts = 64;
    for (long long restart = 0; restart < budget_restarts; restart++) {
        uint64_t a0 = rng_next() % q, b0 = rng_next() % q;
        uint64_t v0 = mulmod64(modexp64(g, a0, p), modexp64(y, b0, p), p);
        rho_state tortoise = { a0, b0, v0 };
        rho_state hare = tortoise;

        /* Expected collision by the birthday bound is ~1.25*sqrt(q); budget
         * generously above that so a single attempt almost always succeeds. */
        const long long max_iter = 400000000LL;
        for (long long i = 1; i <= max_iter; i++) {
            tortoise = rho_step(tortoise, p, q, g, y);
            hare = rho_step(rho_step(hare, p, q, g, y), p, q, g, y);
            if (tortoise.v == hare.v) {
                uint64_t db = modsub(hare.b, tortoise.b, q);
                if (db == 0) break;             /* degenerate collision, retry */
                uint64_t inv = modinv64(db, q);
                uint64_t da = modsub(tortoise.a, hare.a, q);
                uint64_t x = mulmod64(da, inv, q);
                if (modexp64(g, x, p) == y) { *x_out = x; return 1; }
                break;                            /* spurious, retry */
            }
        }
    }
    return 0;
}
