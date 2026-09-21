/* Mixed-Boolean-Arithmetic (MBA) rewrite of the Feistel round function.
 *
 * Every XOR and every ADD in the ARX round is replaced by a provably
 * equivalent OR/AND-based formula:
 *
 *   a ^ b == (a | b) - (a & b)
 *   a + b == (a | b) + (a & b)
 *
 * (standard, well-known bitwise identities -- verified exhaustively in the
 * test suite, not assumed). A disassembly of this function shows a thicket
 * of OR/AND/ADD/SUB instructions with no XOR or plain ADD anywhere; recovering
 * the original ARX shape requires either recognizing/simplifying the MBA
 * pattern (tools like this exist -- e.g. SiMBA, MBA-Blast -- but applying one
 * is itself real reverse-engineering work) or re-deriving the function's
 * truth table by other means. This is a *drop-in replacement* for spn.c's
 * static feistel_round: same key schedule, bit-identical output for every
 * input, verified by direct cross-testing against it. */
#ifndef MONO_MBA_FEISTEL_H
#define MONO_MBA_FEISTEL_H
#include <stdint.h>
#include "spn.h"

/* One MBA-obfuscated forward Feistel round, in place, matching spn.c's
 * feistel_round(s, key) exactly. */
void mono_mba_feistel_round(uint8_t s[MONO_BLOCK], const uint8_t key[MONO_HALF]);

#endif
