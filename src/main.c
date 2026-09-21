/* MONOLITH -- reverse-engineering challenge (the binary itself is the target).
 *
 * Reads a single line of the form  MONOLITH{................................}
 * (32 characters inside the braces) and reports whether it is the one input
 * that the embedded transform maps to the embedded target.
 *
 * The binary is deliberately benign: it only reads stdin and writes stdout
 * (plus, on Windows, sets the console to UTF-8 + ANSI). No network, no files,
 * no process/registry access -- nothing offensive. */
#include <stdio.h>
#include <string.h>
#include "spn.h"
#include "vm.h"
#include "generated/mono_data.h"

#if defined(_WIN32)
#  include <windows.h>
static void console_setup(void) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
}
#else
static void console_setup(void) {}
#endif

#define C_RST  "\033[0m"
#define C_DIM  "\033[2m"
#define C_CYAN "\033[36m"
#define C_GRN  "\033[1;32m"
#define C_RED  "\033[1;31m"
#define C_YEL  "\033[33m"
#define C_MAG  "\033[35m"

static void banner(void) {
    printf(C_CYAN
"        ███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗ ██╗     ██╗████████╗██╗  ██╗\n"
"        ████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██║     ██║╚══██╔══╝██║  ██║\n"
"        ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║     ██║   ██║   ███████║\n"
"        ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██║   ██╔══██║\n"
"        ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ██║   ██║  ██║\n"
"        ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝\n"
    C_RST);
    printf(C_DIM "        黒 曜 の 碑  ―  T H E   M O N O L I T H\n" C_RST);
    printf(C_DIM "        a single input opens it. find it.  /  唯一の鍵を探せ。\n\n" C_RST);
}

static int read_line(char *buf, size_t cap) {
    if (!fgets(buf, (int)cap, stdin)) return 0;
    size_t n = strlen(buf);
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    return 1;
}

/* Extract the 32-byte inner if the line is MONOLITH{<32 chars>}. */
static int parse_flag(const char *line, uint8_t inner[MONO_BLOCK]) {
    const char *pfx = "MONOLITH{";
    size_t pl = strlen(pfx);
    size_t ll = strlen(line);
    if (ll != pl + MONO_BLOCK + 1) return 0;
    if (strncmp(line, pfx, pl) != 0) return 0;
    if (line[ll - 1] != '}') return 0;
    memcpy(inner, line + pl, MONO_BLOCK);
    return 1;
}

int main(void) {
    console_setup();
    banner();

    printf(C_CYAN "  seal> " C_RST);
    fflush(stdout);

    char line[256];
    if (!read_line(line, sizeof line)) {
        printf(C_DIM "\n  (no input)\n" C_RST);
        return 1;
    }

    uint8_t inner[MONO_BLOCK];
    if (!parse_flag(line, inner)) {
        printf(C_RED  "\n  ✗ malformed sigil.\n" C_RST);
        printf(C_DIM  "    expected  MONOLITH{ ... }  with 32 glyphs inside.\n" C_RST);
        printf(C_MAG  "    黒曜は沈黙している。\n" C_RST);
        return 1;
    }

    mono_target target;
    memcpy(target.remainder, MONO_TARGET_REMAINDER, MONO_REMAINDER_BYTES);
    target.scalar_target = MONO_TARGET_R;
    int ok = mono_vm_check(MONO_ENC_BC, MONO_ENC_BC_LEN, inner, &target);

    if (ok) {
        printf(C_GRN "\n  ✓ THE MONOLITH OPENS.\n" C_RST);
        printf(C_GRN "    %s\n" C_RST, line);
        printf(C_DIM "    碑は開かれた。よくぞここまで辿り着いた。\n" C_RST);
        return 0;
    } else {
        printf(C_RED "\n  ✗ rejected. the surface is unmarked.\n" C_RST);
        printf(C_DIM "    the depths do not yield to guessing.\n" C_RST);
        printf(C_MAG "    刻印は拒まれた。\n" C_RST);
        return 1;
    }
}
