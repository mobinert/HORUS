// ---------------------------------------------------------------------------
//  console.hpp  -  the bit that makes the output look like a tool and not a
//                  debug dump. ANSI colour, a banner, boxes, coloured verdict
//                  badges. Colour can be switched off (--no-color or a pipe).
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <iostream>
#include <vector>

#if defined(_WIN32)
#  include <windows.h>
#  include <io.h>
#endif

namespace horus {
namespace ui {

// Flipped off by main() when output isn't a terminal or the user asks.
inline bool& color_enabled() { static bool on = true; return on; }

// On Windows 10+ the console understands ANSI escapes, but only once you opt in
// per handle. Do that here; if it fails we just fall back to plain text.
inline void init() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &mode)) {
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
    SetConsoleOutputCP(CP_UTF8);
    if (!_isatty(_fileno(stdout))) color_enabled() = false;
#endif
}

namespace ansi {
    inline std::string wrap(const char* code, const std::string& s) {
        if (!color_enabled()) return s;
        return std::string("\033[") + code + "m" + s + "\033[0m";
    }
    inline std::string dim    (const std::string& s) { return wrap("2",  s); }
    inline std::string bold   (const std::string& s) { return wrap("1",  s); }
    inline std::string red    (const std::string& s) { return wrap("31;1", s); }
    inline std::string green  (const std::string& s) { return wrap("32;1", s); }
    inline std::string yellow (const std::string& s) { return wrap("33;1", s); }
    inline std::string blue   (const std::string& s) { return wrap("34;1", s); }
    inline std::string cyan   (const std::string& s) { return wrap("36;1", s); }
    inline std::string grey   (const std::string& s) { return wrap("90", s); }
}

inline void banner() {
    const char* art =
        "  _   _  ___  ____  _   _ ____\n"
        " | | | |/ _ \\|  _ \\| | | / ___|\n"
        " | |_| | | | | |_) | | | \\___ \\\n"
        " |  _  | |_| |  _ <| |_| |___) |\n"
        " |_| |_|\\___/|_| \\_\\\\___/|____/\n";
    std::cout << ansi::cyan(art);
    std::cout << ansi::grey("  \xF0\x9F\x94\xB1 the all-seeing eye  v2  -  PE analysis + UEBA behavioral profiling\n\n");
}

inline std::string rule(char c = '-', int width = 64) {
    return ansi::grey(std::string(width, c));
}

inline void section(const std::string& title) {
    std::cout << "\n" << ansi::bold(title) << "\n" << rule() << "\n";
}

// A left-aligned label followed by a value, columns lined up.
inline void kv(const std::string& key, const std::string& value, int keywidth = 16) {
    std::string padded = key;
    if ((int)padded.size() < keywidth) padded.append(keywidth - padded.size(), ' ');
    std::cout << "  " << ansi::grey(padded) << value << "\n";
}

// Colour a 0-100 risk number by band.
inline std::string colour_score(int score) {
    std::string s = std::to_string(score) + "/100";
    if (score >= 60) return ansi::red(s);
    if (score >= 30) return ansi::yellow(s);
    if (score >= 10) return ansi::cyan(s);
    return ansi::green(s);
}

// A chunky verdict badge, coloured to match.
inline std::string verdict_badge(const std::string& text, int score) {
    std::string padded = "  " + text + "  ";
    if (!color_enabled()) return "[ " + text + " ]";
    const char* code = score >= 60 ? "41;97;1"        // white on red
                     : score >= 30 ? "43;30;1"        // black on yellow
                     : score >= 10 ? "46;30;1"        // black on cyan
                     :               "42;30;1";       // black on green
    return std::string("\033[") + code + "m" + padded + "\033[0m";
}

} // namespace ui
} // namespace horus
