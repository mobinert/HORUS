// ---------------------------------------------------------------------------
//  clip.hpp  -  grab an indicator straight off the Windows clipboard
//
//  Analysts live with a hash or an IP already on the clipboard. `horus --clip`
//  just reads it and runs, no copy-paste-into-quotes dance.
// ---------------------------------------------------------------------------
#pragma once

#include <string>

#if defined(_WIN32)
#  include <windows.h>
#endif

namespace horus {
namespace clip {

inline std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

inline std::string read() {
#if defined(_WIN32)
    if (!OpenClipboard(nullptr)) return {};
    std::string out;
    if (HANDLE h = GetClipboardData(CF_TEXT)) {
        if (const char* p = (const char*)GlobalLock(h)) {
            out = p;
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    // an indicator is one token - take the first line, trimmed
    std::string t = trim(out);
    size_t nl = t.find_first_of("\r\n");
    if (nl != std::string::npos) t = trim(t.substr(0, nl));
    return t;
#else
    return {};
#endif
}

} // namespace clip
} // namespace horus
