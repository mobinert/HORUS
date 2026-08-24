#pragma once

#include <string>

namespace horus {
namespace encoding {

inline std::string base64(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= input.size()) {
        unsigned v = (static_cast<unsigned char>(input[i]) << 16) |
                     (static_cast<unsigned char>(input[i + 1]) << 8) |
                      static_cast<unsigned char>(input[i + 2]);
        out += table[(v >> 18) & 63];
        out += table[(v >> 12) & 63];
        out += table[(v >> 6) & 63];
        out += table[v & 63];
        i += 3;
    }

    if (i < input.size()) {
        unsigned v = static_cast<unsigned char>(input[i]) << 16;
        out += table[(v >> 18) & 63];
        if (i + 1 < input.size()) {
            v |= static_cast<unsigned char>(input[i + 1]) << 8;
            out += table[(v >> 12) & 63];
            out += table[(v >> 6) & 63];
            out += '=';
        } else {
            out += table[(v >> 12) & 63];
            out += "==";
        }
    }
    return out;
}

} // namespace encoding
} // namespace horus
