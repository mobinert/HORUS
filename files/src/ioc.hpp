// ---------------------------------------------------------------------------
//  ioc.hpp  -  indicator-of-compromise type detection
//
//  Analysts paste in whatever they have - a hash off a ticket, an IP from a
//  firewall log, a URL out of an email header - and expect the tool to "just
//  know" what it's looking at and route it to the right intel source. This
//  module is that router. It is deliberately string-only and side-effect free;
//  deciding whether something is a *file on disk* happens up in main(), because
//  that needs to actually touch the filesystem.
//
//  Order of the checks matters. A URL contains a host, a host can look like a
//  bare domain, so we peel from the most specific shape (scheme://) down to the
//  least (a plain label.tld), and only then fall back to "unknown".
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <cctype>
#include <algorithm>

namespace argus {

enum class IocType {
    Unknown,
    MD5,
    SHA1,
    SHA256,
    IPv4,
    IPv6,
    Url,
    Domain,
    Email,
    FilePath        // resolved by the caller, never by classify()
};

inline const char* ioc_type_name(IocType t) {
    switch (t) {
        case IocType::MD5:      return "MD5 hash";
        case IocType::SHA1:     return "SHA-1 hash";
        case IocType::SHA256:   return "SHA-256 hash";
        case IocType::IPv4:     return "IPv4 address";
        case IocType::IPv6:     return "IPv6 address";
        case IocType::Url:      return "URL";
        case IocType::Domain:   return "domain";
        case IocType::Email:    return "email address";
        case IocType::FilePath: return "file";
        default:                return "unknown indicator";
    }
}

namespace detail {

    inline std::string trim(const std::string& in) {
        size_t b = 0, e = in.size();
        while (b < e && std::isspace((unsigned char)in[b])) ++b;
        while (e > b && std::isspace((unsigned char)in[e - 1])) --e;
        return in.substr(b, e - b);
    }

    inline bool all_hex(const std::string& s) {
        if (s.empty()) return false;
        for (char c : s)
            if (!std::isxdigit((unsigned char)c)) return false;
        return true;
    }

    // Strict dotted-quad: exactly four decimal octets, each 0-255, no leading
    // zeros that would hint at something octal-ish, no stray characters.
    inline bool is_ipv4(const std::string& s) {
        int octets = 0;
        size_t i = 0;
        while (i < s.size()) {
            size_t start = i;
            int val = 0, digits = 0;
            while (i < s.size() && std::isdigit((unsigned char)s[i])) {
                val = val * 10 + (s[i] - '0');
                ++digits;
                if (val > 255) return false;
                ++i;
            }
            if (digits == 0 || digits > 3) return false;
            if (digits > 1 && s[start] == '0') return false; // 01, 007, ...
            ++octets;
            if (i == s.size()) break;
            if (s[i] != '.') return false;
            ++i;
            if (i == s.size()) return false;               // trailing dot
        }
        return octets == 4;
    }

    // A pragmatic IPv6 recogniser. Validates the hex groups and the single
    // permitted "::" compression run. Not a full RFC 4291 parser, but it won't
    // mistake a domain or a hash for an address, which is all we need here.
    inline bool is_ipv6(const std::string& s) {
        if (s.find(':') == std::string::npos) return false;
        int groups = 0;
        bool seen_double_colon = false;
        size_t i = 0;
        // leading "::"
        if (s.size() >= 2 && s[0] == ':' && s[1] == ':') { seen_double_colon = true; i = 2; }
        else if (!s.empty() && s[0] == ':') return false;  // single leading colon is illegal

        while (i < s.size()) {
            // a hextet of 1-4 hex digits
            size_t start = i;
            while (i < s.size() && std::isxdigit((unsigned char)s[i])) ++i;
            size_t len = i - start;
            if (len > 4) return false;
            if (len > 0) ++groups;

            if (i == s.size()) break;
            if (s[i] == ':') {
                ++i;
                if (i < s.size() && s[i] == ':') {
                    if (seen_double_colon) return false;   // only one "::" allowed
                    seen_double_colon = true;
                    ++i;
                }
            } else {
                return false;                              // stray non-hex, non-colon char
            }
        }
        // 8 groups uncompressed, fewer only if "::" filled the gap
        if (seen_double_colon) return groups <= 7;
        return groups == 8;
    }

    // Hostname rules: dot-separated labels, each 1-63 chars of [a-z0-9-], not
    // starting or ending with a hyphen, and a final label that is alphabetic
    // (the TLD) so we don't accept bare numbers as domains.
    inline bool is_domain(const std::string& s) {
        if (s.empty() || s.size() > 253) return false;
        if (s.front() == '.' || s.back() == '.') return false;
        if (s.find('.') == std::string::npos) return false;

        size_t start = 0;
        std::string last_label;
        for (size_t i = 0; i <= s.size(); ++i) {
            if (i == s.size() || s[i] == '.') {
                std::string label = s.substr(start, i - start);
                if (label.empty() || label.size() > 63) return false;
                if (label.front() == '-' || label.back() == '-') return false;
                for (char c : label)
                    if (!(std::isalnum((unsigned char)c) || c == '-')) return false;
                last_label = label;
                start = i + 1;
            }
        }
        // TLD must be all letters and at least two chars (com, org, io...)
        if (last_label.size() < 2) return false;
        for (char c : last_label)
            if (!std::isalpha((unsigned char)c)) return false;
        return true;
    }

} // namespace detail

// The one entry point. Returns the best guess at what kind of indicator the
// (already-trimmed-internally) input represents.
inline IocType classify(const std::string& raw) {
    std::string s = detail::trim(raw);
    if (s.empty()) return IocType::Unknown;

    // 1. URL - the only thing carrying an explicit scheme
    {
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        if (lower.rfind("http://", 0) == 0  ||
            lower.rfind("https://", 0) == 0 ||
            lower.rfind("ftp://", 0) == 0)
            return IocType::Url;
    }

    // 2. Email - exactly one '@' with a domain-shaped right-hand side
    {
        auto at = s.find('@');
        if (at != std::string::npos && s.find('@', at + 1) == std::string::npos) {
            std::string local = s.substr(0, at);
            std::string host  = s.substr(at + 1);
            if (!local.empty() && detail::is_domain(host))
                return IocType::Email;
        }
    }

    // 3. IP literals
    if (detail::is_ipv4(s)) return IocType::IPv4;
    if (detail::is_ipv6(s)) return IocType::IPv6;

    // 4. Hashes - pure hex of a known width. Check before domain so a 32-char
    //    hex blob is never mistaken for a weird hostname.
    if (detail::all_hex(s)) {
        switch (s.size()) {
            case 32: return IocType::MD5;
            case 40: return IocType::SHA1;
            case 64: return IocType::SHA256;
            default: break; // odd-length hex - fall through, probably not an IOC
        }
    }

    // 5. Domain - the catch-all for label.tld shapes
    if (detail::is_domain(s)) return IocType::Domain;

    return IocType::Unknown;
}

} // namespace argus
