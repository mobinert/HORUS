// ---------------------------------------------------------------------------
//  main.cpp  -  HORUS v2  command line
//
//  Two modes:
//
//    * file on disk  -> hash it; if it's a PE, tear it apart: headers,
//      sections + entropy, imports grouped by capability, imphash, UEBA
//      behavioral profile, and any URLs/IPs in its strings.
//      VirusTotal reputation is added when VT_API_KEY is set.
//
//    * anything else -> classify the indicator type and fan it out across
//      configured intel sources in parallel.
//
//  v2 additions:
//    - UEBA behavioral profiling (archetype matching + risk modifier)
//    - Software hint detection from embedded strings
//    - Authenticode directory presence check
//    - Fixed scoring: UPX no longer double-penalized, VirtualProtect backed
//      out of the score when it's explained by UPX unpacking
//    - ScreenCapture weight reduced; ScreenCapture+Net combo added
//
//  API keys: --vt-key / --abuse-key or VT_API_KEY / ABUSEIPDB_API_KEY env vars
// ---------------------------------------------------------------------------
#include "ioc.hpp"
#include "pe.hpp"
#include "signatures.hpp"
#include "ueba.hpp"
#include "crypto.hpp"
#include "intel.hpp"
#include "console.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <cstdlib>
#include <algorithm>
#include <set>

namespace {

struct Options {
    std::string target;
    std::string vt_key;
    std::string abuse_key;
    bool json     = false;
    bool strings  = false;
    bool no_color = false;
    bool help     = false;
    bool profile  = false;   // verbose UEBA explanation
};

std::string get_env(const char* name) {
#if defined(_WIN32)
    char* buf = nullptr; size_t sz = 0;
    if (_dupenv_s(&buf, &sz, name) == 0 && buf) {
        std::string v(buf); free(buf); return v;
    }
    return {};
#else
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
#endif
}

bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return true;
}

bool file_exists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

std::string entropy_bar(double h) {
    int filled = (int)((h / 8.0) * 18.0 + 0.5);
    if (filled < 0)  filled = 0;
    if (filled > 18) filled = 18;
    std::string bar = "[";
    bar.append(filled, '#');
    bar.append(18 - filled, '.');
    bar += "]";
    return bar;
}

std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { char b[8]; std::snprintf(b,sizeof(b),"\\u%04x",c); o += b; }
                else o += c;
        }
    }
    return o;
}

// ---- pull URLs / IPv4s / suspicious tokens from extracted strings ----------
struct EmbeddedIocs {
    std::set<std::string> urls;
    std::set<std::string> ips;
    std::set<std::string> interesting;
};

// XOR decode - same key as signatures.hpp / ueba.hpp.
// Keeps sensitive string literals out of .rdata so the tool doesn't
// trigger AV string-match heuristics on its own watch-list vocabulary.
static inline std::string mdx(std::initializer_list<uint8_t> enc) {
    std::string s; s.reserve(enc.size());
    for (auto b : enc) s += (char)(b ^ 0x5A);
    return s;
}

EmbeddedIocs scan_strings(const std::vector<std::string>& strs) {
    EmbeddedIocs found;
    static const std::vector<std::string> watch = {
        mdx({0x39,0x37,0x3E,0x74,0x3F,0x22,0x3F}),                                                    // cmd.exe
        mdx({0x2A,0x35,0x2D,0x3F,0x28,0x29,0x32,0x3F,0x36,0x36}),                                    // powershell
        mdx({0x28,0x2F,0x34,0x3E,0x36,0x36,0x69,0x68}),                                               // rundll32
        mdx({0x28,0x3F,0x3D,0x29,0x2C,0x28,0x69,0x68}),                                               // regsvr32
        mdx({0x29,0x39,0x32,0x2E,0x3B,0x29,0x31,0x29}),                                               // schtasks
        mdx({0x37,0x29,0x32,0x2E,0x3B}),                                                               // mshta
        mdx({0x06,0x19,0x2F,0x28,0x28,0x3F,0x34,0x2E,0x0C,0x3F,0x28,0x29,0x33,0x35,0x34,0x06,0x08,0x2F,0x34}), // \CurrentVersion\Run
        mdx({0x17,0x35,0x20,0x33,0x36,0x36,0x3B,0x75}),                                               // Mozilla/
        mdx({0x74,0x35,0x34,0x33,0x35,0x34}),                                                          // .onion
        mdx({0x38,0x33,0x2E,0x29,0x3B,0x3E,0x37,0x33,0x34}),                                          // bitsadmin
        mdx({0x39,0x3F,0x28,0x2E,0x2F,0x2E,0x33,0x36}),                                               // certutil
        mdx({0x2D,0x29,0x39,0x28,0x33,0x2A,0x2E}),                                                    // wscript
        mdx({0x39,0x29,0x39,0x28,0x33,0x2A,0x2E}),                                                    // cscript
        mdx({0x2C,0x29,0x29,0x3B,0x3E,0x37,0x33,0x34}),                                               // vssadmin
        mdx({0x38,0x39,0x3E,0x3F,0x3E,0x33,0x2E}),                                                    // bcdedit
        mdx({0x34,0x3F,0x2E,0x29,0x32}),                                                               // netsh
    };

    for (const auto& s : strs) {
        for (const char* scheme : {"http://", "https://"}) {
            size_t pos = 0;
            while ((pos = s.find(scheme, pos)) != std::string::npos) {
                size_t end = pos;
                while (end < s.size() && s[end] > 0x20 && s[end] != '"' &&
                       s[end] != '\'' && s[end] != '<' && s[end] != '>')
                    ++end;
                found.urls.insert(s.substr(pos, end - pos));
                pos = end;
            }
        }
        for (size_t i = 0; i < s.size(); ++i) {
            if (!std::isdigit((unsigned char)s[i])) continue;
            if (i > 0 && (std::isdigit((unsigned char)s[i-1]) || s[i-1] == '.')) continue;
            size_t j = i;
            while (j < s.size() && (std::isdigit((unsigned char)s[j]) || s[j] == '.')) ++j;
            std::string cand = s.substr(i, j - i);
            if (horus::classify(cand) == horus::IocType::IPv4) found.ips.insert(cand);
            i = j;
        }
        for (const auto& w : watch)
            if (s.find(w) != std::string::npos) { found.interesting.insert(w); break; }
    }
    return found;
}

// Detect likely product/company hints from strings --------------------------
struct SoftwareHints {
    std::vector<std::string> matched_keywords;
    bool looks_like_automation = false;
    bool looks_like_installer  = false;
    bool looks_like_security   = false;
};

SoftwareHints detect_hints(const std::vector<std::string>& strs) {
    SoftwareHints h;
    static const char* auto_kw[] = {
        "AutoHotkey", "AutoIt", "AHK", "macro", "hotkey", "SendKeys", nullptr
    };
    static const char* inst_kw[] = {
        "Setup", "Installer", "Uninstall", "NSIS", "Inno Setup",
        "Install Wizard", "Bootstrapper", "Redistributable", nullptr
    };
    // Security-related terms are encoded so they don't appear as plaintext in the binary
    static const std::vector<std::string> sec_kw = {
        mdx({0x2C,0x33,0x28,0x2F,0x29,0x2E,0x35,0x2E,0x3B,0x36}), // virustotal
        mdx({0x37,0x3B,0x36,0x2D,0x3B,0x28,0x3F}),                  // malware
        mdx({0x29,0x3B,0x34,0x3E,0x38,0x35,0x22}),                   // sandbox
        mdx({0x3B,0x34,0x2E,0x33,0x2C,0x33,0x28,0x2F,0x29}),        // antivirus
        mdx({0x3E,0x3F,0x2E,0x3F,0x39,0x2E,0x33,0x35,0x34}),        // detection
    };

    auto scan_arr = [&](const char** kws, bool& flag) {
        for (int i = 0; kws[i]; ++i) {
            std::string kw = kws[i];
            std::string kl = kw;
            std::transform(kl.begin(), kl.end(), kl.begin(),
                           [](unsigned char c){ return (char)std::tolower(c); });
            for (const auto& s : strs) {
                std::string sl = s;
                std::transform(sl.begin(), sl.end(), sl.begin(),
                               [](unsigned char c){ return (char)std::tolower(c); });
                if (sl.find(kl) != std::string::npos) {
                    flag = true;
                    bool already = false;
                    for (auto& m : h.matched_keywords) if (m == kw) { already = true; break; }
                    if (!already) h.matched_keywords.push_back(kw);
                    break;
                }
            }
        }
    };

    auto scan_vec = [&](const std::vector<std::string>& kws, bool& flag) {
        for (const auto& kw : kws) {
            for (const auto& s : strs) {
                std::string sl = s;
                std::transform(sl.begin(), sl.end(), sl.begin(),
                               [](unsigned char c){ return (char)std::tolower(c); });
                if (sl.find(kw) != std::string::npos) {
                    flag = true;
                    bool already = false;
                    for (auto& m : h.matched_keywords) if (m == kw) { already = true; break; }
                    if (!already) h.matched_keywords.push_back(kw);
                    break;
                }
            }
        }
    };

    scan_arr(auto_kw, h.looks_like_automation);
    scan_arr(inst_kw, h.looks_like_installer);
    scan_vec(sec_kw,  h.looks_like_security);
    return h;
}

std::vector<std::shared_ptr<horus::intel::IntelSource>> build_sources(const Options& o) {
    std::vector<std::shared_ptr<horus::intel::IntelSource>> v;
    if (!o.vt_key.empty())    v.push_back(std::make_shared<horus::intel::VirusTotal>(o.vt_key));
    if (!o.abuse_key.empty()) v.push_back(std::make_shared<horus::intel::AbuseIPDB>(o.abuse_key));
    return v;
}

void print_source_result(const horus::intel::SourceResult& r) {
    using namespace horus::ui;
    if (!r.ok) {
        std::cout << "  " << ansi::bold(r.source) << "  " << ansi::grey("- " + r.error) << "\n";
        return;
    }
    if (!r.found) {
        std::cout << "  " << ansi::bold(r.source) << "  " << ansi::green("clean / unknown") << "\n";
    } else {
        std::string sev;
        if (r.malicious >= 0)  sev = (r.malicious > 0 ? ansi::red(r.summary) : ansi::green(r.summary));
        else if (r.score >= 0) sev = (r.score >= 50 ? ansi::red(r.summary) :
                                      r.score >= 25 ? ansi::yellow(r.summary) : ansi::green(r.summary));
        else                   sev = r.summary;
        std::cout << "  " << ansi::bold(r.source) << "  " << sev << "\n";
        for (auto& kvp : r.details)
            std::cout << "      " << ansi::grey(kvp.first + ": ") << kvp.second << "\n";
    }
}

int vt_score_from(int malicious) {
    if (malicious <= 0) return 0;
    int s = 35 + malicious * 4;
    return s > 100 ? 100 : s;
}

const char* verdict_for_score(int s) {
    if (s >= 60) return "LIKELY MALICIOUS";
    if (s >= 30) return "SUSPICIOUS";
    if (s >= 10) return "LOW RISK";
    return "CLEAN";
}

// ===========================================================================
//  File analysis
// ===========================================================================
int analyze_file(const Options& opts) {
    using namespace horus;

    std::vector<uint8_t> bytes;
    if (!read_file(opts.target, bytes)) {
        std::cerr << "error: cannot read file: " << opts.target << "\n";
        return 2;
    }

    crypto::FileHashes hashes = crypto::hash_buffer(bytes);
    pe::Analyzer analyzer(bytes);
    pe::Info info = analyzer.analyze();

    std::string imphash;
    if (info.valid && !info.imphash_string.empty())
        imphash = crypto::md5_hex(info.imphash_string);

    // Extract strings early - needed for both UEBA and IOC pivot
    auto strs = analyzer.extract_strings(5);

    sig::ScoreResult risk;
    if (info.valid) risk = sig::score(info);

    // UEBA behavioral profile
    bool has_upx = info.valid && risk.has_upx;
    ueba::Profile behavior = ueba::profile(info, risk, strs, has_upx);

    // Software hint detection
    SoftwareHints hints = detect_hints(strs);

    // Optional VT check
    intel::SourceResult vt;
    auto sources = build_sources(opts);
    if (!opts.vt_key.empty() && !hashes.sha256.empty()) {
        intel::VirusTotal vtsrc(opts.vt_key);
        vt = vtsrc.lookup(hashes.sha256, IocType::SHA256);
    }

    int base_score   = info.valid ? risk.score : 0;
    // Apply UEBA modifier to static score, clamped 0-100
    int static_score = base_score + behavior.modifier;
    if (static_score < 0)   static_score = 0;
    if (static_score > 100) static_score = 100;

    int vt_score     = (vt.ok && vt.found) ? vt_score_from(vt.malicious) : 0;
    int final_score  = std::max(static_score, vt_score);

    if (opts.json) {
        std::cout << "{\n";
        std::cout << "  \"target\": \"" << json_escape(opts.target) << "\",\n";
        std::cout << "  \"size\": " << bytes.size() << ",\n";
        std::cout << "  \"md5\": \"" << hashes.md5 << "\",\n";
        std::cout << "  \"sha1\": \"" << hashes.sha1 << "\",\n";
        std::cout << "  \"sha256\": \"" << hashes.sha256 << "\",\n";
        std::cout << "  \"is_pe\": " << (info.valid ? "true" : "false") << ",\n";
        if (info.valid) {
            std::cout << "  \"bitness\": " << (info.is_64bit ? 64 : 32) << ",\n";
            std::cout << "  \"imphash\": \"" << imphash << "\",\n";
            std::cout << "  \"has_authenticode\": " << (info.has_authenticode ? "true" : "false") << ",\n";
            std::cout << "  \"has_upx\": " << (has_upx ? "true" : "false") << ",\n";
            std::cout << "  \"base_score\": " << base_score << ",\n";
            std::cout << "  \"ueba_archetype\": \"" << ueba::archetype_label(behavior.type) << "\",\n";
            std::cout << "  \"ueba_modifier\": " << behavior.modifier << ",\n";
            std::cout << "  \"static_score\": " << static_score << ",\n";
        }
        if (vt.ok && vt.found)
            std::cout << "  \"vt_detections\": " << vt.malicious << ",\n";
        std::cout << "  \"final_score\": " << final_score << ",\n";
        std::cout << "  \"verdict\": \"" << verdict_for_score(final_score) << "\"\n";
        std::cout << "}\n";
        return final_score >= 30 ? 1 : 0;
    }

    using namespace horus::ui;

    section("FILE");
    kv("path",    opts.target);
    kv("size",    std::to_string(bytes.size()) + " bytes");
    kv("MD5",     hashes.md5);
    kv("SHA-1",   hashes.sha1);
    kv("SHA-256", hashes.sha256);

    if (!info.valid) {
        std::cout << "\n  " << ansi::grey("Not a PE file (" + info.error + ") - hashing only.") << "\n";
    } else {
        section("PE HEADER");
        kv("type",      info.is_dll ? "DLL" : "executable");
        kv("bitness",   info.is_64bit ? "64-bit (PE32+)" : "32-bit (PE32)");
        kv("machine",   info.machine_name);
        kv("subsystem", info.subsystem_name);
        kv("compiled",  info.compile_time + (info.timestamp_suspicious ? ansi::yellow("  (suspicious)") : ""));
        kv("image base",[&]{ char b[32]; std::snprintf(b,sizeof(b),"0x%llx",(unsigned long long)info.image_base); return std::string(b); }());
        kv("entry RVA", [&]{ char b[32]; std::snprintf(b,sizeof(b),"0x%x",info.entry_point_rva); return std::string(b); }());
        kv("imphash",   imphash);
        kv("signed",    info.has_authenticode
                            ? ansi::green("yes (Authenticode directory present)")
                            : ansi::grey("no"));

        section("SECTIONS");
        for (const auto& s : info.sections) {
            std::string flags;
            flags += s.readable   ? "r" : "-";
            flags += s.writable   ? "w" : "-";
            flags += s.executable ? "x" : "-";
            char line[128];
            std::snprintf(line, sizeof(line), "  %-9s %s  H=%.2f %s %s",
                          s.name.c_str(), flags.c_str(), s.entropy,
                          entropy_bar(s.entropy).c_str(),
                          s.is_rwx() ? "RWX!" : "");
            std::string out = line;
            if (s.is_rwx() || s.entropy >= 7.2) std::cout << ansi::yellow(out) << "\n";
            else std::cout << out << "\n";
        }

        section("IMPORTS  (" + std::to_string(info.imports.size()) + " DLLs, " +
                std::to_string(info.total_imports) + " functions)");
        for (const auto& imp : info.imports) {
            std::cout << "  " << ansi::bold(imp.dll)
                      << ansi::grey("  (" + std::to_string(imp.functions.size()) + ")") << "\n";
        }

        section("CAPABILITIES");
        if (risk.capabilities.empty()) {
            std::cout << "  " << ansi::grey("none of the watched API groups were imported") << "\n";
        } else {
            for (const auto& h : risk.capabilities) {
                const auto& m = sig::meta(h.cap);
                std::string tag = h.significant
                    ? ansi::yellow(std::string("[") + m.label + "]")
                    : ansi::grey(std::string("[") + m.label + " - common]");
                std::cout << "  " << tag << " " << ansi::grey(m.blurb) << "\n";
                std::string apis = "      ";
                for (size_t i = 0; i < h.apis.size() && i < 6; ++i) apis += h.apis[i] + "  ";
                if (h.apis.size() > 6) apis += "...";
                std::cout << ansi::grey(apis) << "\n";
            }
        }
        if (!risk.findings.empty()) {
            std::cout << "\n";
            for (const auto& f : risk.findings)
                std::cout << "  " << ansi::red("!") << " " << f.text << "\n";
        }

        // ---- software hints ----
        if (!hints.matched_keywords.empty() || info.has_authenticode) {
            section("SOFTWARE HINTS");
            if (!hints.matched_keywords.empty()) {
                std::string row = "  " + ansi::cyan("keywords ");
                for (auto& k : hints.matched_keywords) row += k + "  ";
                std::cout << row << "\n";
            }
            if (hints.looks_like_automation)
                std::cout << "  " << ansi::cyan("type     ") << "automation / scripting tool\n";
            else if (hints.looks_like_installer)
                std::cout << "  " << ansi::cyan("type     ") << "software installer\n";
            else if (hints.looks_like_security)
                std::cout << "  " << ansi::cyan("type     ") << "security / analysis tool\n";
            std::cout << "  " << ansi::cyan("signed   ")
                      << (info.has_authenticode
                              ? ansi::green("yes (Authenticode directory present)")
                              : ansi::grey("no")) << "\n";
            if (has_upx)
                std::cout << "  " << ansi::cyan("packer   ")
                          << ansi::grey("UPX (legitimate open-source packer)") << "\n";
        }

        // ---- embedded IOC pivot ----
        EmbeddedIocs emb = scan_strings(strs);
        if (!emb.urls.empty() || !emb.ips.empty() || !emb.interesting.empty()) {
            section("EMBEDDED INDICATORS  (from strings)");
            for (auto& u : emb.urls) std::cout << "  " << ansi::cyan("url ") << u << "\n";
            for (auto& ip : emb.ips) std::cout << "  " << ansi::cyan("ip  ") << ip << "\n";
            if (!emb.interesting.empty()) {
                std::string row = "  " + ansi::cyan("tokens ");
                for (auto& t : emb.interesting) row += t + "  ";
                std::cout << row << "\n";
            }
            if (!opts.abuse_key.empty() && !emb.ips.empty()) {
                std::cout << "\n  " << ansi::grey("enriching embedded IPs...") << "\n";
                for (auto& ip : emb.ips) {
                    auto rs = intel::enrich(sources, ip, IocType::IPv4);
                    std::cout << "  " << ansi::bold(ip) << "\n";
                    for (auto& r : rs) print_source_result(r);
                }
            }
        }

        if (opts.strings) {
            section("STRINGS  (showing up to 40 of " + std::to_string(strs.size()) + ")");
            for (size_t i = 0; i < strs.size() && i < 40; ++i)
                std::cout << "  " << ansi::grey(strs[i]) << "\n";
        }

        // ---- UEBA behavioral profile ----
        section("BEHAVIORAL PROFILE  (UEBA)");
        if (behavior.type == ueba::Archetype::Unknown) {
            std::cout << "  " << ansi::grey("no strong archetype match") << "\n";
        } else {
            const char* arc_col = (behavior.modifier > 0) ? "\033[31;1m"    // red  = more dangerous
                                : (behavior.modifier < 0) ? "\033[32;1m"    // green = less dangerous
                                :                           "\033[33;1m";   // yellow = neutral
            std::string label_str = arc_col + std::string(ueba::archetype_label(behavior.type)) + "\033[0m";
            if (!color_enabled()) label_str = ueba::archetype_label(behavior.type);

            char conf[16];
            std::snprintf(conf, sizeof(conf), "%.0f%%", behavior.confidence * 100.f);
            kv("archetype", label_str + ansi::grey(std::string("  (confidence ") + conf + ")"));
            kv("reasoning", behavior.reasoning);

            std::string mod_str;
            if (behavior.modifier > 0)
                mod_str = ansi::red("+" + std::to_string(behavior.modifier) + "  (context raises score - stronger threat signals)");
            else if (behavior.modifier < 0)
                mod_str = ansi::green(std::to_string(behavior.modifier) + "  (context reduces score - benign pattern)");
            else
                mod_str = ansi::grey("0  (neutral - insufficient context to adjust)");
            kv("modifier", mod_str);

            if (opts.profile) {
                // verbose breakdown of which signals fired
                std::cout << "\n  " << ansi::grey("-- capability signals used for profiling --") << "\n";
                auto show_cap = [&](const char* name, bool present) {
                    std::cout << "  " << ansi::grey(std::string("  ") + name + ":  ")
                              << (present ? ansi::yellow("yes") : ansi::grey("no")) << "\n";
                };
                show_cap("process injection", ueba::has_sig_cap(risk, sig::Capability::ProcessInjection));
                show_cap("input capture",     ueba::has_sig_cap(risk, sig::Capability::InputCapture));
                show_cap("networking",         ueba::has_cap(risk, sig::Capability::Networking));
                show_cap("screen capture",     ueba::has_cap(risk, sig::Capability::ScreenCapture));
                show_cap("cryptography",       ueba::has_cap(risk, sig::Capability::Cryptography));
                show_cap("reconnaissance",     ueba::has_cap(risk, sig::Capability::Reconnaissance));
                show_cap("anti-debug",         ueba::has_cap(risk, sig::Capability::AntiDebug));
                show_cap("UPX packing",        has_upx);
                char buf[32];
                std::snprintf(buf, sizeof(buf), "%zu", info.total_imports);
                std::cout << "  " << ansi::grey("  import count:  ") << buf << "\n";
            }
        }
    }

    // ---- VT file reputation ----
    if (!opts.vt_key.empty()) {
        section("VIRUSTOTAL");
        print_source_result(vt);
    } else {
        std::cout << "\n  " << ansi::grey("(set VT_API_KEY to add VirusTotal file reputation)") << "\n";
    }

    // ---- verdict ----
    section("VERDICT");
    std::cout << "  " << verdict_badge(verdict_for_score(final_score), final_score)
              << "   risk " << colour_score(final_score) << "\n";

    if (info.valid) {
        std::string base_line = "base score (static): " + std::to_string(base_score);
        if (behavior.modifier != 0) {
            std::string adj = (behavior.modifier > 0 ? "+" : "") + std::to_string(behavior.modifier);
            base_line += "  UEBA " + adj + "  ->  adjusted: " + std::to_string(static_score);
        }
        std::cout << "  " << ansi::grey(base_line) << "\n";
        if (vt.ok && vt.found)
            std::cout << "  " << ansi::grey("virustotal: " + vt.summary) << "\n";
        if (has_upx && final_score < 60)
            std::cout << "  " << ansi::grey("note: UPX packing is common in legitimate open-source software") << "\n";
    }

    std::cout << "\n";
    return final_score >= 30 ? 1 : 0;
}

// ===========================================================================
//  IOC enrichment
// ===========================================================================
int enrich_ioc(const Options& opts) {
    using namespace horus;
    IocType type = classify(opts.target);

    if (type == IocType::Unknown) {
        std::cerr << "error: '" << opts.target
                  << "' is neither a readable file nor a recognised indicator.\n";
        return 2;
    }

    auto sources = build_sources(opts);
    auto results = intel::enrich(sources, opts.target, type);

    int worst = 0;
    for (auto& r : results) {
        if (r.ok && r.found) {
            if (r.malicious > 0) worst = std::max(worst, vt_score_from(r.malicious));
            if (r.score >= 0)    worst = std::max(worst, r.score);
        }
    }

    if (opts.json) {
        std::cout << "{\n  \"indicator\": \"" << json_escape(opts.target) << "\",\n";
        std::cout << "  \"type\": \"" << ioc_type_name(type) << "\",\n";
        std::cout << "  \"sources\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            std::cout << "    {\"source\": \"" << r.source << "\", \"ok\": " << (r.ok?"true":"false")
                      << ", \"found\": " << (r.found?"true":"false");
            if (r.malicious >= 0) std::cout << ", \"malicious\": " << r.malicious << ", \"total\": " << r.total;
            if (r.score >= 0)     std::cout << ", \"score\": " << r.score;
            std::cout << "}" << (i+1<results.size() ? "," : "") << "\n";
        }
        std::cout << "  ],\n  \"verdict\": \"" << verdict_for_score(worst) << "\"\n}\n";
        return worst >= 30 ? 1 : 0;
    }

    using namespace horus::ui;
    section("INDICATOR");
    kv("value", opts.target);
    kv("type",  ioc_type_name(type));

    section("INTEL");
    if (results.empty())
        std::cout << "  " << ansi::grey("no configured source handles this indicator type "
                                        "(set VT_API_KEY / ABUSEIPDB_API_KEY)") << "\n";
    for (auto& r : results) print_source_result(r);

    section("VERDICT");
    std::cout << "  " << verdict_badge(verdict_for_score(worst), worst)
              << "   risk " << colour_score(worst) << "\n\n";
    return worst >= 30 ? 1 : 0;
}

void usage() {
    std::cout <<
    "HORUS v2 - PE analysis + UEBA behavioral profiling\n\n"
    "usage: horus <indicator-or-file> [options]\n\n"
    "  <indicator-or-file>   a hash / IP / domain / URL / email, OR a file path\n\n"
    "options:\n"
    "  --vt-key <key>        VirusTotal API key   (or env VT_API_KEY)\n"
    "  --abuse-key <key>     AbuseIPDB API key     (or env ABUSEIPDB_API_KEY)\n"
    "  --strings             dump extracted strings\n"
    "  --profile             verbose UEBA signal breakdown\n"
    "  --json                machine-readable JSON output\n"
    "  --no-color            disable ANSI colour\n"
    "  -h, --help            this help\n\n"
    "examples:\n"
    "  horus suspicious.exe\n"
    "  horus suspicious.exe --profile\n"
    "  horus 44d88612fea8a8f36de82e1278abb02f\n"
    "  horus 185.220.101.5 --abuse-key $env:ABUSEIPDB_API_KEY\n"
    "  horus suspect.exe --vt-key $env:VT_API_KEY --json\n";
}

Options parse_args(int argc, char** argv) {
    Options o;
    o.vt_key    = get_env("VT_API_KEY");
    o.abuse_key = get_env("ABUSEIPDB_API_KEY");
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "error: " << what << " needs a value\n"; std::exit(2); }
            return argv[++i];
        };
        if      (a == "-h" || a == "--help") o.help = true;
        else if (a == "--json")              o.json = true;
        else if (a == "--strings")           o.strings = true;
        else if (a == "--no-color")          o.no_color = true;
        else if (a == "--profile")           o.profile = true;
        else if (a == "--vt-key")            o.vt_key = next("--vt-key");
        else if (a == "--abuse-key")         o.abuse_key = next("--abuse-key");
        else if (!a.empty() && a[0] == '-')  { std::cerr << "unknown option: " << a << "\n"; std::exit(2); }
        else                                  o.target = a;
    }
    return o;
}

} // namespace

int main(int argc, char** argv) {
    Options opts = parse_args(argc, argv);

    horus::ui::init();
    if (opts.no_color) horus::ui::color_enabled() = false;

    if (opts.help || opts.target.empty()) {
        if (!opts.json) horus::ui::banner();
        usage();
        return opts.target.empty() && !opts.help ? 2 : 0;
    }

    if (!opts.json) horus::ui::banner();

    if (file_exists(opts.target))
        return analyze_file(opts);
    return enrich_ioc(opts);
}
