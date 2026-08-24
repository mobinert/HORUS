// ---------------------------------------------------------------------------
//  core.hpp  -  the analysis engine, split out of main so every front-end
//               (cli, gui, and the unified build) runs the exact same pipeline.
//
//  Nothing here writes to stdout. analyze_file() / enrich_ioc() compute a
//  Report; the console renderer and the JSON serialisers below turn a Report
//  into text. The GUI eats the richer gui_json().
// ---------------------------------------------------------------------------
#pragma once

#include "ioc.hpp"
#include "pe.hpp"
#include "signatures.hpp"
#include "ueba.hpp"
#include "crypto.hpp"
#include "intel.hpp"
#include "fuzzy.hpp"
#include "attack.hpp"
#include "authenticode.hpp"

#include <string>
#include <vector>
#include <memory>
#include <set>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <algorithm>
#include <utility>
#include <cstdint>
#include <filesystem>

namespace horus {
namespace core {

struct Options {
    std::string target;
    std::string vt_key;
    std::string abuse_key;
    bool json     = false;
    bool strings  = false;
    bool no_color = false;
    bool help     = false;
    bool show_version = false;
    bool profile  = false;

    // folder and report modes
    std::string scan_dir;          // --scan <dir>
    std::string diff_a, diff_b;    // --diff a b
    std::string csv_out;           // --csv <file>
    std::string json_out;          // --json-out <file>
    bool clip = false;             // --clip
    bool gui  = false;             // --gui
    bool recurse = true;           // scan recurses by default
    int  cache_ttl_hours = 0;      // 0 = intel cache off
    bool cache_ttl_set = false;    // argv supplied --cache-ttl, including zero
    std::string html_out;          // --html <file>: write the glass report, no browser

    // v4 persistent case analysis
    std::string case_dir;
    std::string case_out;
    std::string case_name;
    std::string cluster_mode = "balanced";
    bool verify = false;
    bool rebuild = false;
    bool prune = false;
    bool enrich = false;
    bool online_trust = false;
    int max_lookups = 100;
    uint64_t max_file_mb = 512;
};

// ---- small shared helpers -------------------------------------------------
inline std::string get_env(const char* name) {
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

inline bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    out.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return true;
}

inline bool file_exists(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f.good();
}

inline std::string json_escape(const std::string& s) {
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

// XOR decode - same key (0x5A) as signatures.hpp / ueba.hpp. Keeps the tool's
// own watch-list vocabulary out of .rdata so AV heuristics don't string-match it.
inline std::string mdx(std::initializer_list<uint8_t> enc) {
    std::string s; s.reserve(enc.size());
    for (auto b : enc) s += (char)(b ^ 0x5A);
    return s;
}

// ---- embedded IOC + software-hint extraction ------------------------------
struct EmbeddedIocs {
    std::set<std::string> urls;
    std::set<std::string> ips;
    std::set<std::string> interesting;
};

struct EmbeddedIntel {
    std::string value;
    IocType type = IocType::Unknown;
    std::vector<intel::SourceResult> results;
};

inline EmbeddedIocs scan_strings(const std::vector<std::string>& strs) {
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
        mdx({0x38,0x39,0x3E,0x3F,0x3E,0x33,0x2E}),                                                     // bcdedit
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
                std::string candidate = s.substr(pos, end - pos);
                if (horus::classify(candidate) == horus::IocType::Url)
                    found.urls.insert(std::move(candidate));
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

struct SoftwareHints {
    std::vector<std::string> matched_keywords;
    bool looks_like_automation = false;
    bool looks_like_installer  = false;
    bool looks_like_security   = false;
};

inline SoftwareHints detect_hints(const std::vector<std::string>& strs) {
    SoftwareHints h;
    static const char* auto_kw[] = {
        "AutoHotkey", "AutoIt", "AHK", "macro", "hotkey", "SendKeys", nullptr
    };
    static const char* inst_kw[] = {
        "Setup", "Installer", "Uninstall", "NSIS", "Inno Setup",
        "Install Wizard", "Bootstrapper", "Redistributable", nullptr
    };
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

inline std::vector<std::shared_ptr<intel::IntelSource>> build_sources(const Options& o) {
    std::vector<std::shared_ptr<intel::IntelSource>> v;
    if (!o.vt_key.empty())    v.push_back(std::make_shared<intel::VirusTotal>(o.vt_key));
    if (!o.abuse_key.empty()) v.push_back(std::make_shared<intel::AbuseIPDB>(o.abuse_key));
    return v;
}

// Authenticode hash: SHA-256 over the file with the checksum, the security
// data-directory entry and the certificate table carved out (per the PE spec).
inline std::string compute_authentihash(const std::vector<uint8_t>& bytes, const pe::Info& info) {
    if (!info.ah_ready) return {};
    size_t n  = bytes.size();
    size_t ck = info.ah_checksum_off;
    size_t sd = info.ah_secdir_off;
    if (ck + 4 > sd || sd + 8 > n) return {};

    size_t cert_off = 0, cert_end = 0;
    if (info.ah_cert_size > 0 && info.ah_cert_off >= sd + 8 && info.ah_cert_off <= n) {
        cert_off = info.ah_cert_off;
        cert_end = std::min(n, cert_off + info.ah_cert_size);
    }

    const uint8_t* p = bytes.data();
    std::vector<std::pair<const uint8_t*, size_t>> segs;
    segs.push_back({p, ck});
    segs.push_back({p + ck + 4, sd - (ck + 4)});
    if (cert_off) {
        segs.push_back({p + sd + 8, cert_off - (sd + 8)});
        if (cert_end < n) segs.push_back({p + cert_end, n - cert_end});
    } else {
        segs.push_back({p + sd + 8, n - (sd + 8)});
    }
    return crypto::sha256_hex_segments(segs);
}

inline int vt_score_from(int malicious) {
    if (malicious <= 0) return 0;
    int s = 35 + malicious * 4;
    return s > 100 ? 100 : s;
}

inline const char* verdict_for_score(int s) {
    if (s >= 60) return "LIKELY MALICIOUS";
    if (s >= 30) return "SUSPICIOUS";
    if (s >= 10) return "LOW RISK";
    return "CLEAN";
}

inline std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i)
        out += std::string(i ? "," : "") + "\"" + json_escape(values[i]) + "\"";
    return out + "]";
}

enum class AnalysisStatus { Complete, Unknown, Skipped, Error };

inline const char* analysis_status_name(AnalysisStatus status) {
    switch (status) {
        case AnalysisStatus::Complete: return "complete";
        case AnalysisStatus::Skipped:  return "skipped";
        case AnalysisStatus::Error:    return "error";
        default:                       return "unknown";
    }
}

inline const char* verdict_name(bool has_score, int score) {
    return has_score ? verdict_for_score(score) : "UNKNOWN";
}

inline int analysis_exit_code(AnalysisStatus status, bool has_score, int score) {
    if (has_score && score >= 30) return 1;
    return status == AnalysisStatus::Complete ? 0 : 3;
}

// ---------------------------------------------------------------------------
//  Reports
// ---------------------------------------------------------------------------
struct FileReport {
    bool        ok = true;
    std::string error;               // set when ok == false
    std::string target;
    size_t      size = 0;
    AnalysisStatus analysis_status = AnalysisStatus::Unknown;
    bool        has_score = false;
    std::vector<std::string> evidence;
    std::vector<std::string> source_errors;

    crypto::FileHashes hashes;
    pe::Info    info;
    std::string imphash;
    std::vector<std::string> strs;
    sig::ScoreResult risk;
    bool        has_upx = false;
    ueba::Profile behavior;
    SoftwareHints hints;

    std::string tlsh, ssdeep, authentihash, rich_hash;
    std::vector<attack::Technique> techs;
    authcode::Result sig;
    intel::SourceResult vt;
    std::vector<intel::SourceResult> hash_intel;
    EmbeddedIocs emb;
    std::vector<EmbeddedIntel> embedded_intel;

    int base_score = 0, sig_penalty = 0, static_score = 0, vt_score = 0, final_score = 0;
};

struct IndicatorReport {
    bool        ok = true;
    std::string error;
    std::string target;
    IocType     type = IocType::Unknown;
    std::vector<intel::SourceResult> results;
    AnalysisStatus analysis_status = AnalysisStatus::Unknown;
    bool        has_score = false;
    std::vector<std::string> evidence;
    std::vector<std::string> source_errors;
    int         worst = 0;
};

inline void enrich_file_report(FileReport& rep, const Options& opts,
                               const std::vector<std::shared_ptr<intel::IntelSource>>& sources) {
    if (!opts.enrich) return;
    if (sources.empty()) {
        rep.source_errors.push_back("no threat-intelligence provider is configured");
        return;
    }

    int lookups = 0;
    bool limit_reported = false;
    auto supported = [&](IocType type) {
        for (const auto& source : sources) if (source->supports(type)) return true;
        return false;
    };
    auto note_errors = [&](const std::string& value,
                           const std::vector<intel::SourceResult>& results) {
        for (const auto& result : results)
            if (!result.ok && !result.error.empty())
                rep.source_errors.push_back(result.source + " (" + value + "): " + result.error);
    };
    auto query = [&](const std::string& value, IocType type) {
        std::vector<intel::SourceResult> results;
        if (!supported(type)) return results;
        if (lookups >= opts.max_lookups) {
            if (!limit_reported) rep.source_errors.push_back("live lookup limit reached");
            limit_reported = true;
            return results;
        }
        results = intel::enrich(sources, value, type);
        ++lookups;
        note_errors(value, results);
        return results;
    };

    if (!rep.hashes.sha256.empty()) {
        if (!supported(IocType::SHA256)) {
            rep.source_errors.push_back("no configured provider supports SHA-256 enrichment");
        } else {
            rep.hash_intel = query(rep.hashes.sha256, IocType::SHA256);
            if (!rep.hash_intel.empty()) {
                auto found = std::find_if(rep.hash_intel.begin(), rep.hash_intel.end(),
                    [](const intel::SourceResult& result) { return result.source == "VirusTotal"; });
                rep.vt = found == rep.hash_intel.end() ? rep.hash_intel.front() : *found;
            }
        }
    }

    auto enrich_embedded = [&](const std::string& value, IocType type) {
        if (!supported(type)) return;
        EmbeddedIntel record;
        record.value = value;
        record.type = type;
        record.results = query(value, type);
        if (!record.results.empty()) rep.embedded_intel.push_back(std::move(record));
    };
    for (const auto& url : rep.emb.urls) enrich_embedded(url, IocType::Url);
    for (const auto& ip : rep.emb.ips) enrich_embedded(ip, IocType::IPv4);
}

// Analyse a file on disk. bytes are read fresh here.
inline FileReport analyze_file(const Options& opts) {
    FileReport rep;
    rep.target = opts.target;

    std::error_code size_error;
    uintmax_t disk_size = std::filesystem::file_size(std::filesystem::path(opts.target), size_error);
    if (!size_error) {
        rep.size = static_cast<size_t>(disk_size);
        const uint64_t limit = opts.max_file_mb * 1024ULL * 1024ULL;
        if (disk_size > limit) {
            rep.analysis_status = AnalysisStatus::Skipped;
            rep.error = "file exceeds --max-file-mb (" + std::to_string(opts.max_file_mb) + " MiB)";
            return rep;
        }
    }

    std::vector<uint8_t> bytes;
    if (!read_file(opts.target, bytes)) {
        rep.ok = false;
        rep.analysis_status = AnalysisStatus::Error;
        rep.error = "cannot read file: " + opts.target;
        return rep;
    }
    rep.size = bytes.size();

    rep.hashes = crypto::hash_buffer(bytes);
    pe::Analyzer analyzer(bytes);
    rep.info = analyzer.analyze();

    if (rep.info.valid && !rep.info.imphash_string.empty())
        rep.imphash = crypto::md5_hex(rep.info.imphash_string);

    rep.strs = analyzer.extract_strings(5);
    rep.emb = scan_strings(rep.strs);

    if (rep.info.valid) rep.risk = sig::score(rep.info);
    rep.has_upx  = rep.info.valid && rep.risk.has_upx;
    rep.behavior = ueba::profile(rep.info, rep.risk, rep.strs, rep.has_upx);
    rep.hints    = detect_hints(rep.strs);

    rep.tlsh   = fuzzy::tlsh(bytes);
    rep.ssdeep = fuzzy::ssdeep(bytes);
    if (rep.info.valid) {
        rep.authentihash = compute_authentihash(bytes, rep.info);
        if (rep.info.has_rich && !rep.info.rich_clear.empty())
            rep.rich_hash = crypto::md5_hex(rep.info.rich_clear.data(), rep.info.rich_clear.size());
        rep.techs = attack::techniques(rep.risk);
        rep.sig   = authcode::verify(opts.target, rep.info.has_authenticode, opts.online_trust);
    }

    enrich_file_report(rep, opts, build_sources(opts));

    rep.base_score = rep.info.valid ? rep.risk.score : 0;
    rep.sig_penalty = 0;
    if (rep.info.valid && rep.info.has_authenticode) {
        switch (rep.sig.status) {
            case authcode::Status::Invalid:   rep.sig_penalty = 30; break;
            case authcode::Status::Revoked:   rep.sig_penalty = 40; break;
            case authcode::Status::Malformed: rep.sig_penalty = 20; break;
            case authcode::Status::Untrusted: rep.sig_penalty = 8;  break;
            case authcode::Status::Expired:   rep.sig_penalty = 3;  break;
            default: break;
        }
    }
    rep.static_score = rep.base_score + rep.behavior.modifier + rep.sig_penalty;
    if (rep.static_score < 0)   rep.static_score = 0;
    if (rep.static_score > 100) rep.static_score = 100;

    rep.vt_score    = (rep.vt.ok && rep.vt.found) ? vt_score_from(rep.vt.malicious) : 0;
    rep.final_score = std::max(rep.static_score, rep.vt_score);

    if (rep.info.valid) {
        rep.analysis_status = AnalysisStatus::Complete;
        rep.has_score = true;
        rep.evidence.push_back("PE static analysis");
    }
    if (rep.vt.ok && rep.vt.found) {
        rep.analysis_status = AnalysisStatus::Complete;
        rep.has_score = true;
        rep.evidence.push_back((rep.vt.source.empty() ? std::string("reputation") : rep.vt.source) + " file report");
    }

    return rep;
}

// worst 0-100 across a set of source results, same rule the reports use.
inline int compute_worst(const std::vector<intel::SourceResult>& results) {
    int worst = 0;
    for (auto& r : results) {
        if (r.ok && r.found) {
            if (r.malicious > 0) worst = std::max(worst, vt_score_from(r.malicious));
            if (r.score >= 0)    worst = std::max(worst, r.score);
        }
    }
    return worst;
}

inline void finalize_indicator(IndicatorReport& rep) {
    rep.worst = compute_worst(rep.results);
    for (const auto& result : rep.results) {
        if (result.ok && result.found) {
            rep.analysis_status = AnalysisStatus::Complete;
            rep.has_score = true;
            rep.evidence.push_back(result.source + " report");
        } else if (!result.ok && !result.error.empty()) {
            rep.source_errors.push_back(result.source + ": " + result.error);
        }
    }
}

inline IndicatorReport enrich_ioc(const Options& opts) {
    IndicatorReport rep;
    rep.target = detail::trim(opts.target);
    rep.type   = classify(rep.target);
    if (rep.type == IocType::Unknown) {
        rep.ok = false;
        rep.analysis_status = AnalysisStatus::Error;
        rep.error = "'" + opts.target + "' is neither a readable file nor a recognised indicator.";
        return rep;
    }
    if (!opts.enrich) return rep;
    auto sources = build_sources(opts);
    if (sources.empty()) {
        rep.source_errors.push_back("no threat-intelligence provider is configured");
        return rep;
    }
    rep.results = intel::enrich(sources, rep.target, rep.type);
    finalize_indicator(rep);
    return rep;
}

// ---------------------------------------------------------------------------
//  JSON serialisers
// ---------------------------------------------------------------------------
inline std::string source_results_json(const std::vector<intel::SourceResult>& results) {
    std::string out = "[";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        out += std::string(i ? "," : "") + "{\"source\":\"" + json_escape(r.source) + "\"";
        out += std::string(",\"ok\":") + (r.ok ? "true" : "false");
        out += std::string(",\"found\":") + (r.found ? "true" : "false");
        out += ",\"summary\":\"" + json_escape(r.summary) + "\"";
        out += ",\"malicious\":" + std::to_string(r.malicious);
        out += ",\"total\":" + std::to_string(r.total);
        out += ",\"score\":" + std::to_string(r.score);
        out += ",\"error\":\"" + json_escape(r.error) + "\",\"details\":[";
        for (size_t k = 0; k < r.details.size(); ++k)
            out += std::string(k ? "," : "") + "{\"k\":\"" + json_escape(r.details[k].first) +
                   "\",\"v\":\"" + json_escape(r.details[k].second) + "\"}";
        out += "]}";
    }
    return out + "]";
}

// Compact direct-analysis output. New fields are additive where practical.
inline std::string file_json(const Options& opts, const FileReport& rep) {
    const auto& info = rep.info;
    const auto& hashes = rep.hashes;
    std::string o;
    auto add = [&](const std::string& s){ o += s; };
    char buf[256];

    add("{\n");
    add("  \"target\": \"" + json_escape(opts.target) + "\",\n");
    add(std::string("  \"analysis_status\": \"") + analysis_status_name(rep.analysis_status) + "\",\n");
    if (!rep.error.empty()) add("  \"error\": \"" + json_escape(rep.error) + "\",\n");
    add("  \"size\": " + std::to_string(rep.size) + ",\n");
    add("  \"md5\": \"" + hashes.md5 + "\",\n");
    add("  \"sha1\": \"" + hashes.sha1 + "\",\n");
    add("  \"sha256\": \"" + hashes.sha256 + "\",\n");
    if (!rep.tlsh.empty())   add("  \"tlsh\": \"" + rep.tlsh + "\",\n");
    if (!rep.ssdeep.empty()) add("  \"ssdeep\": \"" + json_escape(rep.ssdeep) + "\",\n");
    add(std::string("  \"is_pe\": ") + (info.valid ? "true" : "false") + ",\n");
    if (info.valid) {
        add("  \"bitness\": " + std::string(info.is_64bit ? "64" : "32") + ",\n");
        add("  \"imphash\": \"" + rep.imphash + "\",\n");
        if (!rep.authentihash.empty())
            add("  \"authentihash\": \"" + rep.authentihash + "\",\n");
        if (!rep.rich_hash.empty()) {
            std::snprintf(buf, sizeof(buf), "%08x", info.rich_xor_key);
            add("  \"rich_hash\": \"" + rep.rich_hash + "\",\n");
            add(std::string("  \"rich_xor_key\": \"") + buf + "\",\n");
        }
        if (!info.pdb_path.empty())
            add("  \"pdb_path\": \"" + json_escape(info.pdb_path) + "\",\n");
        add(std::string("  \"is_dotnet\": ") + (info.is_dotnet ? "true" : "false") + ",\n");
        add("  \"tls_callbacks\": " + std::to_string(info.tls_callback_count) + ",\n");
        if (info.has_exports)
            add("  \"exports\": " + std::to_string(info.export_count) + ",\n");
        if (info.overlay_size > 0) {
            std::snprintf(buf, sizeof(buf), "%.2f", info.overlay_entropy);
            add("  \"overlay_size\": " + std::to_string(info.overlay_size) + ",\n");
            add(std::string("  \"overlay_entropy\": ") + buf + ",\n");
        }
        add(std::string("  \"signature\": {\"status\": \"") + authcode::status_label(rep.sig.status) + "\"");
        if (!rep.sig.signer.empty()) add(", \"signer\": \"" + json_escape(rep.sig.signer) + "\"");
        if (!rep.sig.issuer.empty()) add(", \"issuer\": \"" + json_escape(rep.sig.issuer) + "\"");
        add(std::string(", \"revocation_checked\": ") + (rep.sig.revocation_checked ? "true" : "false"));
        add("},\n");
        add("  \"attack\": [");
        for (size_t i = 0; i < rep.techs.size(); ++i)
            add(std::string(i ? ", " : "") + "\"" + rep.techs[i].id + "\"");
        add("],\n");
        add(std::string("  \"has_authenticode\": ") + (info.has_authenticode ? "true" : "false") + ",\n");
        add(std::string("  \"has_upx\": ") + (rep.has_upx ? "true" : "false") + ",\n");
        add("  \"base_score\": " + std::to_string(rep.base_score) + ",\n");
        add(std::string("  \"ueba_archetype\": \"") + ueba::archetype_label(rep.behavior.type) + "\",\n");
        add("  \"ueba_modifier\": " + std::to_string(rep.behavior.modifier) + ",\n");
        add("  \"static_score\": " + std::to_string(rep.static_score) + ",\n");
    }
    if (rep.vt.ok && rep.vt.found)
        add("  \"vt_detections\": " + std::to_string(rep.vt.malicious) + ",\n");
    add("  \"hash_intel\": " + source_results_json(rep.hash_intel) + ",\n");
    add("  \"embedded_intel\": [");
    for (size_t i = 0; i < rep.embedded_intel.size(); ++i) {
        const auto& record = rep.embedded_intel[i];
        add(std::string(i ? "," : "") + "{\"value\":\"" + json_escape(record.value) +
            "\",\"type\":\"" + ioc_type_name(record.type) + "\",\"sources\":" +
            source_results_json(record.results) + "}");
    }
    add("],\n");
    add("  \"evidence\": " + json_string_array(rep.evidence) + ",\n");
    add("  \"source_errors\": " + json_string_array(rep.source_errors) + ",\n");
    add("  \"final_score\": " + (rep.has_score ? std::to_string(rep.final_score) : std::string("null")) + ",\n");
    add(std::string("  \"verdict\": \"") + verdict_name(rep.has_score, rep.final_score) + "\"\n");
    add("}\n");
    return o;
}

// gui_file_json: the fat report the glass console draws from - sections,
// capabilities with labels, ATT&CK names, embedded IOCs, UEBA reasoning.
inline std::string gui_file_json(const Options& opts, const FileReport& rep) {
    const auto& info = rep.info;
    std::string o;
    char b[64];
    auto q = [&](const std::string& s){ return "\"" + json_escape(s) + "\""; };

    o += "{\"kind\":\"file\",";
    o += "\"target\":" + q(opts.target) + ",";
    o += "\"analysis_status\":" + q(analysis_status_name(rep.analysis_status)) + ",";
    o += "\"error\":" + q(rep.error) + ",";
    o += "\"size\":" + std::to_string(rep.size) + ",";
    o += "\"hashes\":{";
    o += "\"md5\":" + q(rep.hashes.md5) + ",\"sha1\":" + q(rep.hashes.sha1) +
         ",\"sha256\":" + q(rep.hashes.sha256) + ",\"tlsh\":" + q(rep.tlsh) +
         ",\"ssdeep\":" + q(rep.ssdeep) + ",\"imphash\":" + q(rep.imphash) +
         ",\"authentihash\":" + q(rep.authentihash) + ",\"rich_hash\":" + q(rep.rich_hash) + "},";
    o += std::string("\"is_pe\":") + (info.valid ? "true" : "false") + ",";

    if (info.valid) {
        o += "\"pe\":{";
        o += std::string("\"type\":") + (info.is_dll ? "\"DLL\"" : "\"executable\"") + ",";
        o += "\"bitness\":" + std::to_string(info.is_64bit ? 64 : 32) + ",";
        o += "\"machine\":" + q(info.machine_name) + ",";
        o += "\"subsystem\":" + q(info.subsystem_name) + ",";
        o += "\"compiled\":" + q(info.compile_time) + ",";
        o += std::string("\"timestamp_suspicious\":") + (info.timestamp_suspicious ? "true" : "false") + ",";
        std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)info.image_base);
        o += "\"image_base\":" + q(b) + ",";
        std::snprintf(b, sizeof(b), "0x%x", info.entry_point_rva);
        o += "\"entry_rva\":" + q(b) + ",";
        o += std::string("\"is_dotnet\":") + (info.is_dotnet ? "true" : "false") + ",";
        o += "\"tls_callbacks\":" + std::to_string(info.tls_callback_count) + ",";
        o += "\"exports\":" + std::to_string(info.has_exports ? info.export_count : 0) + ",";
        o += "\"overlay_size\":" + std::to_string(info.overlay_size) + ",";
        std::snprintf(b, sizeof(b), "%.2f", info.overlay_entropy);
        o += std::string("\"overlay_entropy\":") + b + ",";
        o += "\"pdb_path\":" + q(info.pdb_path) + ",";
        o += "\"sections\":[";
        for (size_t i = 0; i < info.sections.size(); ++i) {
            const auto& s = info.sections[i];
            std::string flags;
            flags += s.readable ? "r" : "-";
            flags += s.writable ? "w" : "-";
            flags += s.executable ? "x" : "-";
            std::snprintf(b, sizeof(b), "%.2f", s.entropy);
            o += std::string(i ? "," : "") + "{\"name\":" + q(s.name) + ",\"flags\":" + q(flags) +
                 ",\"entropy\":" + b + ",\"rwx\":" + (s.is_rwx() ? "true" : "false") + "}";
        }
        o += "],\"imports\":[";
        for (size_t i = 0; i < info.imports.size(); ++i)
            o += std::string(i ? "," : "") + "{\"dll\":" + q(info.imports[i].dll) +
                 ",\"count\":" + std::to_string(info.imports[i].functions.size()) + "}";
        o += "]},";

        o += "\"signature\":{\"status\":" + q(authcode::status_label(rep.sig.status)) +
             ",\"signer\":" + q(rep.sig.signer) + ",\"issuer\":" + q(rep.sig.issuer) +
             ",\"catalog\":" + std::string(rep.sig.catalog ? "true" : "false") +
             ",\"revocation_checked\":" + std::string(rep.sig.revocation_checked ? "true" : "false") + "},";

        o += "\"capabilities\":[";
        for (size_t i = 0; i < rep.risk.capabilities.size(); ++i) {
            const auto& h = rep.risk.capabilities[i];
            const auto& m = sig::meta(h.cap);
            o += std::string(i ? "," : "") + "{\"label\":" + q(m.label) +
                 ",\"significant\":" + (h.significant ? "true" : "false") +
                 ",\"blurb\":" + q(m.blurb) + ",\"apis\":[";
            for (size_t k = 0; k < h.apis.size(); ++k)
                o += std::string(k ? "," : "") + q(h.apis[k]);
            o += "]}";
        }
        o += "],";

        o += "\"findings\":[";
        for (size_t i = 0; i < rep.risk.findings.size(); ++i)
            o += std::string(i ? "," : "") + "{\"text\":" + q(rep.risk.findings[i].text) +
                 ",\"weight\":" + std::to_string(rep.risk.findings[i].weight) + "}";
        o += "],";

        o += "\"attack\":[";
        for (size_t i = 0; i < rep.techs.size(); ++i)
            o += std::string(i ? "," : "") + "{\"id\":" + q(rep.techs[i].id) +
                 ",\"name\":" + q(rep.techs[i].name) + "}";
        o += "],";

        std::snprintf(b, sizeof(b), "%.2f", rep.behavior.confidence);
        o += "\"ueba\":{\"archetype\":" + q(ueba::archetype_label(rep.behavior.type)) +
             ",\"confidence\":" + b + ",\"modifier\":" + std::to_string(rep.behavior.modifier) +
             ",\"reasoning\":" + q(rep.behavior.reasoning) + "},";

        o += "\"hints\":{\"keywords\":[";
        for (size_t i = 0; i < rep.hints.matched_keywords.size(); ++i)
            o += std::string(i ? "," : "") + q(rep.hints.matched_keywords[i]);
        o += std::string("],\"automation\":") + (rep.hints.looks_like_automation ? "true" : "false") +
             ",\"installer\":" + (rep.hints.looks_like_installer ? "true" : "false") +
             ",\"security\":" + (rep.hints.looks_like_security ? "true" : "false") + "},";
    }

    o += "\"embedded\":{\"urls\":[";
    { size_t i = 0; for (auto& u : rep.emb.urls) o += std::string(i++ ? "," : "") + q(u); }
    o += "],\"ips\":[";
    { size_t i = 0; for (auto& ip : rep.emb.ips) o += std::string(i++ ? "," : "") + q(ip); }
    o += "],\"tokens\":[";
    { size_t i = 0; for (auto& t : rep.emb.interesting) o += std::string(i++ ? "," : "") + q(t); }
    o += "]},";

    o += "\"hash_intel\":" + source_results_json(rep.hash_intel) + ",";
    o += "\"embedded_intel\":[";
    for (size_t i = 0; i < rep.embedded_intel.size(); ++i) {
        const auto& record = rep.embedded_intel[i];
        o += std::string(i ? "," : "") + "{\"value\":" + q(record.value) +
             ",\"type\":" + q(ioc_type_name(record.type)) +
             ",\"sources\":" + source_results_json(record.results) + "}";
    }
    o += "],";

    o += "\"scores\":{\"base\":" + std::to_string(rep.base_score) +
         ",\"static\":" + std::to_string(rep.static_score) +
         ",\"vt\":" + std::to_string((rep.vt.ok && rep.vt.found) ? rep.vt_score : -1) +
         ",\"final\":" + (rep.has_score ? std::to_string(rep.final_score) : std::string("null")) + "},";
    if (rep.vt.ok && rep.vt.found)
        o += "\"vt\":{\"summary\":" + q(rep.vt.summary) + ",\"malicious\":" +
             std::to_string(rep.vt.malicious) + ",\"total\":" + std::to_string(rep.vt.total) + "},";
    o += "\"evidence\":" + json_string_array(rep.evidence) + ",";
    o += "\"source_errors\":" + json_string_array(rep.source_errors) + ",";
    o += "\"verdict\":" + q(verdict_name(rep.has_score, rep.final_score));
    o += "}";
    return o;
}

inline std::string gui_indicator_json(const IndicatorReport& rep) {
    std::string o;
    auto q = [&](const std::string& s){ return "\"" + json_escape(s) + "\""; };
    o += "{\"kind\":\"indicator\",\"target\":" + q(rep.target) +
         ",\"type\":" + q(ioc_type_name(rep.type)) +
         ",\"analysis_status\":" + q(analysis_status_name(rep.analysis_status)) + ",\"sources\":[";
    for (size_t i = 0; i < rep.results.size(); ++i) {
        const auto& r = rep.results[i];
        o += std::string(i ? "," : "") + "{\"source\":" + q(r.source) +
             ",\"ok\":" + (r.ok ? "true" : "false") +
             ",\"found\":" + (r.found ? "true" : "false") +
             ",\"summary\":" + q(r.summary) +
             ",\"malicious\":" + std::to_string(r.malicious) +
             ",\"total\":" + std::to_string(r.total) +
             ",\"score\":" + std::to_string(r.score) +
             ",\"error\":" + q(r.error) + ",\"details\":[";
        for (size_t k = 0; k < r.details.size(); ++k)
            o += std::string(k ? "," : "") + "{\"k\":" + q(r.details[k].first) +
                 ",\"v\":" + q(r.details[k].second) + "}";
        o += "]}";
    }
    o += "],\"evidence\":" + json_string_array(rep.evidence) +
         ",\"source_errors\":" + json_string_array(rep.source_errors) +
         ",\"worst\":" + (rep.has_score ? std::to_string(rep.worst) : std::string("null")) +
         ",\"verdict\":" + q(verdict_name(rep.has_score, rep.worst)) + "}";
    return o;
}

inline std::string indicator_json(const IndicatorReport& rep) {
    std::string o;
    o += "{\n  \"indicator\": \"" + json_escape(rep.target) + "\",\n";
    o += "  \"type\": \"" + std::string(ioc_type_name(rep.type)) + "\",\n";
    o += std::string("  \"analysis_status\": \"") + analysis_status_name(rep.analysis_status) + "\",\n";
    o += "  \"sources\": [\n";
    for (size_t i = 0; i < rep.results.size(); ++i) {
        const auto& r = rep.results[i];
        o += "    {\"source\": \"" + r.source + "\", \"ok\": " + (r.ok?"true":"false")
           + ", \"found\": " + (r.found?"true":"false");
        if (r.malicious >= 0) o += ", \"malicious\": " + std::to_string(r.malicious) + ", \"total\": " + std::to_string(r.total);
        if (r.score >= 0)     o += ", \"score\": " + std::to_string(r.score);
        o += "}" + std::string(i+1<rep.results.size() ? "," : "") + "\n";
    }
    o += "  ],\n  \"evidence\": " + json_string_array(rep.evidence) + ",\n";
    o += "  \"source_errors\": " + json_string_array(rep.source_errors) + ",\n";
    o += "  \"score\": " + (rep.has_score ? std::to_string(rep.worst) : std::string("null")) + ",\n";
    o += "  \"verdict\": \"" + std::string(verdict_name(rep.has_score, rep.worst)) + "\"\n}\n";
    return o;
}

} // namespace core
} // namespace horus
