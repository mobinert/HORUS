// ---------------------------------------------------------------------------
//  render.hpp  -  turn a core::Report into the terminal report. All the
//                 std::cout lives here (and in console.hpp); core stays quiet.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "console.hpp"

#include <iostream>
#include <string>

namespace horus {
namespace render {

inline std::string entropy_bar(double h) {
    int filled = (int)((h / 8.0) * 18.0 + 0.5);
    if (filled < 0)  filled = 0;
    if (filled > 18) filled = 18;
    std::string bar = "[";
    bar.append(filled, '#');
    bar.append(18 - filled, '.');
    bar += "]";
    return bar;
}

inline void print_source_result(const intel::SourceResult& r) {
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

// ---------------------------------------------------------------------------
//  File report
// ---------------------------------------------------------------------------
inline int render_file(const core::Options& opts, const core::FileReport& rep) {
    using namespace horus;
    using namespace horus::ui;

    const auto& info    = rep.info;
    const auto& hashes  = rep.hashes;
    const auto& risk    = rep.risk;
    const auto& behavior= rep.behavior;
    const auto& hints   = rep.hints;
    const auto& sig     = rep.sig;
    const auto& techs   = rep.techs;
    bool has_upx = rep.has_upx;

    section("FILE");
    kv("path",    opts.target);
    kv("size",    std::to_string(rep.size) + " bytes");
    kv("MD5",     hashes.md5);
    kv("SHA-1",   hashes.sha1);
    kv("SHA-256", hashes.sha256);
    if (!rep.tlsh.empty())   kv("TLSH",   rep.tlsh);
    if (!rep.ssdeep.empty()) kv("ssdeep", rep.ssdeep);
    kv("analysis", core::analysis_status_name(rep.analysis_status));
    if (!rep.error.empty()) kv("note", rep.error);

    if (rep.analysis_status == core::AnalysisStatus::Skipped) {
        section("VERDICT");
        std::cout << "  " << ansi::yellow("UNKNOWN") << "   " << ansi::grey(rep.error) << "\n\n";
        return 3;
    }

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
        kv("imphash",   rep.imphash);
        if (!rep.authentihash.empty()) kv("authentihash", rep.authentihash);
        if (!rep.rich_hash.empty()) {
            char kb[16]; std::snprintf(kb, sizeof(kb), "0x%08x", info.rich_xor_key);
            kv("rich hash", rep.rich_hash + ansi::grey(std::string("  (xor key ") + kb + ")"));
        }
        {
            std::string line;
            switch (sig.status) {
                case authcode::Status::Valid:     line = ansi::green("valid"); break;
                case authcode::Status::NotSigned: line = ansi::grey("unsigned"); break;
                case authcode::Status::Invalid:   line = ansi::red("INVALID - " + sig.status_text); break;
                case authcode::Status::Untrusted: line = ansi::yellow("untrusted - " + sig.status_text); break;
                case authcode::Status::Expired:   line = ansi::yellow("expired - " + sig.status_text); break;
                case authcode::Status::Revoked:   line = ansi::red("REVOKED - " + sig.status_text); break;
                case authcode::Status::Malformed: line = ansi::yellow("malformed - " + sig.status_text); break;
                default:                          line = ansi::grey(sig.status_text); break;
            }
            if (!sig.signer.empty()) line += ansi::grey("  [" + sig.signer + "]");
            kv("signature", line);
            kv("trust mode", sig.revocation_checked ? "online revocation" : "offline / cache-only");
        }
        if (info.is_dotnet)             kv("managed",  ansi::cyan(".NET / CLR image"));
        if (info.tls_callback_count > 0)
            kv("TLS callbacks", ansi::yellow(std::to_string(info.tls_callback_count) +
                                             " (run before entry point)"));
        if (info.has_exports && info.export_count > 0)
            kv("exports", std::to_string(info.export_count) +
                          (info.export_dll_name.empty() ? "" : "  (" + info.export_dll_name + ")"));
        if (info.overlay_size > 0) {
            char b[96];
            std::snprintf(b, sizeof(b), "%llu bytes  H=%.2f",
                          (unsigned long long)info.overlay_size, info.overlay_entropy);
            std::string ov = b;
            kv("overlay", info.overlay_entropy >= 7.2 ? ansi::yellow(ov) : ov);
        }

        if (info.has_rich || !info.pdb_path.empty()) {
            section("BUILD ENVIRONMENT");
            if (!info.pdb_path.empty()) {
                kv("PDB path", ansi::cyan(info.pdb_path));
                if (!info.codeview_guid.empty())
                    kv("PDB GUID", info.codeview_guid + ansi::grey("  age " +
                                   std::to_string(info.codeview_age)));
            }
            if (info.has_rich) {
                std::cout << "  " << ansi::grey("Rich header - " +
                             std::to_string(info.rich_entries.size()) + " toolchain record(s)") << "\n";
                size_t shown = 0;
                for (const auto& e : info.rich_entries) {
                    if (shown++ >= 12) { std::cout << ansi::grey("      ...") << "\n"; break; }
                    char b[96];
                    std::snprintf(b, sizeof(b), "      prodid %-5u  build %-6u  used %u",
                                  e.prod_id, e.build_id, e.count);
                    std::cout << ansi::grey(b) << "\n";
                }
            }
        }

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

        if (!techs.empty()) {
            section("MITRE ATT&CK");
            for (const auto& t : techs)
                std::cout << "  " << ansi::yellow(t.id) << ansi::grey(std::string(t.id.size() < 10 ? 10 - t.id.size() : 1, ' '))
                          << t.name << "\n";
        }

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
                      << (sig.status == authcode::Status::Valid
                              ? ansi::green(std::string("yes") + (sig.catalog ? " (catalog)" : ""))
                              : ansi::grey(authcode::status_label(sig.status))) << "\n";
            if (has_upx)
                std::cout << "  " << ansi::cyan("packer   ")
                          << ansi::grey("UPX (legitimate open-source packer)") << "\n";
        }

        const core::EmbeddedIocs& emb = rep.emb;
        if (!emb.urls.empty() || !emb.ips.empty() || !emb.interesting.empty()) {
            section("EMBEDDED INDICATORS  (from strings)");
            for (auto& u : emb.urls) std::cout << "  " << ansi::cyan("url ") << u << "\n";
            for (auto& ip : emb.ips) std::cout << "  " << ansi::cyan("ip  ") << ip << "\n";
            if (!emb.interesting.empty()) {
                std::string row = "  " + ansi::cyan("tokens ");
                for (auto& t : emb.interesting) row += t + "  ";
                std::cout << row << "\n";
            }
            for (const auto& record : rep.embedded_intel) {
                std::cout << "\n  " << ansi::bold(record.value) << "\n";
                for (const auto& result : record.results) print_source_result(result);
            }
        }

        if (opts.strings) {
            section("STRINGS  (showing up to 40 of " + std::to_string(rep.strs.size()) + ")");
            for (size_t i = 0; i < rep.strs.size() && i < 40; ++i)
                std::cout << "  " << ansi::grey(rep.strs[i]) << "\n";
        }

        section("BEHAVIORAL PROFILE  (UEBA)");
        if (behavior.type == ueba::Archetype::Unknown) {
            std::cout << "  " << ansi::grey("no strong archetype match") << "\n";
        } else {
            const char* arc_col = (behavior.modifier > 0) ? "\033[31;1m"
                                : (behavior.modifier < 0) ? "\033[32;1m"
                                :                           "\033[33;1m";
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
                char b[32];
                std::snprintf(b, sizeof(b), "%zu", info.total_imports);
                std::cout << "  " << ansi::grey("  import count:  ") << b << "\n";
            }
        }
    }

    if (opts.enrich) {
        section("THREAT INTELLIGENCE");
        for (const auto& result : rep.hash_intel) print_source_result(result);
        if (rep.hash_intel.empty() && rep.embedded_intel.empty())
            std::cout << "  " << ansi::grey("no provider returned a file or IOC report") << "\n";
        for (const auto& error : rep.source_errors)
            std::cout << "  " << ansi::grey(error) << "\n";
    }

    section("VERDICT");
    if (rep.has_score) {
        std::cout << "  " << verdict_badge(core::verdict_for_score(rep.final_score), rep.final_score)
                  << "   risk " << colour_score(rep.final_score) << "\n";
    } else {
        std::cout << "  " << ansi::yellow("UNKNOWN") << "   "
                  << ansi::grey(rep.error.empty() ? "no scoreable evidence" : rep.error) << "\n";
    }

    if (info.valid) {
        std::string base_line = "base score (static): " + std::to_string(rep.base_score);
        if (behavior.modifier != 0) {
            std::string adj = (behavior.modifier > 0 ? "+" : "") + std::to_string(behavior.modifier);
            base_line += "  UEBA " + adj + "  ->  adjusted: " + std::to_string(rep.static_score);
        }
        std::cout << "  " << ansi::grey(base_line) << "\n";
        if (rep.vt.ok && rep.vt.found)
            std::cout << "  " << ansi::grey("virustotal: " + rep.vt.summary) << "\n";
        if (rep.sig_penalty > 0)
            std::cout << "  " << ansi::red("! signature check failed (" + sig.status_text
                      + ") - tamper/forgery signal (+" + std::to_string(rep.sig_penalty) + ")") << "\n";
        if (has_upx && rep.final_score < 60)
            std::cout << "  " << ansi::grey("note: UPX packing is common in legitimate open-source software") << "\n";
    }

    std::cout << "\n";
    return core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.final_score);
}

// ---------------------------------------------------------------------------
//  Indicator report
// ---------------------------------------------------------------------------
inline int render_indicator(const core::Options& opts, const core::IndicatorReport& rep) {
    using namespace horus::ui;
    section("INDICATOR");
    kv("value", rep.target);
    kv("type",  ioc_type_name(rep.type));

    section("INTEL");
    if (rep.results.empty()) {
        const char* hint = opts.enrich
            ? "no configured source handles this indicator type"
            : "network enrichment was not requested (use --enrich)";
        std::cout << "  " << ansi::grey(hint) << "\n";
    }
    for (auto& r : rep.results) print_source_result(r);
    for (const auto& error : rep.source_errors)
        std::cout << "  " << ansi::grey(error) << "\n";

    section("VERDICT");
    if (rep.has_score) {
        std::cout << "  " << verdict_badge(core::verdict_for_score(rep.worst), rep.worst)
                  << "   risk " << colour_score(rep.worst) << "\n\n";
    } else {
        std::cout << "  " << ansi::yellow("UNKNOWN") << "   "
                  << ansi::grey("no provider returned scoreable evidence") << "\n\n";
    }
    return core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.worst);
}

} // namespace render
} // namespace horus
