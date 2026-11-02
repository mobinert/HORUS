// ---------------------------------------------------------------------------
//  diff.hpp  -  side-by-side compare of two PEs
//
//  Compare two samples without uploading either one: imphash match, TLSH
//  distance, rich-header match, section entropy drift, and verdicts.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "console.hpp"
#include "fuzzy.hpp"

#include <iostream>
#include <string>
#include <algorithm>
#include <iomanip>
#include <locale>
#include <sstream>

namespace horus {
namespace diffs {

inline core::AnalysisStatus comparison_status(const core::FileReport& a,
                                              const core::FileReport& b) {
    if (a.analysis_status == core::AnalysisStatus::Skipped ||
        b.analysis_status == core::AnalysisStatus::Skipped)
        return core::AnalysisStatus::Skipped;
    if (a.info.valid && b.info.valid &&
        a.analysis_status == core::AnalysisStatus::Complete &&
        b.analysis_status == core::AnalysisStatus::Complete)
        return core::AnalysisStatus::Complete;
    return core::AnalysisStatus::Unknown;
}

inline int comparison_exit_code(const core::FileReport& a, const core::FileReport& b) {
    if (!a.ok || !b.ok) return 2;
    if (comparison_status(a, b) != core::AnalysisStatus::Complete) return 3;
    if ((a.has_score && a.final_score >= 30) ||
        (b.has_score && b.final_score >= 30)) return 1;
    return 0;
}

inline std::string nullable_string(const std::string& value) {
    return value.empty() ? "null" : "\"" + core::json_escape(value) + "\"";
}

inline std::string json_number(double value) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(8) << value;
    return out.str();
}

inline std::string file_json(const std::string& path, const core::FileReport& report) {
    std::ostringstream out;
    out << "{\"path\":\"" << core::json_escape(path) << "\""
        << ",\"analysis_status\":\"" << core::analysis_status_name(report.analysis_status) << "\""
        << ",\"error\":" << nullable_string(report.error)
        << ",\"size\":" << report.size
        << ",\"sha256\":" << nullable_string(report.hashes.sha256)
        << ",\"is_pe\":" << (report.info.valid ? "true" : "false")
        << ",\"imphash\":" << nullable_string(report.imphash)
        << ",\"rich_hash\":" << nullable_string(report.rich_hash)
        << ",\"tlsh\":" << nullable_string(report.tlsh)
        << ",\"score\":" << (report.has_score ? std::to_string(report.final_score) : "null")
        << ",\"verdict\":\"" << core::verdict_name(report.has_score, report.final_score) << "\"}";
    return out.str();
}

inline std::string comparison_json(const std::string& pa, const std::string& pb,
                                   const core::FileReport& a, const core::FileReport& b) {
    std::ostringstream out;
    out << "{\"kind\":\"diff\",\"analysis_status\":\""
        << core::analysis_status_name(comparison_status(a, b)) << "\""
        << ",\"file_a\":" << file_json(pa, a)
        << ",\"file_b\":" << file_json(pb, b)
        << ",\"comparison\":{\"sha256_match\":";
    if (!a.hashes.sha256.empty() && !b.hashes.sha256.empty())
        out << (a.hashes.sha256 == b.hashes.sha256 ? "true" : "false");
    else out << "null";
    out << ",\"imphash_match\":";
    if (a.info.valid && b.info.valid && !a.imphash.empty() && !b.imphash.empty())
        out << (a.imphash == b.imphash ? "true" : "false");
    else out << "null";
    out << ",\"rich_hash_match\":";
    if (a.info.valid && b.info.valid && (!a.rich_hash.empty() || !b.rich_hash.empty()))
        out << (a.rich_hash == b.rich_hash ? "true" : "false");
    else out << "null";
    out << ",\"tlsh_distance\":";
    if (a.info.valid && b.info.valid && !a.tlsh.empty() && !b.tlsh.empty()) {
        int distance = fuzzy::tlsh_diff(a.tlsh, b.tlsh);
        if (distance >= 0) out << distance; else out << "null";
    } else out << "null";
    out << ",\"sections\":[";
    if (a.info.valid && b.info.valid) {
        std::vector<std::string> names;
        for (const auto& section : a.info.sections) names.push_back(section.name);
        for (const auto& section : b.info.sections)
            if (std::find(names.begin(), names.end(), section.name) == names.end())
                names.push_back(section.name);
        auto find_sec = [](const pe::Info& info, const std::string& name) -> const pe::Section* {
            for (const auto& section : info.sections)
                if (section.name == name) return &section;
            return nullptr;
        };
        for (size_t i = 0; i < names.size(); ++i) {
            const pe::Section* sa = find_sec(a.info, names[i]);
            const pe::Section* sb = find_sec(b.info, names[i]);
            if (i) out << ',';
            out << "{\"name\":\"" << core::json_escape(names[i]) << "\""
                << ",\"entropy_a\":" << (sa ? json_number(sa->entropy) : "null")
                << ",\"entropy_b\":" << (sb ? json_number(sb->entropy) : "null")
                << ",\"drift\":" << ((sa && sb) ? json_number(sb->entropy - sa->entropy) : "null")
                << '}';
        }
    }
    out << "]}}\n";
    return out.str();
}

inline std::string yn(bool same) {
    using namespace ui;
    return same ? ansi::green("same") : ansi::yellow("differ");
}

inline int run(const core::Options& base, const std::string& pa, const std::string& pb) {
    using namespace ui;

    core::Options oa = base; oa.target = pa; oa.enrich = false;
    core::Options ob = base; ob.target = pb; ob.enrich = false;

    core::FileReport A = core::analyze_file(oa);
    core::FileReport B = core::analyze_file(ob);
    if (!A.ok) { std::cerr << "error: " << A.error << "\n"; return 2; }
    if (!B.ok) { std::cerr << "error: " << B.error << "\n"; return 2; }

    if (base.json) {
        std::cout << comparison_json(pa, pb, A, B);
        return comparison_exit_code(A, B);
    }

    section("DIFF");
    kv("file A", pa);
    kv("file B", pb);

    section("IDENTITY");
    bool has_sha = !A.hashes.sha256.empty() && !B.hashes.sha256.empty();
    bool same_sha = has_sha && A.hashes.sha256 == B.hashes.sha256;
    kv("sha256", !has_sha ? ansi::yellow("unavailable") :
                  same_sha ? ansi::green("identical files") : ansi::yellow("different bytes"));
    kv("size",    std::to_string(A.size) + "  vs  " + std::to_string(B.size) + " bytes");

    if (A.info.valid && B.info.valid) {
        bool same_imp = !A.imphash.empty() && A.imphash == B.imphash;
        kv("imphash", A.imphash.empty() || B.imphash.empty()
                        ? ansi::yellow("unavailable")
                        : yn(same_imp) + ansi::grey("   " + A.imphash + "  /  " + B.imphash));

        if (!A.rich_hash.empty() || !B.rich_hash.empty())
            kv("rich hash", yn(A.rich_hash == B.rich_hash));

        if (!A.tlsh.empty() && !B.tlsh.empty()) {
            int d = fuzzy::tlsh_diff(A.tlsh, B.tlsh);
            if (d >= 0) {
                std::string note = d == 0   ? ansi::green("0 (identical)")
                                 : d < 40    ? ansi::green(std::to_string(d) + " (near-identical / strongly related)")
                                 : d < 120   ? ansi::yellow(std::to_string(d) + " (related)")
                                 :             ansi::grey(std::to_string(d) + " (unrelated)");
                kv("TLSH dist", note);
            }
        }
    }

    // section entropy drift, matched by name
    if (A.info.valid && B.info.valid) {
        section("SECTIONS  (entropy A -> B)");
        auto find_sec = [](const pe::Info& I, const std::string& n) -> const pe::Section* {
            for (const auto& s : I.sections) if (s.name == n) return &s;
            return nullptr;
        };
        std::vector<std::string> names;
        for (const auto& s : A.info.sections) names.push_back(s.name);
        for (const auto& s : B.info.sections)
            if (std::find(names.begin(), names.end(), s.name) == names.end()) names.push_back(s.name);

        for (const auto& n : names) {
            const pe::Section* sa = find_sec(A.info, n);
            const pe::Section* sb = find_sec(B.info, n);
            char line[128];
            if (sa && sb) {
                double drift = sb->entropy - sa->entropy;
                std::snprintf(line, sizeof(line), "  %-9s %.2f -> %.2f  (%+.2f)",
                              n.c_str(), sa->entropy, sb->entropy, drift);
                std::string out = line;
                std::cout << (std::abs(drift) >= 0.5 ? ansi::yellow(out) : out) << "\n";
            } else {
                std::snprintf(line, sizeof(line), "  %-9s %s", n.c_str(),
                              sa ? "only in A" : "only in B");
                std::cout << ansi::grey(line) << "\n";
            }
        }
    }

    section("VERDICT");
    auto print_verdict = [](const char* label, const core::FileReport& report) {
        if (report.has_score)
            std::cout << "  " << label << "  "
                      << verdict_badge(core::verdict_for_score(report.final_score), report.final_score)
                      << "   risk " << colour_score(report.final_score) << "\n";
        else
            std::cout << "  " << label << "  " << ansi::yellow("UNKNOWN")
                      << "   risk n/a\n";
    };
    print_verdict("A", A);
    print_verdict("B", B);
    kv("comparison", core::analysis_status_name(comparison_status(A, B)));
    std::cout << "\n";
    return comparison_exit_code(A, B);
}

} // namespace diffs
} // namespace horus
