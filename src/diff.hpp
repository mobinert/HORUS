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

namespace horus {
namespace diffs {

inline std::string yn(bool same) {
    using namespace ui;
    return same ? ansi::green("same") : ansi::yellow("differ");
}

inline int run(const core::Options& base, const std::string& pa, const std::string& pb) {
    using namespace ui;

    core::Options oa = base; oa.target = pa; oa.vt_key.clear();
    core::Options ob = base; ob.target = pb; ob.vt_key.clear();

    core::FileReport A = core::analyze_file(oa);
    core::FileReport B = core::analyze_file(ob);
    if (!A.ok) { std::cerr << "error: " << A.error << "\n"; return 2; }
    if (!B.ok) { std::cerr << "error: " << B.error << "\n"; return 2; }

    section("DIFF");
    kv("file A", pa);
    kv("file B", pb);

    section("IDENTITY");
    bool same_sha = !A.hashes.sha256.empty() && A.hashes.sha256 == B.hashes.sha256;
    kv("sha256",  same_sha ? ansi::green("identical files") : ansi::yellow("different bytes"));
    kv("size",    std::to_string(A.size) + "  vs  " + std::to_string(B.size) + " bytes");

    if (A.info.valid && B.info.valid) {
        bool same_imp = !A.imphash.empty() && A.imphash == B.imphash;
        kv("imphash", yn(same_imp) + ansi::grey("   " + A.imphash + "  /  " + B.imphash));

        if (!A.rich_hash.empty() || !B.rich_hash.empty())
            kv("rich hash", yn(A.rich_hash == B.rich_hash));

        if (!A.tlsh.empty() && !B.tlsh.empty()) {
            int d = fuzzy::tlsh_diff(A.tlsh, B.tlsh);
            std::string note = d == 0   ? ansi::green("0 (identical)")
                             : d < 40    ? ansi::green(std::to_string(d) + " (near-identical / strongly related)")
                             : d < 120   ? ansi::yellow(std::to_string(d) + " (related)")
                             :             ansi::grey(std::to_string(d) + " (unrelated)");
            kv("TLSH dist", note);
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
    std::cout << "  A  " << verdict_badge(core::verdict_for_score(A.final_score), A.final_score)
              << "   risk " << colour_score(A.final_score) << "\n";
    std::cout << "  B  " << verdict_badge(core::verdict_for_score(B.final_score), B.final_score)
              << "   risk " << colour_score(B.final_score) << "\n\n";
    return 0;
}

} // namespace diffs
} // namespace horus
