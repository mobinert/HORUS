// ---------------------------------------------------------------------------
//  batch.hpp  -  point it at a folder, get a triage table back
//
//  Walks a directory, scores every file, sorts worst-first. Optional CSV / JSON
//  dumps for feeding a ticket or the GUI grid. Local static analysis only - it
//  deliberately doesn't fire VT for every file and drain your quota.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "console.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>

namespace horus {
namespace batch {

struct Row {
    std::string path;
    std::string sha256;
    std::string imphash;
    bool        is_pe = false;
    int         score = 0;
    std::string verdict;
};

inline std::vector<Row> scan(const core::Options& base) {
    namespace fs = std::filesystem;
    std::vector<Row> rows;
    std::error_code ec;
    fs::path root(base.scan_dir);
    if (!fs::exists(root, ec)) return rows;

    auto handle = [&](const fs::path& p) {
        core::Options o = base;
        o.target = p.string();
        o.vt_key.clear();               // static-only per file
        core::FileReport r = core::analyze_file(o);
        if (!r.ok) return;
        Row row;
        row.path    = p.string();
        row.sha256  = r.hashes.sha256;
        row.imphash = r.imphash;
        row.is_pe   = r.info.valid;
        row.score   = r.final_score;
        row.verdict = core::verdict_for_score(r.final_score);
        rows.push_back(std::move(row));
    };

    if (base.recurse) {
        for (auto it = fs::recursive_directory_iterator(
                 root, fs::directory_options::skip_permission_denied, ec);
             !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (it->is_regular_file(ec)) handle(it->path());
        }
    } else {
        for (auto& de : fs::directory_iterator(root, ec))
            if (!ec && de.is_regular_file(ec)) handle(de.path());
    }

    std::sort(rows.begin(), rows.end(),
              [](const Row& a, const Row& b){ return a.score > b.score; });
    return rows;
}

inline std::string basename(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

inline void write_csv(const std::vector<Row>& rows, const std::string& path) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << "path,sha256,is_pe,score,verdict\n";
    for (const auto& r : rows) {
        std::string p = r.path;
        bool q = p.find(',') != std::string::npos || p.find('"') != std::string::npos;
        if (q) { std::string e = "\""; for (char c : p) { if (c=='"') e += '"'; e += c; } e += '"'; p = e; }
        f << p << "," << r.sha256 << "," << (r.is_pe ? "1" : "0") << ","
          << r.score << "," << r.verdict << "\n";
    }
}

inline void write_json(const std::vector<Row>& rows, const std::string& path) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << "[\n";
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& r = rows[i];
        f << "  {\"path\":\"" << core::json_escape(r.path) << "\""
          << ",\"sha256\":\"" << r.sha256 << "\""
          << ",\"imphash\":\"" << r.imphash << "\""
          << ",\"is_pe\":" << (r.is_pe ? "true" : "false")
          << ",\"score\":" << r.score
          << ",\"verdict\":\"" << r.verdict << "\"}"
          << (i + 1 < rows.size() ? "," : "") << "\n";
    }
    f << "]\n";
}

inline int run(const core::Options& base) {
    using namespace ui;
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(fs::path(base.scan_dir), ec)) {
        std::cerr << "error: no such directory: " << base.scan_dir << "\n";
        return 2;
    }

    std::vector<Row> rows = scan(base);

    if (base.json) { std::cout << "["; /* compact */
        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            std::cout << (i?",":"") << "{\"path\":\"" << core::json_escape(r.path)
                      << "\",\"sha256\":\"" << r.sha256 << "\",\"is_pe\":" << (r.is_pe?"true":"false")
                      << ",\"score\":" << r.score << ",\"verdict\":\"" << r.verdict << "\"}";
        }
        std::cout << "]\n";
    } else {
        section("BATCH SCAN  (" + std::to_string(rows.size()) + " files, worst first)");
        std::cout << "  " << ansi::grey("SCORE  VERDICT           FILE") << "\n";
        int flagged = 0;
        for (const auto& r : rows) {
            if (r.score >= 30) ++flagged;
            char head[64];
            std::snprintf(head, sizeof(head), "  %3d    %-16s  ", r.score, r.verdict.c_str());
            std::string line = head + basename(r.path);
            if (r.score >= 60)      std::cout << ansi::red(line)    << "\n";
            else if (r.score >= 30) std::cout << ansi::yellow(line) << "\n";
            else                    std::cout << line               << "\n";
        }
        section("SUMMARY");
        kv("scanned", std::to_string(rows.size()) + " files");
        kv("flagged", std::to_string(flagged) + ansi::grey("  (score >= 30)"));
    }

    if (!base.csv_out.empty())  write_csv(rows, base.csv_out);
    if (!base.json_out.empty()) write_json(rows, base.json_out);

    int worst = 0;
    for (const auto& r : rows) worst = std::max(worst, r.score);
    return worst >= 30 ? 1 : 0;
}

} // namespace batch
} // namespace horus
