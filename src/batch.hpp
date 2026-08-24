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
#include "output.hpp"

#include <iostream>
#include <sstream>
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
    core::AnalysisStatus status = core::AnalysisStatus::Unknown;
    bool        has_score = false;
    int         score = 0;
    std::string verdict;
    std::string error;
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
        o.enrich = false;                // batch stays local and predictable
        core::FileReport r = core::analyze_file(o);
        Row row;
        row.path    = p.string();
        row.sha256  = r.hashes.sha256;
        row.imphash = r.imphash;
        row.is_pe   = r.info.valid;
        row.status  = r.analysis_status;
        row.has_score = r.has_score;
        row.score   = r.final_score;
        row.verdict = core::verdict_name(r.has_score, r.final_score);
        row.error   = r.error;
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

    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        if (a.has_score != b.has_score) return a.has_score > b.has_score;
        if (a.score != b.score) return a.score > b.score;
        return a.path < b.path;
    });
    return rows;
}

inline std::string basename(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

inline bool write_csv(const std::vector<Row>& rows, const std::string& path,
                      std::string& error) {
    std::ostringstream out;
    out << "path,sha256,is_pe,analysis_status,score,verdict,error\n";
    for (const auto& r : rows) {
        out << output::csv_cell(r.path) << ',' << output::csv_cell(r.sha256) << ','
            << (r.is_pe ? "1" : "0") << ',' << core::analysis_status_name(r.status) << ',';
        if (r.has_score) out << r.score;
        out << ',' << output::csv_cell(r.verdict) << ',' << output::csv_cell(r.error) << "\n";
    }
    return output::write_atomic(std::filesystem::path(path), out.str(), error);
}

inline std::string rows_json(const std::vector<Row>& rows, bool pretty) {
    std::ostringstream out;
    out << (pretty ? "[\n" : "[");
    for (size_t i = 0; i < rows.size(); ++i) {
        const auto& r = rows[i];
        if (pretty) out << "  ";
        out << "{\"path\":\"" << core::json_escape(r.path) << "\""
            << ",\"sha256\":\"" << r.sha256 << "\""
            << ",\"imphash\":\"" << r.imphash << "\""
            << ",\"is_pe\":" << (r.is_pe ? "true" : "false")
            << ",\"analysis_status\":\"" << core::analysis_status_name(r.status) << "\""
            << ",\"score\":" << (r.has_score ? std::to_string(r.score) : "null")
            << ",\"verdict\":\"" << r.verdict << "\""
            << ",\"error\":\"" << core::json_escape(r.error) << "\"}"
            << (i + 1 < rows.size() ? "," : "");
        if (pretty) out << "\n";
    }
    out << (pretty ? "]\n" : "]\n");
    return out.str();
}

inline bool write_json(const std::vector<Row>& rows, const std::string& path,
                       std::string& error) {
    return output::write_atomic(std::filesystem::path(path), rows_json(rows, true), error);
}

inline int run(const core::Options& base) {
    using namespace ui;
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path root(base.scan_dir);
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        std::cerr << "error: no such directory: " << base.scan_dir << "\n";
        return 2;
    }

    std::vector<Row> rows = scan(base);

    if (base.json) {
        std::cout << rows_json(rows, false);
    } else {
        section("BATCH SCAN  (" + std::to_string(rows.size()) + " files, worst first)");
        std::cout << "  " << ansi::grey("SCORE  VERDICT           FILE") << "\n";
        int flagged = 0, incomplete = 0;
        for (const auto& r : rows) {
            if (r.has_score && r.score >= 30) ++flagged;
            if (r.status != core::AnalysisStatus::Complete) ++incomplete;
            char head[64];
            std::string shown_score = r.has_score ? std::to_string(r.score) : "-";
            std::snprintf(head, sizeof(head), "  %3s    %-16s  ", shown_score.c_str(), r.verdict.c_str());
            std::string line = head + basename(r.path);
            if (r.has_score && r.score >= 60)      std::cout << ansi::red(line)    << "\n";
            else if (r.has_score && r.score >= 30) std::cout << ansi::yellow(line) << "\n";
            else if (!r.has_score)                 std::cout << ansi::grey(line)   << "\n";
            else                    std::cout << line               << "\n";
        }
        section("SUMMARY");
        kv("scanned", std::to_string(rows.size()) + " files");
        kv("flagged", std::to_string(flagged) + ansi::grey("  (score >= 30)"));
        kv("incomplete", std::to_string(incomplete) + ansi::grey("  (unknown, skipped, or error)"));
    }

    std::string error;
    if (!base.csv_out.empty() && !write_csv(rows, base.csv_out, error)) {
        std::cerr << "error: " << error << "\n";
        return 2;
    }
    if (!base.json_out.empty() && !write_json(rows, base.json_out, error)) {
        std::cerr << "error: " << error << "\n";
        return 2;
    }

    bool incomplete = false;
    for (const auto& r : rows) {
        if (r.has_score && r.score >= 30) return 1;
        if (r.status != core::AnalysisStatus::Complete) incomplete = true;
    }
    return incomplete ? 3 : 0;
}

} // namespace batch
} // namespace horus
