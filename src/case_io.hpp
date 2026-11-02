#pragma once

#include "case_types.hpp"
#include "core.hpp"
#include "encoding.hpp"
#include "gui/case_html.hpp"
#include "json.hpp"
#include "output.hpp"

#include <windows.h>
#include <objbase.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace horus {
namespace casework {

namespace fs = std::filesystem;

inline std::string q(const std::string& s) {
    return "\"" + core::json_escape(s) + "\"";
}

inline std::string string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (size_t i = 0; i < values.size(); ++i)
        out += std::string(i ? "," : "") + q(values[i]);
    return out + "]";
}

inline std::vector<std::string> read_string_array(const json::Value& value) {
    std::vector<std::string> out;
    for (const auto& v : value.items()) if (v.is_string()) out.push_back(v.as_string());
    return out;
}

inline std::string utc_now() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

inline std::string guid(const char* prefix) {
    GUID id{};
    if (CoCreateGuid(&id) != S_OK)
        return std::string(prefix) + std::to_string(static_cast<long long>(std::time(nullptr)));
    char buf[64];
    std::snprintf(buf, sizeof(buf),
        "%s%08lx-%04x-%04x-%04x-%012llx", prefix,
        static_cast<unsigned long>(id.Data1), id.Data2, id.Data3,
        static_cast<unsigned>((id.Data4[0] << 8) | id.Data4[1]),
        (static_cast<unsigned long long>(id.Data4[2]) << 40) |
        (static_cast<unsigned long long>(id.Data4[3]) << 32) |
        (static_cast<unsigned long long>(id.Data4[4]) << 24) |
        (static_cast<unsigned long long>(id.Data4[5]) << 16) |
        (static_cast<unsigned long long>(id.Data4[6]) << 8) |
         static_cast<unsigned long long>(id.Data4[7]));
    return buf;
}

inline std::string path_binding(const fs::path& root) {
    std::error_code ec;
    std::string value = fs::weakly_canonical(root, ec).generic_string();
    if (ec) value = fs::absolute(root, ec).generic_string();
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return crypto::sha256_hex(reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

inline std::string mtime_of(const fs::path& path, std::error_code& ec) {
    auto stamp = fs::last_write_time(path, ec);
    if (ec) return {};
    return std::to_string(stamp.time_since_epoch().count());
}

inline std::string shown_status(const Sample& sample) {
    return sample.missing ? "missing" : sample.status;
}

inline std::string sample_state_json(const Sample& s) {
    std::string out = "{";
    out += "\"path\":" + q(s.path);
    out += ",\"size\":" + std::to_string(s.size);
    out += ",\"mtime\":" + q(s.mtime);
    out += std::string(",\"missing\":") + (s.missing ? "true" : "false");
    out += ",\"status\":" + q(s.status);
    out += ",\"error\":" + q(s.error);
    out += ",\"md5\":" + q(s.md5) + ",\"sha1\":" + q(s.sha1) +
           ",\"sha256\":" + q(s.sha256) + ",\"tlsh\":" + q(s.tlsh) +
           ",\"ssdeep\":" + q(s.ssdeep);
    out += std::string(",\"is_pe\":") + (s.is_pe ? "true" : "false");
    out += ",\"imphash\":" + q(s.imphash) + ",\"rich_hash\":" + q(s.rich_hash) +
           ",\"section_fingerprint\":" + q(s.section_fingerprint);
    out += ",\"capabilities\":" + string_array(s.capabilities);
    out += ",\"attack\":" + string_array(s.attack);
    out += ",\"urls\":" + string_array(s.urls) + ",\"ips\":" + string_array(s.ips);
    out += std::string(",\"has_score\":") + (s.has_score ? "true" : "false");
    out += ",\"static_score\":" + std::to_string(s.static_score);
    out += ",\"score\":" + std::to_string(s.score) + ",\"verdict\":" + q(s.verdict);
    out += ",\"intel_summary\":" + q(s.intel_summary);
    out += ",\"duplicate_id\":" + q(s.duplicate_id) + ",\"cluster_id\":" + q(s.cluster_id);
    return out + "}";
}

inline std::string cluster_json(const Cluster& c) {
    std::string out = "{\"id\":" + q(c.id) + ",\"representative\":" + q(c.representative) +
                      ",\"members\":[";
    for (size_t i = 0; i < c.members.size(); ++i) {
        const auto& m = c.members[i];
        out += std::string(i ? "," : "") + "{\"sha256\":" + q(m.sha256) +
               ",\"similarity\":" + std::to_string(m.similarity) +
               ",\"evidence\":" + string_array(m.evidence) + "}";
    }
    return out + "]}";
}

inline std::string ioc_json(const IocRecord& r) {
    return "{\"value\":" + q(r.value) + ",\"type\":" + q(r.type) +
           ",\"paths\":" + string_array(r.paths) +
           ",\"lookup_status\":" + q(r.lookup_status) +
           ",\"ok\":" + (r.ok ? std::string("true") : std::string("false")) +
           ",\"found\":" + (r.found ? std::string("true") : std::string("false")) +
           ",\"score\":" + std::to_string(r.score) +
           ",\"summary\":" + q(r.summary) + ",\"error\":" + q(r.error) + "}";
}

inline std::string state_json(const State& state) {
    std::string out = "{\n";
    out += "  \"schema\": 1,\n";
    out += "  \"id\": " + q(state.id) + ",\n";
    out += "  \"name\": " + q(state.name) + ",\n";
    out += "  \"root_binding\": " + q(state.root_binding) + ",\n";
    out += "  \"created\": " + q(state.created) + ",\n";
    out += "  \"updated\": " + q(state.updated) + ",\n";
    out += "  \"run_count\": " + std::to_string(state.run_count) + ",\n";
    out += "  \"samples\": [\n";
    for (size_t i = 0; i < state.samples.size(); ++i)
        out += "    " + sample_state_json(state.samples[i]) +
               (i + 1 < state.samples.size() ? "," : "") + "\n";
    out += "  ],\n  \"clusters\": [";
    for (size_t i = 0; i < state.clusters.size(); ++i)
        out += std::string(i ? "," : "") + cluster_json(state.clusters[i]);
    out += "],\n  \"iocs\": [";
    for (size_t i = 0; i < state.iocs.size(); ++i)
        out += std::string(i ? "," : "") + ioc_json(state.iocs[i]);
    out += "]\n}\n";
    return out;
}

inline Sample read_sample(const json::Value& v) {
    Sample s;
    s.path = v["path"].as_string();
    s.size = static_cast<uint64_t>(v["size"].as_int());
    s.mtime = v["mtime"].as_string();
    s.missing = v["missing"].as_bool();
    s.status = v["status"].as_string("unknown");
    s.error = v["error"].as_string();
    s.md5 = v["md5"].as_string();
    s.sha1 = v["sha1"].as_string();
    s.sha256 = v["sha256"].as_string();
    s.tlsh = v["tlsh"].as_string();
    s.ssdeep = v["ssdeep"].as_string();
    s.is_pe = v["is_pe"].as_bool();
    s.imphash = v["imphash"].as_string();
    s.rich_hash = v["rich_hash"].as_string();
    s.section_fingerprint = v["section_fingerprint"].as_string();
    s.capabilities = read_string_array(v["capabilities"]);
    s.attack = read_string_array(v["attack"]);
    s.urls = read_string_array(v["urls"]);
    s.ips = read_string_array(v["ips"]);
    s.has_score = v["has_score"].as_bool();
    s.static_score = static_cast<int>(v["static_score"].as_int());
    s.score = static_cast<int>(v["score"].as_int());
    s.verdict = v["verdict"].as_string("UNKNOWN");
    s.intel_summary = v["intel_summary"].as_string();
    s.duplicate_id = v["duplicate_id"].as_string();
    s.cluster_id = v["cluster_id"].as_string();
    return s;
}

inline Cluster read_cluster(const json::Value& v) {
    Cluster c;
    c.id = v["id"].as_string();
    c.representative = v["representative"].as_string();
    for (const auto& mv : v["members"].items()) {
        ClusterMember m;
        m.sha256 = mv["sha256"].as_string();
        m.similarity = static_cast<int>(mv["similarity"].as_int(100));
        m.evidence = read_string_array(mv["evidence"]);
        c.members.push_back(std::move(m));
    }
    return c;
}

inline IocRecord read_ioc(const json::Value& v) {
    IocRecord r;
    r.value = v["value"].as_string();
    r.type = v["type"].as_string();
    r.paths = read_string_array(v["paths"]);
    r.lookup_status = v["lookup_status"].as_string("not_requested");
    r.ok = v["ok"].as_bool();
    r.found = v["found"].as_bool();
    r.score = static_cast<int>(v["score"].as_int());
    r.summary = v["summary"].as_string();
    r.error = v["error"].as_string();
    return r;
}

inline bool load_state(const fs::path& path, State& state, bool& exists,
                       std::string& error) {
    exists = fs::exists(path);
    if (!exists) return true;
    std::ifstream f(path, std::ios::binary);
    if (!f) { error = "cannot read existing case state"; return false; }
    std::ostringstream ss; ss << f.rdbuf();
    try {
        auto doc = json::parse(ss.str());
        if (doc["schema"].as_int() != 1) {
            error = "unsupported case state schema";
            return false;
        }
        state.schema = 1;
        state.id = doc["id"].as_string();
        state.name = doc["name"].as_string();
        state.root_binding = doc["root_binding"].as_string();
        state.created = doc["created"].as_string();
        state.updated = doc["updated"].as_string();
        state.run_count = static_cast<int>(doc["run_count"].as_int());
        for (const auto& v : doc["samples"].items()) state.samples.push_back(read_sample(v));
        for (const auto& v : doc["clusters"].items()) state.clusters.push_back(read_cluster(v));
        for (const auto& v : doc["iocs"].items()) state.iocs.push_back(read_ioc(v));
        if (state.id.empty()) { error = "case state has no id"; return false; }
        return true;
    } catch (const std::exception& e) {
        error = std::string("invalid case state: ") + e.what();
        return false;
    }
}

inline std::string public_json(const RunResult& run, const core::Options& opts) {
    size_t complete = 0, unknown = 0, skipped = 0, errors = 0, missing = 0, flagged = 0;
    for (const auto& s : run.state.samples) {
        const std::string status = shown_status(s);
        if (status == "complete") ++complete;
        else if (status == "unknown") ++unknown;
        else if (status == "skipped") ++skipped;
        else if (status == "error") ++errors;
        else if (status == "missing") ++missing;
        if (!s.missing && s.has_score && s.score >= 30) ++flagged;
    }

    std::string out = "{\n";
    out += "  \"schema\": \"horus-case/v1\",\n  \"kind\": \"case\",\n";
    out += "  \"case\": {\"id\":" + q(run.state.id) + ",\"name\":" + q(run.state.name) +
           ",\"created\":" + q(run.state.created) + ",\"updated\":" + q(run.state.updated) +
           ",\"run\":" + std::to_string(run.state.run_count) + "},\n";
    out += "  \"settings\": {\"cluster_mode\":" + q(opts.cluster_mode) +
           ",\"recursive\":" + (opts.recurse ? std::string("true") : std::string("false")) +
           ",\"enriched\":" + (opts.enrich ? std::string("true") : std::string("false")) +
           ",\"max_file_mb\":" + std::to_string(opts.max_file_mb) + "},\n";
    out += "  \"summary\": {\"total\":" + std::to_string(run.state.samples.size()) +
           ",\"complete\":" + std::to_string(complete) +
           ",\"unknown\":" + std::to_string(unknown) +
           ",\"skipped\":" + std::to_string(skipped) +
           ",\"errors\":" + std::to_string(errors) +
           ",\"missing\":" + std::to_string(missing) +
           ",\"flagged\":" + std::to_string(flagged) +
           ",\"duplicates\":" + std::to_string(run.duplicates.size()) +
           ",\"clusters\":" + std::to_string(run.clusters.size()) +
           ",\"analyzed\":" + std::to_string(run.analyzed) +
           ",\"reused\":" + std::to_string(run.reused) +
           ",\"live_lookups\":" + std::to_string(run.live_lookups) +
           ",\"cache_hits\":" + std::to_string(run.cache_hits) +
           ",\"changes\":" + std::to_string(run.changes.size()) + "},\n";

    out += "  \"changes\": [";
    for (size_t i = 0; i < run.changes.size(); ++i) {
        const auto& c = run.changes[i];
        auto side = [](bool present, const std::string& sha256, const std::string& status,
                       bool has_score, int score) {
            if (!present) return std::string("null");
            return std::string("{\"sha256\":") + q(sha256) +
                   ",\"status\":" + q(status) +
                   ",\"score\":" + (has_score ? std::to_string(score) : "null") + "}";
        };
        out += std::string(i ? "," : "") + "{\"kind\":" + q(c.kind) +
               ",\"path\":" + q(c.path) +
               ",\"before\":" + side(c.has_before, c.before_sha256, c.before_status,
                                        c.before_has_score, c.before_score) +
               ",\"after\":" + side(c.has_after, c.after_sha256, c.after_status,
                                       c.after_has_score, c.after_score) + "}";
    }
    out += "],\n";

    out += "  \"samples\": [\n";
    for (size_t i = 0; i < run.state.samples.size(); ++i) {
        const auto& s = run.state.samples[i];
        out += "    {\"path\":" + q(s.path) + ",\"size\":" + std::to_string(s.size) +
               ",\"analysis_status\":" + q(shown_status(s)) +
               ",\"error\":" + q(s.error) +
               ",\"is_pe\":" + (s.is_pe ? std::string("true") : std::string("false")) +
               ",\"score\":" + (s.has_score ? std::to_string(s.score) : std::string("null")) +
               ",\"static_score\":" + (s.is_pe ? std::to_string(s.static_score) : std::string("null")) +
               ",\"verdict\":" + q(s.verdict) +
               ",\"hashes\":{\"md5\":" + q(s.md5) + ",\"sha1\":" + q(s.sha1) +
               ",\"sha256\":" + q(s.sha256) + ",\"tlsh\":" + q(s.tlsh) +
               ",\"ssdeep\":" + q(s.ssdeep) + "}" +
               ",\"features\":{\"imphash\":" + q(s.imphash) + ",\"rich_hash\":" + q(s.rich_hash) +
               ",\"section_fingerprint\":" + q(s.section_fingerprint) + "}" +
               ",\"capabilities\":" + string_array(s.capabilities) +
               ",\"attack\":" + string_array(s.attack) +
               ",\"embedded\":{\"urls\":" + string_array(s.urls) + ",\"ips\":" + string_array(s.ips) + "}" +
               ",\"intel_summary\":" + q(s.intel_summary) +
               ",\"duplicate_id\":" + q(s.duplicate_id) +
               ",\"cluster_id\":" + q(s.cluster_id) + "}" +
               (i + 1 < run.state.samples.size() ? "," : "") + "\n";
    }
    out += "  ],\n  \"duplicates\": [";
    for (size_t i = 0; i < run.duplicates.size(); ++i) {
        const auto& d = run.duplicates[i];
        out += std::string(i ? "," : "") + "{\"id\":" + q(d.id) +
               ",\"sha256\":" + q(d.sha256) + ",\"paths\":" + string_array(d.paths) + "}";
    }
    out += "],\n  \"clusters\": [";
    for (size_t i = 0; i < run.clusters.size(); ++i)
        out += std::string(i ? "," : "") + cluster_json(run.clusters[i]);
    out += "],\n  \"iocs\": [";
    for (size_t i = 0; i < run.iocs.size(); ++i) {
        const auto& r = run.iocs[i];
        out += std::string(i ? "," : "") + ioc_json(r);
    }
    out += "]\n}\n";
    return out;
}

inline std::string join(const std::vector<std::string>& values, const char* separator) {
    std::string out;
    for (size_t i = 0; i < values.size(); ++i) out += (i ? separator : "") + values[i];
    return out;
}

inline std::string samples_csv(const RunResult& run) {
    std::string out = "path,sha256,is_pe,analysis_status,score,verdict,duplicate_id,cluster_id,error\r\n";
    for (const auto& s : run.state.samples)
        out += output::csv_cell(s.path) + "," + output::csv_cell(s.sha256) + "," +
               (s.is_pe ? "1" : "0") + "," + output::csv_cell(shown_status(s)) + "," +
               (s.has_score ? std::to_string(s.score) : "") + "," +
               output::csv_cell(s.verdict) + "," + output::csv_cell(s.duplicate_id) + "," +
               output::csv_cell(s.cluster_id) + "," +
               output::csv_cell(s.error) + "\r\n";
    return out;
}

inline std::string clusters_csv(const RunResult& run) {
    std::map<std::string, std::vector<std::string>> paths;
    for (const auto& s : run.state.samples) if (!s.missing) paths[s.sha256].push_back(s.path);
    std::string out = "cluster_id,representative_sha256,member_sha256,paths,similarity,evidence\r\n";
    for (const auto& c : run.clusters)
        for (const auto& m : c.members)
            out += output::csv_cell(c.id) + "," + output::csv_cell(c.representative) + "," +
                   output::csv_cell(m.sha256) + "," +
                   output::csv_cell(join(paths[m.sha256], " | ")) + "," + std::to_string(m.similarity) + "," +
                   output::csv_cell(join(m.evidence, " | ")) + "\r\n";
    return out;
}

inline std::string iocs_csv(const RunResult& run) {
    std::string out = "type,value,paths,lookup_status,found,score,summary,error\r\n";
    for (const auto& r : run.iocs)
        out += output::csv_cell(r.type) + "," + output::csv_cell(r.value) + "," +
               output::csv_cell(join(r.paths, " | ")) + "," + output::csv_cell(r.lookup_status) + "," +
               (r.found ? "1" : "0") + "," + std::to_string(r.score) + "," +
               output::csv_cell(r.summary) + "," + output::csv_cell(r.error) + "\r\n";
    return out;
}

inline std::string changes_csv(const RunResult& run) {
    std::string out = "kind,path,before_sha256,after_sha256,before_status,after_status,before_score,after_score\r\n";
    for (const auto& c : run.changes) {
        out += output::csv_cell(c.kind) + "," + output::csv_cell(c.path) + "," +
               output::csv_cell(c.before_sha256) + "," + output::csv_cell(c.after_sha256) + "," +
               output::csv_cell(c.before_status) + "," + output::csv_cell(c.after_status) + "," +
               (c.before_has_score ? std::to_string(c.before_score) : "") + "," +
               (c.after_has_score ? std::to_string(c.after_score) : "") + "\r\n";
    }
    return out;
}

inline std::string report_html(const std::string& document) {
    std::string html(gui::kCaseHtml, gui::kCaseHtmlSize);
    const std::string marker = "__HORUS_CASE_B64__";
    size_t at = html.find(marker);
    if (at != std::string::npos) html.replace(at, marker.size(), encoding::base64(document));
    return html;
}

inline bool write_outputs(RunResult& run, const core::Options& opts, std::string& error) {
    fs::path workspace(run.workspace);
    std::error_code ec;
    fs::create_directories(workspace / ".horus", ec);
    if (ec) { error = "cannot create case workspace: " + ec.message(); return false; }

    run.public_json = public_json(run, opts);
    run.report_path = (workspace / "report.html").string();
    if (!output::write_atomic(workspace / "case.json", run.public_json, error)) return false;
    if (!output::write_atomic(workspace / "samples.csv", samples_csv(run), error)) return false;
    if (!output::write_atomic(workspace / "clusters.csv", clusters_csv(run), error)) return false;
    if (!output::write_atomic(workspace / "iocs.csv", iocs_csv(run), error)) return false;
    if (!output::write_atomic(workspace / "changes.csv", changes_csv(run), error)) return false;
    if (!output::write_atomic(workspace / "report.html", report_html(run.public_json), error)) return false;
    if (!output::write_atomic(workspace / ".horus" / "state.json", state_json(run.state), error)) return false;
    return true;
}

} // namespace casework
} // namespace horus
