#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace horus {
namespace casework {

struct Sample {
    std::string path;
    uint64_t size = 0;
    std::string mtime;
    bool missing = false;
    std::string status = "unknown";
    std::string error;

    std::string md5;
    std::string sha1;
    std::string sha256;
    std::string tlsh;
    std::string ssdeep;
    bool is_pe = false;
    std::string imphash;
    std::string rich_hash;
    std::string section_fingerprint;
    std::vector<std::string> capabilities;
    std::vector<std::string> attack;
    std::vector<std::string> urls;
    std::vector<std::string> ips;

    bool has_score = false;
    int static_score = 0;
    int score = 0;
    std::string verdict = "UNKNOWN";
    std::string intel_summary;
    std::string duplicate_id;
    std::string cluster_id;
};

struct DuplicateGroup {
    std::string id;
    std::string sha256;
    std::vector<std::string> paths;
};

struct ClusterMember {
    std::string sha256;
    int similarity = 100;
    std::vector<std::string> evidence;
};

struct Cluster {
    std::string id;
    std::string representative;
    std::vector<ClusterMember> members;
};

struct IocRecord {
    std::string value;
    std::string type;
    std::vector<std::string> paths;
    std::string lookup_status = "not_requested";
    bool ok = false;
    bool found = false;
    int score = 0;
    std::string summary;
    std::string error;
};

struct State {
    int schema = 1;
    std::string id;
    std::string name;
    std::string root_binding;
    std::string created;
    std::string updated;
    int run_count = 0;
    std::vector<Sample> samples;
    std::vector<Cluster> clusters;
    std::vector<IocRecord> iocs;
};

struct RunResult {
    State state;
    std::vector<DuplicateGroup> duplicates;
    std::vector<Cluster> clusters;
    std::vector<IocRecord> iocs;
    std::string workspace;
    std::string report_path;
    std::string public_json;
    size_t analyzed = 0;
    size_t reused = 0;
    size_t live_lookups = 0;
    size_t cache_hits = 0;
};

} // namespace casework
} // namespace horus
