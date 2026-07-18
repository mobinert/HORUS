// ---------------------------------------------------------------------------
//  cache.hpp  -  a tiny on-disk cache for intel lookups (~/.horus-cache.json)
//
//  VT / AbuseIPDB answers don't change second to second, and the free tiers are
//  stingy. When a TTL is configured we remember what a source said about an
//  indicator and serve it straight back until it goes stale - repeat lookups are
//  instant and cost zero quota.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "intel.hpp"
#include "json.hpp"

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <ctime>
#include <algorithm>

namespace horus {
namespace cache {

inline std::string cache_path() {
    std::string h = core::get_env("USERPROFILE");
    if (h.empty()) h = core::get_env("HOME");
    return h.empty() ? std::string(".horus-cache.json") : h + "\\.horus-cache.json";
}

inline long long now_epoch() { return (long long)std::time(nullptr); }

inline std::string keyof(const std::string& indicator) {
    std::string k = indicator;
    std::transform(k.begin(), k.end(), k.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    return k;
}

struct Entry {
    long long ts = 0;
    std::vector<intel::SourceResult> results;
};

using Store = std::map<std::string, Entry>;

inline Store load(const std::string& path) {
    Store m;
    std::ifstream f(path, std::ios::binary);
    if (!f) return m;
    std::stringstream ss; ss << f.rdbuf();
    try {
        auto doc = json::parse(ss.str());
        for (auto& kv : doc.members()) {
            Entry e;
            e.ts = kv.second["ts"].as_int(0);
            for (auto& rv : kv.second["results"].items()) {
                intel::SourceResult r;
                r.source    = rv["source"].as_string();
                r.ok        = rv["ok"].as_bool();
                r.found     = rv["found"].as_bool();
                r.summary   = rv["summary"].as_string();
                r.malicious = (int)rv["malicious"].as_int(-1);
                r.total     = (int)rv["total"].as_int(-1);
                r.score     = (int)rv["score"].as_int(-1);
                r.error     = rv["error"].as_string();
                for (auto& dv : rv["details"].items())
                    r.details.push_back({dv["k"].as_string(), dv["v"].as_string()});
                e.results.push_back(std::move(r));
            }
            m[kv.first] = std::move(e);
        }
    } catch (...) {}
    return m;
}
inline Store load() { return load(cache_path()); }

inline void save(const Store& m, const std::string& path) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return;
    f << "{\n";
    size_t i = 0;
    for (auto& kv : m) {
        const Entry& e = kv.second;
        f << "  \"" << core::json_escape(kv.first) << "\": {\"ts\": " << e.ts << ", \"results\": [";
        for (size_t j = 0; j < e.results.size(); ++j) {
            const auto& r = e.results[j];
            f << (j ? "," : "")
              << "{\"source\":\""   << core::json_escape(r.source) << "\""
              << ",\"ok\":"         << (r.ok ? "true" : "false")
              << ",\"found\":"      << (r.found ? "true" : "false")
              << ",\"summary\":\""  << core::json_escape(r.summary) << "\""
              << ",\"malicious\":"  << r.malicious
              << ",\"total\":"      << r.total
              << ",\"score\":"      << r.score
              << ",\"error\":\""    << core::json_escape(r.error) << "\""
              << ",\"details\":[";
            for (size_t d = 0; d < r.details.size(); ++d)
                f << (d ? "," : "")
                  << "{\"k\":\"" << core::json_escape(r.details[d].first)
                  << "\",\"v\":\"" << core::json_escape(r.details[d].second) << "\"}";
            f << "]}";
        }
        f << "]}" << (++i < m.size() ? "," : "") << "\n";
    }
    f << "}\n";
}
inline void save(const Store& m) { save(m, cache_path()); }

inline bool fresh(const Store& m, const std::string& key, int ttl_hours,
                  std::vector<intel::SourceResult>& out) {
    if (ttl_hours <= 0) return false;
    auto it = m.find(key);
    if (it == m.end()) return false;
    if (now_epoch() - it->second.ts > (long long)ttl_hours * 3600) return false;
    out = it->second.results;
    return true;
}

// Indicator enrichment with the on-disk cache in front of it.
inline core::IndicatorReport enrich_cached(const core::Options& opts) {
    core::IndicatorReport rep;
    rep.target = opts.target;
    rep.type   = classify(opts.target);
    if (rep.type == IocType::Unknown) {
        rep.ok = false;
        rep.error = "'" + opts.target + "' is neither a readable file nor a recognised indicator.";
        return rep;
    }

    std::string key = keyof(opts.target);
    Store store = load();
    std::vector<intel::SourceResult> cached;
    if (fresh(store, key, opts.cache_ttl_hours, cached)) {
        rep.results = cached;
        rep.worst   = core::compute_worst(rep.results);
        return rep;
    }

    auto sources = core::build_sources(opts);
    rep.results  = intel::enrich(sources, opts.target, rep.type);
    rep.worst    = core::compute_worst(rep.results);

    // only cache a query that actually reached a source
    bool worth_caching = false;
    for (auto& r : rep.results) if (r.ok) { worth_caching = true; break; }
    if (worth_caching) {
        Entry e; e.ts = now_epoch(); e.results = rep.results;
        store[key] = std::move(e);
        save(store);
    }
    return rep;
}

} // namespace cache
} // namespace horus
