// ---------------------------------------------------------------------------
//  config.hpp  -  optional ~/.horus.json so you don't paste keys every run
//
//  Precedence stays flag > env > config: the loader only fills a field that's
//  still empty after argv/env parsing. A malformed file is ignored, not fatal -
//  the tool should never refuse to run because of its own dotfile.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "json.hpp"

#include <string>
#include <fstream>
#include <sstream>

namespace horus {
namespace config {

inline std::string home_dir() {
    std::string h = core::get_env("USERPROFILE");
    if (h.empty()) h = core::get_env("HOME");
    return h;
}

inline std::string config_path() {
    std::string h = home_dir();
    return h.empty() ? std::string(".horus.json") : h + "\\.horus.json";
}

struct Config {
    std::string vt_key;
    std::string abuse_key;
    int  cache_ttl_hours = 0;
    bool loaded = false;
};

inline Config load(const std::string& path) {
    Config c;
    std::ifstream f(path, std::ios::binary);
    if (!f) return c;
    std::stringstream ss; ss << f.rdbuf();
    try {
        auto doc = json::parse(ss.str());
        c.vt_key          = doc["vt_key"].as_string();
        c.abuse_key       = doc["abuse_key"].as_string();
        c.cache_ttl_hours = (int)doc["cache_ttl_hours"].as_int(0);
        c.loaded = true;
    } catch (...) {
        // bad json - pretend the file wasn't there
    }
    return c;
}

inline Config load() { return load(config_path()); }

// Fill only what argv/env left blank.
inline void apply(core::Options& o, const Config& c) {
    if (o.vt_key.empty()    && !c.vt_key.empty())    o.vt_key = c.vt_key;
    if (o.abuse_key.empty() && !c.abuse_key.empty()) o.abuse_key = c.abuse_key;
    if (o.cache_ttl_hours == 0 && c.cache_ttl_hours > 0) o.cache_ttl_hours = c.cache_ttl_hours;
}

} // namespace config
} // namespace horus
