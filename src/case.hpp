#pragma once

#include "cache.hpp"
#include "case_io.hpp"
#include "cluster.hpp"
#include "console.hpp"

#include <windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace horus {
namespace casework {

struct InputFile {
    fs::path full_path;
    std::string relative_path;
    uint64_t size = 0;
    std::string mtime;
    std::string skip_reason;
};

inline std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

inline std::string path_key(const std::string& path) {
    return lower(path);
}

inline bool same_component(const fs::path& a, const fs::path& b) {
#if defined(_WIN32)
    return _wcsicmp(a.c_str(), b.c_str()) == 0;
#else
    return a == b;
#endif
}

inline bool path_within(const fs::path& child, const fs::path& parent) {
    std::error_code ec1, ec2;
    fs::path c = fs::weakly_canonical(child, ec1);
    fs::path p = fs::weakly_canonical(parent, ec2);
    if (ec1 || ec2) return false;
    auto ci = c.begin(), pi = p.begin();
    for (; pi != p.end(); ++pi, ++ci)
        if (ci == c.end() || !same_component(*ci, *pi)) return false;
    return true;
}

inline bool add_input(const fs::directory_entry& entry, const fs::path& root,
                      std::vector<InputFile>& files, std::string& error) {
    std::error_code ec;
    fs::file_status symlink = entry.symlink_status(ec);
    if (ec) return true;

    InputFile in;
    in.full_path = entry.path();
    in.relative_path = fs::relative(entry.path(), root, ec).generic_string();
    if (ec || in.relative_path.empty()) return true;

    if (fs::is_symlink(symlink)) {
        in.skip_reason = "symbolic links are not followed";
    } else if (!entry.is_regular_file(ec) || ec) {
        return true;
    } else {
        in.size = static_cast<uint64_t>(entry.file_size(ec));
        if (ec) in.skip_reason = "cannot read file size";
        if (in.skip_reason.empty()) {
            in.mtime = mtime_of(entry.path(), ec);
            if (ec) in.skip_reason = "cannot read modification time";
        }
    }

    files.push_back(std::move(in));
    if (files.size() > 5000) {
        error = "case contains more than 5000 files";
        return false;
    }
    return true;
}

inline bool enumerate(const fs::path& root, const fs::path& workspace, bool recurse,
                      std::vector<InputFile>& files, std::string& error) {
    std::error_code ec;
    if (!fs::exists(root, ec) || !fs::is_directory(root, ec)) {
        error = "case source is not a directory: " + root.string();
        return false;
    }
    if (path_within(root, workspace) && path_within(workspace, root)) {
        error = "case workspace must be separate from the samples directory";
        return false;
    }
    const bool workspace_inside_root = path_within(workspace, root);

    if (recurse) {
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        while (!ec && it != end) {
            if (workspace_inside_root && it->is_directory(ec) &&
                path_within(it->path(), workspace)) {
                it.disable_recursion_pending();
            } else if ((!workspace_inside_root || !path_within(it->path(), workspace)) &&
                       !add_input(*it, root, files, error)) {
                return false;
            }
            it.increment(ec);
        }
    } else {
        for (fs::directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
             !ec && it != end; it.increment(ec)) {
            if ((!workspace_inside_root || !path_within(it->path(), workspace)) &&
                !add_input(*it, root, files, error))
                return false;
        }
    }
    if (ec) {
        error = "cannot enumerate case directory: " + ec.message();
        return false;
    }
    std::sort(files.begin(), files.end(), [](const InputFile& a, const InputFile& b) {
        return path_key(a.relative_path) < path_key(b.relative_path);
    });
    return true;
}

inline std::vector<std::string> sorted_unique(std::vector<std::string> values) {
    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

inline std::string section_fingerprint(const core::FileReport& report) {
    if (!report.info.valid || report.info.sections.empty()) return {};
    std::string shape;
    for (const auto& section : report.info.sections) {
        std::string name = lower(section.name);
        uint64_t size_bucket = report.size
            ? std::min<uint64_t>(32, (static_cast<uint64_t>(section.raw_size) * 32) / report.size)
            : 0;
        int entropy_bucket = static_cast<int>(std::lround(section.entropy * 2.0));
        shape += name + ":" + (section.readable ? "r" : "-") +
                 (section.writable ? "w" : "-") + (section.executable ? "x" : "-") +
                 ":" + std::to_string(size_bucket) + ":" + std::to_string(entropy_bucket) + ";";
    }
    return crypto::md5_hex(shape);
}

inline Sample sample_from_report(const InputFile& input, const core::FileReport& report) {
    Sample sample;
    sample.path = input.relative_path;
    sample.size = input.size;
    sample.mtime = input.mtime;
    sample.md5 = report.hashes.md5;
    sample.sha1 = report.hashes.sha1;
    sample.sha256 = report.hashes.sha256;
    sample.tlsh = report.tlsh;
    sample.ssdeep = report.ssdeep;
    sample.is_pe = report.info.valid;
    sample.imphash = report.imphash;
    sample.rich_hash = report.rich_hash;
    sample.section_fingerprint = section_fingerprint(report);
    for (const auto& cap : report.risk.capabilities)
        if (cap.significant) sample.capabilities.push_back(sig::meta(cap.cap).label);
    for (const auto& technique : report.techs) sample.attack.push_back(technique.id);
    sample.capabilities = sorted_unique(std::move(sample.capabilities));
    sample.attack = sorted_unique(std::move(sample.attack));
    sample.urls.assign(report.emb.urls.begin(), report.emb.urls.end());
    sample.ips.assign(report.emb.ips.begin(), report.emb.ips.end());
    if (sample.is_pe) {
        sample.status = "complete";
        sample.has_score = true;
        sample.static_score = report.static_score;
        sample.score = report.final_score;
        sample.verdict = core::verdict_for_score(sample.score);
    } else {
        sample.status = "unknown";
        sample.verdict = "UNKNOWN";
    }
    return sample;
}

inline bool cached_hash_matches(const fs::path& path, const std::string& expected) {
    if (expected.empty()) return false;
    std::vector<uint8_t> bytes;
    if (!core::read_file(path.string(), bytes)) return false;
    return crypto::hash_buffer(bytes).sha256 == expected;
}

inline std::vector<IocRecord> collect_iocs(const std::vector<Sample>& samples,
                                           const std::vector<IocRecord>& previous) {
    std::map<std::string, IocRecord> old;
    for (const auto& r : previous) old[r.type + "\n" + r.value] = r;
    std::map<std::string, IocRecord> now;

    auto add = [&](const std::string& type, const std::string& value, const std::string& path) {
        if (value.empty()) return;
        std::string key = type + "\n" + value;
        auto it = now.find(key);
        if (it == now.end()) {
            IocRecord record;
            auto prior = old.find(key);
            if (prior != old.end()) record = prior->second;
            record.type = type;
            record.value = value;
            record.paths.clear();
            it = now.emplace(key, std::move(record)).first;
        }
        it->second.paths.push_back(path);
    };

    for (const auto& sample : samples) {
        if (sample.missing) continue;
        add("sha256", sample.sha256, sample.path);
        for (const auto& value : sample.urls) add("url", value, sample.path);
        for (const auto& value : sample.ips) add("ipv4", value, sample.path);
    }

    std::vector<IocRecord> out;
    for (auto& kv : now) {
        kv.second.paths = sorted_unique(std::move(kv.second.paths));
        out.push_back(std::move(kv.second));
    }
    return out;
}

inline void summarize_lookup(IocRecord& record,
                             const std::vector<intel::SourceResult>& results) {
    record.ok = false;
    record.found = false;
    record.score = core::compute_worst(results);
    record.summary.clear();
    record.error.clear();
    for (const auto& result : results) {
        if (result.ok) {
            record.ok = true;
            if (result.found) record.found = true;
            if (!result.summary.empty()) {
                if (!record.summary.empty()) record.summary += " | ";
                record.summary += result.source + ": " + result.summary;
            }
        } else if (!result.error.empty()) {
            if (!record.error.empty()) record.error += " | ";
            record.error += result.source + ": " + result.error;
        }
    }
}

inline void enrich_iocs(RunResult& run, const core::Options& opts) {
    if (!opts.enrich) return;

    cache::Store store = cache::load();
    bool cache_dirty = false;
    for (auto& record : run.iocs) {
        IocType type = classify(record.value);
        auto sources = core::build_sources(opts);
        bool supported = false;
        for (const auto& source : sources) if (source->supports(type)) { supported = true; break; }
        if (!supported) {
            record.lookup_status = "unavailable";
            record.ok = false;
            record.found = false;
            record.error = "no configured provider supports this indicator";
            continue;
        }

        std::vector<intel::SourceResult> results;
        std::string key = cache::keyof(record.value);
        if (cache::fresh(store, key, opts.cache_ttl_hours, results)) {
            record.lookup_status = "cached";
            ++run.cache_hits;
        } else if (run.live_lookups >= static_cast<size_t>(opts.max_lookups)) {
            record.lookup_status = "limit";
            record.error = "live lookup limit reached";
            continue;
        } else {
            record.lookup_status = "live";
            results = intel::enrich(sources, record.value, type);
            ++run.live_lookups;
            bool worth_caching = false;
            for (const auto& result : results) if (result.ok) { worth_caching = true; break; }
            if (worth_caching && opts.cache_ttl_hours > 0) {
                cache::Entry entry;
                entry.ts = cache::now_epoch();
                entry.results = results;
                store[key] = std::move(entry);
                cache_dirty = true;
            }
        }
        summarize_lookup(record, results);
    }
    if (cache_dirty) cache::save(store);

    std::map<std::string, const IocRecord*> hashes;
    for (const auto& record : run.iocs)
        if (record.type == "sha256") hashes[record.value] = &record;
    for (auto& sample : run.state.samples) {
        auto it = hashes.find(sample.sha256);
        if (sample.missing || it == hashes.end()) continue;
        const IocRecord& record = *it->second;
        if (record.ok && record.found) {
            sample.has_score = true;
            sample.status = "complete";
            sample.score = std::max(sample.is_pe ? sample.static_score : 0, record.score);
            sample.verdict = core::verdict_for_score(sample.score);
            sample.intel_summary = record.summary;
        } else if (record.lookup_status == "live" || record.lookup_status == "cached") {
            sample.intel_summary.clear();
            if (sample.is_pe) {
                sample.has_score = true;
                sample.status = "complete";
                sample.score = sample.static_score;
                sample.verdict = core::verdict_for_score(sample.score);
            } else {
                sample.has_score = false;
                sample.status = "unknown";
                sample.score = 0;
                sample.verdict = "UNKNOWN";
            }
        }
    }
}

inline Change make_change(const std::string& kind, const Sample* before,
                          const Sample* after) {
    Change change;
    change.kind = kind;
    change.path = after ? after->path : before->path;
    if (before) {
        change.has_before = true;
        change.before_sha256 = before->sha256;
        change.before_status = shown_status(*before);
        change.before_has_score = !before->missing && before->has_score;
        change.before_score = before->score;
    }
    if (after) {
        change.has_after = true;
        change.after_sha256 = after->sha256;
        change.after_status = shown_status(*after);
        change.after_has_score = !after->missing && after->has_score;
        change.after_score = after->score;
    }
    return change;
}

// Only the latest refresh is compared. This is an additive export; the portable
// state continues to hold the current case rather than an unbounded event log.
inline std::vector<Change> detect_changes(const State& before, const State& after) {
    std::map<std::string, const Sample*> old_samples, new_samples;
    for (const auto& sample : before.samples)
        old_samples[path_key(sample.path)] = &sample;
    for (const auto& sample : after.samples)
        new_samples[path_key(sample.path)] = &sample;

    std::vector<Change> changes;
    for (const auto& [key, current] : new_samples) {
        auto it = old_samples.find(key);
        const Sample* previous = it == old_samples.end() ? nullptr : it->second;
        if (!previous) {
            changes.push_back(make_change("added", nullptr, current));
        } else if (previous->missing && !current->missing) {
            changes.push_back(make_change("restored", previous, current));
        } else if (!previous->missing && current->missing) {
            changes.push_back(make_change("missing", previous, current));
        } else if (!current->missing && (previous->size != current->size ||
                   (!previous->sha256.empty() && !current->sha256.empty() &&
                    previous->sha256 != current->sha256))) {
            changes.push_back(make_change("modified", previous, current));
        } else if (!current->missing &&
                   (previous->status != current->status ||
                    previous->has_score != current->has_score ||
                    (previous->has_score && previous->score != current->score) ||
                    previous->verdict != current->verdict ||
                    previous->intel_summary != current->intel_summary)) {
            changes.push_back(make_change("assessment_changed", previous, current));
        }
    }
    for (const auto& [key, previous] : old_samples)
        if (!new_samples.count(key))
            changes.push_back(make_change("removed", previous, nullptr));
    std::sort(changes.begin(), changes.end(), [](const Change& a, const Change& b) {
        const std::string ak = path_key(a.path), bk = path_key(b.path);
        return ak == bk ? a.kind < b.kind : ak < bk;
    });
    return changes;
}

inline bool build(const core::Options& opts, RunResult& run, std::string& error) {
    fs::path root(opts.case_dir);
    fs::path workspace = opts.case_out.empty()
        ? fs::path(opts.case_dir + ".horus-case") : fs::path(opts.case_out);
    run.workspace = workspace.string();

    State old;
    bool state_exists = false;
    fs::path state_path = workspace / ".horus" / "state.json";
    if (!load_state(state_path, old, state_exists, error)) {
        if (!opts.rebuild) return false;
        old = State{};
        state_exists = false;
        error.clear();
    }

    std::vector<InputFile> inputs;
    if (!enumerate(root, workspace, opts.recurse, inputs, error)) return false;

    const std::string binding = path_binding(root);
    bool force_verify = opts.verify || (state_exists && old.root_binding != binding);
    std::map<std::string, Sample> cached;
    for (const auto& sample : old.samples) cached[path_key(sample.path)] = sample;
    std::set<std::string> seen;

    State next;
    next.id = state_exists ? old.id : guid("case-");
    next.name = !opts.case_name.empty() ? opts.case_name :
                (state_exists && !old.name.empty() ? old.name : root.filename().string());
    if (next.name.empty()) next.name = "Horus case";
    next.root_binding = binding;
    next.created = state_exists && !old.created.empty() ? old.created : utc_now();
    next.updated = utc_now();
    next.run_count = (state_exists ? old.run_count : 0) + 1;

    const uint64_t max_bytes = opts.max_file_mb * 1024ULL * 1024ULL;
    for (size_t pos = 0; pos < inputs.size(); ++pos) {
        const auto& input = inputs[pos];
        const std::string key = path_key(input.relative_path);
        seen.insert(key);
        auto prior = cached.find(key);

        if (!input.skip_reason.empty()) {
            Sample sample;
            sample.path = input.relative_path;
            sample.size = input.size;
            sample.mtime = input.mtime;
            sample.status = "skipped";
            sample.error = input.skip_reason;
            next.samples.push_back(std::move(sample));
            continue;
        }
        if (input.size > max_bytes) {
            Sample sample;
            sample.path = input.relative_path;
            sample.size = input.size;
            sample.mtime = input.mtime;
            sample.status = "skipped";
            sample.error = "file exceeds --max-file-mb";
            next.samples.push_back(std::move(sample));
            continue;
        }

        bool can_reuse = !opts.rebuild && prior != cached.end() &&
                         prior->second.size == input.size && prior->second.mtime == input.mtime &&
                         prior->second.status != "error";
        if (can_reuse && force_verify)
            can_reuse = cached_hash_matches(input.full_path, prior->second.sha256);

        if (can_reuse) {
            Sample sample = prior->second;
            sample.path = input.relative_path;
            sample.missing = false;
            sample.duplicate_id.clear();
            sample.cluster_id.clear();
            next.samples.push_back(std::move(sample));
            ++run.reused;
            continue;
        }

        core::Options file_opts = opts;
        file_opts.target = input.full_path.string();
        file_opts.vt_key.clear();
        file_opts.abuse_key.clear();
        file_opts.enrich = false;
        core::FileReport report = core::analyze_file(file_opts);
        if (!report.ok) {
            Sample sample;
            sample.path = input.relative_path;
            sample.size = input.size;
            sample.mtime = input.mtime;
            sample.status = "error";
            sample.error = "cannot read sample";
            next.samples.push_back(std::move(sample));
        } else {
            next.samples.push_back(sample_from_report(input, report));
        }
        ++run.analyzed;
    }

    if (!opts.prune)
        for (auto sample : old.samples) {
            if (seen.count(path_key(sample.path))) continue;
            sample.missing = true;
            sample.duplicate_id.clear();
            sample.cluster_id.clear();
            next.samples.push_back(std::move(sample));
        }

    std::sort(next.samples.begin(), next.samples.end(), [](const Sample& a, const Sample& b) {
        return path_key(a.path) < path_key(b.path);
    });
    run.state = std::move(next);
    run.iocs = collect_iocs(run.state.samples, old.iocs);
    enrich_iocs(run, opts);
    run.duplicates = duplicate_groups(run.state.samples);
    run.clusters = build_clusters(run.state.samples, opts.cluster_mode, old.clusters,
                                  [] { return guid("cluster-"); });
    run.state.clusters = run.clusters;
    run.state.iocs = run.iocs;
    run.changes = detect_changes(old, run.state);
    return write_outputs(run, opts, error);
}

inline bool open_report(const std::string& path) {
    HINSTANCE result = ShellExecuteW(nullptr, L"open", fs::path(path).c_str(),
                                     nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<INT_PTR>(result) > 32;
}

inline int exit_code(const RunResult& run) {
    bool incomplete = false;
    for (const auto& sample : run.state.samples) {
        if (!sample.missing && sample.has_score && sample.score >= 30) return 1;
        if (shown_status(sample) != "complete") incomplete = true;
    }
    return incomplete ? 3 : 0;
}

inline int run(const core::Options& opts) {
    if (opts.verify && opts.rebuild) {
        std::cerr << "error: --verify and --rebuild cannot be used together\n";
        return 2;
    }
    if (opts.cluster_mode != "conservative" && opts.cluster_mode != "balanced" &&
        opts.cluster_mode != "broad") {
        std::cerr << "error: --cluster-mode must be conservative, balanced, or broad\n";
        return 2;
    }
    if (opts.max_lookups < 0 || opts.max_file_mb == 0) {
        std::cerr << "error: lookup and file limits must be non-negative\n";
        return 2;
    }

    RunResult result;
    std::string error;
    if (!build(opts, result, error)) {
        std::cerr << "error: " << error << "\n";
        return 2;
    }

    if (opts.json) {
        std::cout << result.public_json;
    } else if (!opts.gui) {
        ui::section("CASE  " + result.state.name);
        ui::kv("workspace", result.workspace);
        ui::kv("samples", std::to_string(result.state.samples.size()));
        ui::kv("analyzed", std::to_string(result.analyzed));
        ui::kv("reused", std::to_string(result.reused));
        ui::kv("changes", std::to_string(result.changes.size()));
        ui::kv("duplicates", std::to_string(result.duplicates.size()));
        ui::kv("clusters", std::to_string(result.clusters.size()));
        if (opts.enrich) {
            ui::kv("live lookups", std::to_string(result.live_lookups));
            ui::kv("cache hits", std::to_string(result.cache_hits));
        }
        ui::kv("report", result.report_path);
    }

    if (opts.gui && !open_report(result.report_path)) {
        std::cerr << "error: case report was written but could not be opened\n";
        return 2;
    }
    return exit_code(result);
}

} // namespace casework
} // namespace horus
