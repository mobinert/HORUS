#pragma once

#include "case_types.hpp"
#include "fuzzy.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace horus {
namespace casework {

struct Similarity {
    bool accepted = false;
    int score = 0;
    int tlsh_distance = -1;
    bool imphash = false;
    bool rich = false;
    bool sections = false;
    int capability_overlap = 0;
    std::vector<std::string> evidence;
};

inline int overlap_percent(const std::vector<std::string>& a,
                           const std::vector<std::string>& b) {
    if (a.empty() && b.empty()) return 100;
    std::set<std::string> aa(a.begin(), a.end()), bb(b.begin(), b.end());
    size_t both = 0;
    for (const auto& v : aa) if (bb.count(v)) ++both;
    const size_t either = aa.size() + bb.size() - both;
    return either ? static_cast<int>((both * 100) / either) : 0;
}

inline Similarity compare(const Sample& a, const Sample& b,
                          const std::string& mode) {
    Similarity s;
    if (!a.is_pe || !b.is_pe || a.sha256.empty() || a.sha256 == b.sha256)
        return s;

    if (!a.tlsh.empty() && !b.tlsh.empty())
        s.tlsh_distance = fuzzy::tlsh_diff(a.tlsh, b.tlsh);
    s.imphash = !a.imphash.empty() && a.imphash == b.imphash;
    s.rich = !a.rich_hash.empty() && a.rich_hash == b.rich_hash;
    s.sections = !a.section_fingerprint.empty() &&
                 a.section_fingerprint == b.section_fingerprint;
    s.capability_overlap = overlap_percent(a.capabilities, b.capabilities);

    const int structural = static_cast<int>(s.imphash) +
                           static_cast<int>(s.rich) +
                           static_cast<int>(s.sections);
    const int d = s.tlsh_distance;
    if (mode == "conservative") {
        s.accepted = (d >= 0 && d <= 25 && structural >= 1) || structural == 3;
    } else if (mode == "broad") {
        s.accepted = (d >= 0 && d <= 100) || structural >= 2;
    } else {
        s.accepted = (d >= 0 && d <= 35) ||
                     (d >= 0 && d <= 65 && structural >= 1) ||
                     (s.imphash && (s.rich || s.sections));
    }

    if (d >= 0 && d <= 100) s.score += 60 - (d * 60 / 100);
    if (s.imphash) s.score += 18;
    if (s.rich) s.score += 12;
    if (s.sections) s.score += 10;
    s.score += s.capability_overlap / 20;
    if (s.score > 100) s.score = 100;

    if (d >= 0) s.evidence.push_back("TLSH distance " + std::to_string(d));
    if (s.imphash) s.evidence.push_back("imphash match");
    if (s.rich) s.evidence.push_back("Rich hash match");
    if (s.sections) s.evidence.push_back("section layout match");
    if (s.capability_overlap > 0)
        s.evidence.push_back("capability overlap " + std::to_string(s.capability_overlap) + "%");
    return s;
}

inline std::vector<DuplicateGroup> duplicate_groups(std::vector<Sample>& samples) {
    std::map<std::string, std::vector<size_t>> by_hash;
    for (size_t i = 0; i < samples.size(); ++i)
        if (!samples[i].missing && !samples[i].sha256.empty())
            by_hash[samples[i].sha256].push_back(i);

    std::vector<DuplicateGroup> groups;
    for (const auto& kv : by_hash) {
        if (kv.second.size() < 2) continue;
        DuplicateGroup g;
        g.sha256 = kv.first;
        g.id = "dup-" + kv.first.substr(0, 12);
        for (size_t index : kv.second) {
            samples[index].duplicate_id = g.id;
            g.paths.push_back(samples[index].path);
        }
        groups.push_back(std::move(g));
    }
    return groups;
}

inline std::set<std::string> member_hashes(const Cluster& c) {
    std::set<std::string> out;
    for (const auto& m : c.members) out.insert(m.sha256);
    return out;
}

inline size_t overlap_count(const Cluster& a, const Cluster& b) {
    auto aa = member_hashes(a);
    size_t n = 0;
    for (const auto& m : b.members) if (aa.count(m.sha256)) ++n;
    return n;
}

inline void carry_cluster_ids(std::vector<Cluster>& current,
                              const std::vector<Cluster>& previous,
                              const std::function<std::string()>& make_id) {
    struct Match { size_t overlap, now, old; };
    std::vector<Match> matches;
    for (size_t i = 0; i < current.size(); ++i)
        for (size_t j = 0; j < previous.size(); ++j) {
            size_t n = overlap_count(current[i], previous[j]);
            if (n) matches.push_back({n, i, j});
        }
    std::sort(matches.begin(), matches.end(), [&](const Match& a, const Match& b) {
        if (a.overlap != b.overlap) return a.overlap > b.overlap;
        if (current[a.now].representative != current[b.now].representative)
            return current[a.now].representative < current[b.now].representative;
        return previous[a.old].id < previous[b.old].id;
    });

    std::set<size_t> used_now, used_old;
    for (const auto& m : matches) {
        if (used_now.count(m.now) || used_old.count(m.old)) continue;
        current[m.now].id = previous[m.old].id;
        used_now.insert(m.now);
        used_old.insert(m.old);
    }
    for (auto& c : current) if (c.id.empty()) c.id = make_id();
}

inline std::vector<Cluster> build_clusters(std::vector<Sample>& samples,
                                           const std::string& mode,
                                           const std::vector<Cluster>& previous,
                                           const std::function<std::string()>& make_id) {
    std::map<std::string, size_t> unique;
    for (size_t i = 0; i < samples.size(); ++i) {
        auto& s = samples[i];
        s.cluster_id.clear();
        if (!s.missing && s.is_pe && !s.sha256.empty()) unique.emplace(s.sha256, i);
    }

    struct Draft { size_t representative; std::vector<size_t> members; };
    std::vector<Draft> drafts;
    for (const auto& kv : unique) {
        size_t index = kv.second;
        int best_score = -1;
        size_t best = drafts.size();
        for (size_t i = 0; i < drafts.size(); ++i) {
            Similarity sim = compare(samples[drafts[i].representative], samples[index], mode);
            if (sim.accepted && sim.score > best_score) {
                best_score = sim.score;
                best = i;
            }
        }
        if (best == drafts.size()) drafts.push_back({index, {index}});
        else drafts[best].members.push_back(index);
    }

    std::vector<Cluster> out;
    for (auto& d : drafts) {
        if (d.members.size() < 2) continue;
        size_t medoid = d.representative;
        long long best_total = -1;
        for (size_t candidate : d.members) {
            bool valid = true;
            long long total = 0;
            for (size_t member : d.members) {
                if (candidate == member) { total += 100; continue; }
                Similarity sim = compare(samples[candidate], samples[member], mode);
                if (!sim.accepted) { valid = false; break; }
                total += sim.score;
            }
            if (valid && (total > best_total ||
                (total == best_total && samples[candidate].sha256 < samples[medoid].sha256))) {
                medoid = candidate;
                best_total = total;
            }
        }

        Cluster c;
        c.representative = samples[medoid].sha256;
        for (size_t member : d.members) {
            ClusterMember cm;
            cm.sha256 = samples[member].sha256;
            if (member == medoid) {
                cm.evidence.push_back("cluster representative");
            } else {
                Similarity sim = compare(samples[medoid], samples[member], mode);
                cm.similarity = sim.score;
                cm.evidence = std::move(sim.evidence);
            }
            c.members.push_back(std::move(cm));
        }
        std::sort(c.members.begin(), c.members.end(), [](const ClusterMember& a, const ClusterMember& b) {
            return a.sha256 < b.sha256;
        });
        out.push_back(std::move(c));
    }

    std::sort(out.begin(), out.end(), [](const Cluster& a, const Cluster& b) {
        return a.representative < b.representative;
    });
    carry_cluster_ids(out, previous, make_id);

    std::map<std::string, std::string> id_by_hash;
    for (const auto& c : out)
        for (const auto& m : c.members) id_by_hash[m.sha256] = c.id;
    for (auto& s : samples) {
        auto it = id_by_hash.find(s.sha256);
        if (!s.missing && it != id_by_hash.end()) s.cluster_id = it->second;
    }
    return out;
}

} // namespace casework
} // namespace horus
