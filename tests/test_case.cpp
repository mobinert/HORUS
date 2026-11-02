#include "case.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#include <windows.h>
#include <psapi.h>

using namespace horus;
namespace fs = std::filesystem;

int failures = 0;
#define CHECK(c) do { if (!(c)) { std::cerr << "FAIL line " << __LINE__ << ": " #c "\n"; ++failures; } } while (0)

static std::string read_text(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream out;
    out << f.rdbuf();
    return out.str();
}

static const casework::Sample* find_sample(const casework::RunResult& run,
                                           const std::string& path) {
    for (const auto& sample : run.state.samples) if (sample.path == path) return &sample;
    return nullptr;
}

static const casework::Change* find_change(const casework::RunResult& run,
                                           const std::string& path) {
    for (const auto& change : run.changes) if (change.path == path) return &change;
    return nullptr;
}

static std::string fake_sha(size_t value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(64) << value;
    return out.str();
}

int main(int argc, char** argv) {
    fs::path root = fs::temp_directory_path() / casework::guid("horus-case-test-");
    fs::path samples = root / "samples";
    fs::path workspace = root / "workspace";
    std::error_code ec;
    fs::create_directories(samples, ec);
    CHECK(!ec);

    fs::copy_file(argv[0], samples / "a.exe", fs::copy_options::overwrite_existing, ec);
    CHECK(!ec);
    fs::copy_file(argv[0], samples / "b.exe", fs::copy_options::overwrite_existing, ec);
    CHECK(!ec);
    fs::copy_file(argv[0], samples / "sample", fs::copy_options::overwrite_existing, ec);
    CHECK(!ec);
    fs::copy_file(argv[0], samples / "nearby.exe", fs::copy_options::overwrite_existing, ec);
    CHECK(!ec);
    { std::ofstream f(samples / "nearby.exe", std::ios::binary | std::ios::app); f.put('\0'); }
    { std::ofstream f(samples / "=formula.txt", std::ios::binary); f << "plain text"; }
    { std::ofstream f(samples / "text sample.txt", std::ios::binary); f << "first"; }

    core::Options opts;
    opts.case_dir = samples.string();
    opts.case_out = workspace.string();
    opts.case_name = "lab </script><script>alert(1)</script>";
    opts.vt_key = "vt-secret-for-export-test";
    opts.abuse_key = "abuse-secret-for-export-test";

    casework::RunResult first;
    std::string error;
    CHECK(casework::build(opts, first, error));
    if (!error.empty()) std::cerr << error << "\n";
    CHECK(first.state.samples.size() == 6);
    CHECK(first.changes.size() == 6);
    CHECK(find_change(first, "a.exe") && find_change(first, "a.exe")->kind == "added");
    CHECK(first.duplicates.size() == 1);
    CHECK(first.duplicates[0].paths.size() == 3);
    CHECK(!first.clusters.empty());
    CHECK(find_sample(first, "text sample.txt") != nullptr);
    CHECK(find_sample(first, "text sample.txt")->status == "unknown");
    CHECK(first.public_json.find(samples.string()) == std::string::npos);
    CHECK(first.public_json.find(opts.vt_key) == std::string::npos);
    CHECK(first.public_json.find(opts.abuse_key) == std::string::npos);
    CHECK(first.public_json.find("malware_family") == std::string::npos);
    CHECK(json::parse(first.public_json)["schema"].as_string() == "horus-case/v1");
    CHECK(json::parse(first.public_json)["changes"].items().size() == 6);
    CHECK(json::parse(first.public_json)["summary"]["changes"].as_int() == 6);
    CHECK(read_text(workspace / "changes.csv").find("added,a.exe") != std::string::npos);
    CHECK(read_text(workspace / "changes.csv").find("'=formula.txt") != std::string::npos);

    const std::string payload = "</script><script>alert(1)</script>";
    std::string report = read_text(workspace / "report.html");
    std::string state = read_text(workspace / ".horus" / "state.json");
    CHECK(report.find(payload) == std::string::npos);
    CHECK(report.find("__HORUS_CASE_B64__") == std::string::npos);
    CHECK(report.find(opts.vt_key) == std::string::npos);
    CHECK(state.find(samples.string()) == std::string::npos);
    CHECK(state.find(opts.vt_key) == std::string::npos);
    CHECK(read_text(workspace / "samples.csv").find("'=formula.txt") != std::string::npos);

    casework::RunResult hostile_csv;
    casework::Sample hostile_sample;
    hostile_sample.path = "safe";
    hostile_sample.sha256 = "=sha";
    hostile_sample.status = "+status";
    hostile_sample.verdict = "@verdict";
    hostile_sample.duplicate_id = "-duplicate";
    hostile_sample.cluster_id = "\tcluster";
    hostile_csv.state.samples.push_back(hostile_sample);
    casework::Cluster hostile_cluster;
    hostile_cluster.id = "=cluster";
    hostile_cluster.representative = "+representative";
    casework::ClusterMember hostile_member;
    hostile_member.sha256 = "-member";
    hostile_member.evidence = {"@evidence"};
    hostile_cluster.members.push_back(hostile_member);
    hostile_csv.clusters.push_back(hostile_cluster);
    casework::IocRecord hostile_ioc;
    hostile_ioc.type = "=type";
    hostile_ioc.value = "+value";
    hostile_ioc.paths = {"-path"};
    hostile_ioc.lookup_status = "@lookup";
    hostile_ioc.summary = "\tsummary";
    hostile_csv.iocs.push_back(hostile_ioc);
    const std::string hostile_samples = casework::samples_csv(hostile_csv);
    const std::string hostile_clusters = casework::clusters_csv(hostile_csv);
    const std::string hostile_iocs = casework::iocs_csv(hostile_csv);
    CHECK(hostile_samples.find("'=sha") != std::string::npos);
    CHECK(hostile_samples.find("'+status") != std::string::npos);
    CHECK(hostile_samples.find("'@verdict") != std::string::npos);
    CHECK(hostile_samples.find("'-duplicate") != std::string::npos);
    CHECK(hostile_clusters.find("'=cluster") != std::string::npos);
    CHECK(hostile_clusters.find("'+representative") != std::string::npos);
    CHECK(hostile_clusters.find("'-member") != std::string::npos);
    CHECK(hostile_iocs.find("'=type") != std::string::npos);
    CHECK(hostile_iocs.find("'+value") != std::string::npos);
    CHECK(hostile_iocs.find("'@lookup") != std::string::npos);

    std::string case_id = first.state.id;
    std::string cluster_id = first.clusters.empty() ? "" : first.clusters[0].id;
    casework::RunResult second;
    CHECK(casework::build(opts, second, error));
    CHECK(second.state.id == case_id);
    CHECK(second.reused == 6);
    CHECK(second.changes.empty());
    CHECK(json::parse(second.public_json)["changes"].items().empty());
    CHECK(!second.clusters.empty() && second.clusters[0].id == cluster_id);

    fs::path moved_workspace = root / "workspace-moved";
    fs::copy(workspace, moved_workspace, fs::copy_options::recursive, ec);
    CHECK(!ec);
    core::Options moved = opts;
    moved.case_out = moved_workspace.string();
    casework::RunResult moved_run;
    CHECK(casework::build(moved, moved_run, error));
    CHECK(moved_run.state.id == case_id);
    CHECK(moved_run.reused == 6);

    core::Options verify = opts;
    verify.verify = true;
    casework::RunResult checked;
    CHECK(casework::build(verify, checked, error));
    CHECK(checked.reused == 6);

    { std::ofstream f(samples / "new sample.txt", std::ios::binary); f << "new"; }
    casework::RunResult added;
    CHECK(casework::build(opts, added, error));
    CHECK(find_sample(added, "new sample.txt") != nullptr);
    CHECK(added.analyzed >= 1);
    CHECK(find_change(added, "new sample.txt") &&
          find_change(added, "new sample.txt")->kind == "added");

    core::Options rebuild = opts;
    rebuild.rebuild = true;
    casework::RunResult rebuilt;
    CHECK(casework::build(rebuild, rebuilt, error));
    CHECK(rebuilt.reused == 0);
    CHECK(rebuilt.analyzed == 7);

    { std::ofstream f(samples / "text sample.txt", std::ios::binary | std::ios::trunc); f << "changed"; }
    casework::RunResult changed;
    CHECK(casework::build(opts, changed, error));
    CHECK(changed.analyzed >= 1);
    CHECK(find_change(changed, "text sample.txt") &&
          find_change(changed, "text sample.txt")->kind == "modified");

    fs::remove(samples / "text sample.txt", ec);
    CHECK(!ec);
    casework::RunResult missing;
    CHECK(casework::build(opts, missing, error));
    CHECK(find_sample(missing, "text sample.txt") != nullptr);
    CHECK(find_sample(missing, "text sample.txt")->missing);
    CHECK(find_change(missing, "text sample.txt") &&
          find_change(missing, "text sample.txt")->kind == "missing");

    core::Options prune = opts;
    prune.prune = true;
    casework::RunResult pruned;
    CHECK(casework::build(prune, pruned, error));
    CHECK(find_sample(pruned, "text sample.txt") == nullptr);
    CHECK(find_change(pruned, "text sample.txt") &&
          find_change(pruned, "text sample.txt")->kind == "removed");

    casework::State before_changes, after_changes;
    casework::Sample restored;
    restored.path = "restored.exe";
    restored.missing = true;
    restored.sha256 = fake_sha(23);
    before_changes.samples.push_back(restored);
    restored.missing = false;
    restored.status = "complete";
    after_changes.samples.push_back(restored);
    casework::Sample reassessed;
    reassessed.path = "reassessed.exe";
    reassessed.sha256 = fake_sha(24);
    reassessed.status = "complete";
    reassessed.has_score = true;
    reassessed.score = 10;
    reassessed.verdict = "LOW";
    before_changes.samples.push_back(reassessed);
    reassessed.score = 40;
    reassessed.verdict = "SUSPICIOUS";
    after_changes.samples.push_back(reassessed);
    auto changes = casework::detect_changes(before_changes, after_changes);
    CHECK(changes.size() == 2);
    CHECK(changes[0].kind == "assessment_changed");
    CHECK(changes[0].before_score == 10 && changes[0].after_score == 40);
    CHECK(changes[1].kind == "restored");

    fs::create_directories(samples / "nested", ec);
    CHECK(!ec);
    { std::ofstream f(samples / "nested" / "inside.txt", std::ios::binary); f << "nested"; }
    core::Options flat = opts;
    flat.case_out = (root / "flat-workspace").string();
    flat.recurse = false;
    casework::RunResult flat_run;
    CHECK(casework::build(flat, flat_run, error));
    CHECK(find_sample(flat_run, "nested/inside.txt") == nullptr);

    core::Options recursive = opts;
    recursive.case_out = (root / "recursive-workspace").string();
    casework::RunResult recursive_run;
    CHECK(casework::build(recursive, recursive_run, error));
    CHECK(find_sample(recursive_run, "nested/inside.txt") != nullptr);

    fs::path parent_case = root / "parent-case";
    fs::path child_samples = parent_case / "samples";
    fs::create_directories(child_samples, ec);
    CHECK(!ec);
    { std::ofstream f(child_samples / "one.txt", std::ios::binary); f << "one"; }
    core::Options parent_workspace;
    parent_workspace.case_dir = child_samples.string();
    parent_workspace.case_out = parent_case.string();
    casework::RunResult parent_run;
    CHECK(casework::build(parent_workspace, parent_run, error));
    CHECK(parent_run.state.samples.size() == 1);

    core::Options same_workspace;
    same_workspace.case_dir = child_samples.string();
    same_workspace.case_out = child_samples.string();
    casework::RunResult rejected_workspace;
    CHECK(!casework::build(same_workspace, rejected_workspace, error));
    CHECK(error.find("workspace must be separate") != std::string::npos);

    auto make_pair = [&](const std::string& mode, const std::string& imp_b,
                         const std::string& rich_b, const std::string& sections_b) {
        std::vector<casework::Sample> pair(2);
        pair[0].path = "a"; pair[0].sha256 = fake_sha(1001); pair[0].is_pe = true;
        pair[0].imphash = "imp-a"; pair[0].rich_hash = "rich-a"; pair[0].section_fingerprint = "sec-a";
        pair[1].path = "b"; pair[1].sha256 = fake_sha(1002); pair[1].is_pe = true;
        pair[1].imphash = imp_b; pair[1].rich_hash = rich_b; pair[1].section_fingerprint = sections_b;
        int ids = 0;
        return casework::build_clusters(pair, mode, {}, [&] { return "preset-" + std::to_string(++ids); });
    };
    CHECK(make_pair("conservative", "imp-a", "rich-a", "sec-a").size() == 1);
    CHECK(make_pair("conservative", "imp-a", "rich-a", "sec-b").empty());
    CHECK(make_pair("balanced", "imp-a", "rich-a", "sec-b").size() == 1);
    CHECK(make_pair("balanced", "imp-b", "rich-a", "sec-a").empty());
    CHECK(make_pair("broad", "imp-b", "rich-a", "sec-a").size() == 1);

    std::vector<casework::Sample> capability_only(2);
    for (size_t i = 0; i < capability_only.size(); ++i) {
        capability_only[i].path = "cap-" + std::to_string(i);
        capability_only[i].sha256 = fake_sha(1100 + i);
        capability_only[i].is_pe = true;
        capability_only[i].capabilities = {"Process", "Network"};
    }
    CHECK(casework::build_clusters(capability_only, "broad", {}, [] { return "nope"; }).empty());

    std::vector<casework::Sample> joined(4);
    for (size_t i = 0; i < joined.size(); ++i) {
        joined[i].path = "joined-" + std::to_string(i);
        joined[i].sha256 = fake_sha(1200 + i);
        joined[i].is_pe = true;
        joined[i].imphash = "same";
        joined[i].rich_hash = "same";
        joined[i].section_fingerprint = "same";
    }
    int stable_ids = 0;
    auto one_cluster = casework::build_clusters(joined, "balanced", {},
        [&] { return "stable-" + std::to_string(++stable_ids); });
    CHECK(one_cluster.size() == 1);
    std::string original_id = one_cluster[0].id;
    joined[2].imphash = joined[2].rich_hash = joined[2].section_fingerprint = "other";
    joined[3].imphash = joined[3].rich_hash = joined[3].section_fingerprint = "other";
    auto split = casework::build_clusters(joined, "balanced", one_cluster,
        [&] { return "stable-" + std::to_string(++stable_ids); });
    CHECK(split.size() == 2);
    int carried = 0;
    for (const auto& cluster : split) if (cluster.id == original_id) ++carried;
    CHECK(carried == 1);
    for (auto& sample : joined)
        sample.imphash = sample.rich_hash = sample.section_fingerprint = "merged";
    auto merged = casework::build_clusters(joined, "balanced", split,
        [&] { return "stable-" + std::to_string(++stable_ids); });
    CHECK(merged.size() == 1);
    CHECK(merged[0].id == std::min(split[0].id, split[1].id));

    std::vector<casework::Sample> synthetic;
    synthetic.reserve(5000);
    for (size_t i = 0; i < 5000; ++i) {
        casework::Sample sample;
        sample.path = "sample-" + std::to_string(i);
        sample.sha256 = fake_sha(i + 1);
        sample.is_pe = true;
        sample.imphash = "imp-" + std::to_string(i / 50);
        sample.rich_hash = "rich-" + std::to_string(i / 50);
        synthetic.push_back(std::move(sample));
    }
    auto started = std::chrono::steady_clock::now();
    auto clusters = casework::build_clusters(synthetic, "balanced", {},
                                              [] { return casework::guid("cluster-"); });
    auto elapsed = std::chrono::steady_clock::now() - started;
    CHECK(clusters.size() == 100);
    CHECK(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() < 30);
    PROCESS_MEMORY_COUNTERS memory{};
    memory.cb = sizeof(memory);
    CHECK(GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory)) != 0);
    CHECK(memory.PeakWorkingSetSize < 1024ULL * 1024ULL * 1024ULL);

    fs::remove_all(root, ec);
    if (failures) std::cout << "test_case FAILED\n";
    else std::cout << "test_case ok\n";
    return failures ? 1 : 0;
}
