#include "case.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

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

    casework::RunResult first;
    std::string error;
    CHECK(casework::build(opts, first, error));
    if (!error.empty()) std::cerr << error << "\n";
    CHECK(first.state.samples.size() == 6);
    CHECK(first.duplicates.size() == 1);
    CHECK(first.duplicates[0].paths.size() == 3);
    CHECK(!first.clusters.empty());
    CHECK(find_sample(first, "text sample.txt") != nullptr);
    CHECK(find_sample(first, "text sample.txt")->status == "unknown");
    CHECK(first.public_json.find(samples.string()) == std::string::npos);
    CHECK(first.public_json.find("malware_family") == std::string::npos);
    CHECK(json::parse(first.public_json)["schema"].as_string() == "horus-case/v1");

    const std::string payload = "</script><script>alert(1)</script>";
    std::string report = read_text(workspace / "report.html");
    CHECK(report.find(payload) == std::string::npos);
    CHECK(report.find("__HORUS_CASE_B64__") == std::string::npos);
    CHECK(read_text(workspace / "samples.csv").find("'=formula.txt") != std::string::npos);

    std::string case_id = first.state.id;
    std::string cluster_id = first.clusters.empty() ? "" : first.clusters[0].id;
    casework::RunResult second;
    CHECK(casework::build(opts, second, error));
    CHECK(second.state.id == case_id);
    CHECK(second.reused == 6);
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

    fs::remove(samples / "text sample.txt", ec);
    CHECK(!ec);
    casework::RunResult missing;
    CHECK(casework::build(opts, missing, error));
    CHECK(find_sample(missing, "text sample.txt") != nullptr);
    CHECK(find_sample(missing, "text sample.txt")->missing);

    core::Options prune = opts;
    prune.prune = true;
    casework::RunResult pruned;
    CHECK(casework::build(prune, pruned, error));
    CHECK(find_sample(pruned, "text sample.txt") == nullptr);

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

    fs::remove_all(root, ec);
    if (failures) std::cout << "test_case FAILED\n";
    else std::cout << "test_case ok\n";
    return failures ? 1 : 0;
}
