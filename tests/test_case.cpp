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

    core::Options verify = opts;
    verify.verify = true;
    casework::RunResult checked;
    CHECK(casework::build(verify, checked, error));
    CHECK(checked.reused == 6);

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
