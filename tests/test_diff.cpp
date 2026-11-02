#include "core.hpp"
#include "diff.hpp"
#include "fuzzy.hpp"
#include "json.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main(int argc, char** argv){
    // diff a file against itself: everything identical, TLSH distance 0
    core::Options o; o.target = argv[0];
    core::FileReport a = core::analyze_file(o);
    core::FileReport b = core::analyze_file(o);
    CHECK(a.ok && b.ok);
    CHECK(a.hashes.sha256 == b.hashes.sha256);
    CHECK(a.imphash == b.imphash);
    CHECK(!a.tlsh.empty());
    CHECK(fuzzy::tlsh_diff(a.tlsh, b.tlsh) == 0);

    // sanity: tlsh_diff is symmetric and non-negative
    CHECK(fuzzy::tlsh_diff(a.tlsh, b.tlsh) == fuzzy::tlsh_diff(b.tlsh, a.tlsh));

    core::Options opts;
    opts.json = true;
    auto capture_diff = [&](const std::string& left, const std::string& right) {
        std::ostringstream captured;
        std::streambuf* original = std::cout.rdbuf(captured.rdbuf());
        int code = diffs::run(opts, left, right);
        std::cout.rdbuf(original);
        return std::make_pair(code, captured.str());
    };

    auto [same_code, same_text] = capture_diff(argv[0], argv[0]);
    auto same = json::parse(same_text);
    CHECK(same_code == (a.final_score >= 30 ? 1 : 0));
    CHECK(same["kind"].as_string() == "diff");
    CHECK(same["analysis_status"].as_string() == "complete");
    CHECK(same["comparison"]["sha256_match"].as_bool());
    CHECK(a.imphash.empty() ? same["comparison"]["imphash_match"].is_null()
                            : same["comparison"]["imphash_match"].as_bool());
    CHECK(same["comparison"]["tlsh_distance"].as_int(-1) == 0);
    CHECK(same["comparison"]["sections"].is_array());
    CHECK(same["file_a"]["path"].as_string() == argv[0]);
    CHECK(same["file_b"]["score"].is_number());

    namespace fs = std::filesystem;
    fs::path plain = fs::temp_directory_path() /
        ("horus-diff-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".txt");
    {
        std::ofstream output(plain, std::ios::binary);
        output << "plain text";
    }
    auto [unknown_code, unknown_text] = capture_diff(plain.string(), plain.string());
    auto unknown = json::parse(unknown_text);
    CHECK(unknown_code == 3);
    CHECK(unknown["analysis_status"].as_string() == "unknown");
    CHECK(unknown["file_a"]["verdict"].as_string() == "UNKNOWN");
    CHECK(unknown["file_b"]["score"].is_null());
    CHECK(unknown["comparison"]["sha256_match"].as_bool());
    CHECK(unknown["comparison"]["imphash_match"].is_null());
    CHECK(unknown["comparison"]["tlsh_distance"].is_null());
    CHECK(unknown["comparison"]["sections"].size() == 0);

    auto [mixed_code, mixed_text] = capture_diff(argv[0], plain.string());
    auto mixed = json::parse(mixed_text);
    CHECK(mixed_code == 3);
    CHECK(mixed["analysis_status"].as_string() == "unknown");
    CHECK(mixed["file_a"]["is_pe"].as_bool());
    CHECK(!mixed["file_b"]["is_pe"].as_bool());

    opts.json = false;
    auto [plain_code, plain_text] = capture_diff(plain.string(), plain.string());
    CHECK(plain_code == 3);
    CHECK(plain_text.find("UNKNOWN") != std::string::npos);
    CHECK(plain_text.find("CLEAN") == std::string::npos);

    core::FileReport skipped;
    skipped.analysis_status = core::AnalysisStatus::Skipped;
    CHECK(diffs::comparison_status(a, skipped) == core::AnalysisStatus::Skipped);
    CHECK(diffs::comparison_exit_code(a, skipped) == 3);
    fs::remove(plain);

    std::cout << (failures ? "test_diff FAILED\n" : "test_diff ok\n");
    return failures ? 1 : 0;
}
