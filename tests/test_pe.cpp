#include "../src/pe.hpp"
#include <fstream>
#include <iostream>
#include <set>
#include <string>

using namespace horus::pe;

static std::vector<uint8_t> slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

int failures = 0;
#define CHECK(cond) do { if(!(cond)){ std::cerr<<"FAIL line "<<__LINE__<<": " #cond "\n"; ++failures; } } while(0)

int main(int argc, char** argv) {
    // Parse this very test binary. It's a real PE that always exists, so we get
    // genuine header/section/import coverage with no external fixtures. A few
    // invariants hold for any linked executable regardless of toolchain.
    const std::string self = argv[0];
    Analyzer a(slurp(self));
    Info info = a.analyze();

    std::cout << "=== self: " << self << " ===\n";
    CHECK(info.valid);
    if (info.valid) {
        CHECK(info.is_64bit == (sizeof(void*) == 8));    // matches build arch
        CHECK(!info.sections.empty());
        for (auto& s : info.sections) CHECK(s.entropy >= 0.0 && s.entropy <= 8.0001);
        CHECK(info.overall_entropy >= 0.0 && info.overall_entropy <= 8.0001);

        std::set<std::string> dlls;
        for (auto& imp : info.imports) dlls.insert(imp.dll);
        CHECK(dlls.count("KERNEL32.dll") == 1);
        CHECK(info.total_imports > 0);
        CHECK(info.entry_point_rva != 0);

        // imphash canonical string is lowercase, comma-joined
        for (char c : info.imphash_string) CHECK(!(c >= 'A' && c <= 'Z'));

        // v2.1 parser additions - authentihash ranges always resolve on a valid
        // PE; the Rich header is present on MSVC builds (informational elsewhere)
        CHECK(info.ah_ready);

        std::cout << "  bitness=" << (info.is_64bit ? "64" : "32")
                  << " sections=" << info.sections.size()
                  << " imports=" << info.total_imports
                  << " rich=" << (info.has_rich ? info.rich_entries.size() : 0)
                  << " tls_cb=" << info.tls_callback_count
                  << " pdb='" << info.pdb_path << "'\n";
    } else {
        std::cerr << "  error: " << info.error << "\n";
    }

    // negative test - feed it junk
    CHECK(!Analyzer(std::vector<uint8_t>{'h','e','l','l','o',0,1,2,3,4}).analyze().valid);
    // negative test - empty
    CHECK(!Analyzer(std::vector<uint8_t>{}).analyze().valid);

    std::cout << "\n" << (failures ? std::to_string(failures)+" PE test(s) failed"
                                   : "ALL PE TESTS PASSED") << "\n";
    return failures;
}
