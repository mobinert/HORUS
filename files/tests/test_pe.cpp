#include "../src/pe.hpp"
#include <fstream>
#include <iostream>
#include <set>

using namespace argus::pe;

static std::vector<uint8_t> slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

int failures = 0;
#define CHECK(cond) do { if(!(cond)){ std::cerr<<"FAIL line "<<__LINE__<<": " #cond "\n"; ++failures; } } while(0)

static void dump_and_check(const std::string& path, bool want64, int want_sections) {
    std::cout << "\n=== " << path << " ===\n";
    Analyzer a(slurp(path));
    Info info = a.analyze();

    CHECK(info.valid);
    if (!info.valid) { std::cerr << "  error: " << info.error << "\n"; return; }

    std::cout << "  bitness     : " << (info.is_64bit ? "64-bit" : "32-bit")
              << " (" << info.machine_name << ")\n";
    std::cout << "  subsystem   : " << info.subsystem_name << "\n";
    std::cout << "  compiled    : " << info.compile_time << "\n";
    std::cout << "  image base  : 0x" << std::hex << info.image_base << std::dec << "\n";
    std::cout << "  entry RVA   : 0x" << std::hex << info.entry_point_rva << std::dec << "\n";
    std::cout << "  overall H   : " << info.overall_entropy << "\n";

    CHECK(info.is_64bit == want64);
    CHECK((int)info.sections.size() == want_sections);

    std::cout << "  sections    :\n";
    for (auto& s : info.sections) {
        std::cout << "    " << s.name << "  H=" << s.entropy
                  << (s.executable ? " X" : " -")
                  << (s.readable   ? "R"  : "-")
                  << (s.writable   ? "W"  : "-")
                  << (s.is_rwx() ? "  [RWX!]" : "") << "\n";
        CHECK(s.entropy >= 0.0 && s.entropy <= 8.0001);
    }

    std::cout << "  imports     : " << info.imports.size() << " DLLs, "
              << info.total_imports << " functions\n";
    std::set<std::string> dlls;
    for (auto& imp : info.imports) {
        dlls.insert(imp.dll);
        std::cout << "    " << imp.dll << " (" << imp.functions.size() << " fn)\n";
    }
    // Ground truth: both samples import KERNEL32 and VCRUNTIME140
    CHECK(dlls.count("KERNEL32.dll") == 1);
    CHECK(dlls.count("VCRUNTIME140.dll") == 1);
    CHECK(info.total_imports > 0);

    // Show a couple of resolved function names to prove name-parsing works
    if (!info.imports.empty() && !info.imports[0].functions.empty()) {
        std::cout << "    e.g. " << info.imports[0].dll << "!"
                  << info.imports[0].functions[0] << "\n";
    }

    std::cout << "  imphash str : "
              << info.imphash_string.substr(0, 80)
              << (info.imphash_string.size() > 80 ? "..." : "") << "\n";
    // imphash string must be lowercase and comma-structured
    for (char c : info.imphash_string)
        CHECK(!(c >= 'A' && c <= 'Z'));
}

int main() {
    dump_and_check("test/sample64.exe", true, 6);
    dump_and_check("test/sample32.exe", false, 5);

    // negative test - feed it junk
    Analyzer junk(std::vector<uint8_t>{'h','e','l','l','o',0,1,2,3,4});
    CHECK(!junk.analyze().valid);

    // negative test - empty
    Analyzer empty(std::vector<uint8_t>{});
    CHECK(!empty.analyze().valid);

    std::cout << "\n" << (failures ? std::to_string(failures)+" PE test(s) failed"
                                   : "ALL PE TESTS PASSED") << "\n";
    return failures;
}
