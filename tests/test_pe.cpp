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

static void put16(std::vector<uint8_t>& b, size_t at, uint16_t value) {
    b[at] = static_cast<uint8_t>(value);
    b[at + 1] = static_cast<uint8_t>(value >> 8);
}

static void put32(std::vector<uint8_t>& b, size_t at, uint32_t value) {
    for (size_t i = 0; i < 4; ++i)
        b[at + i] = static_cast<uint8_t>(value >> (i * 8));
}

static std::vector<uint8_t> make_pe64(uint16_t optional_size, uint32_t directories,
                                      uint16_t sections = 0) {
    std::vector<uint8_t> b(0x400, 0);
    put16(b, 0, constants::DOS_MAGIC);
    put32(b, 0x3c, 0x80);
    put32(b, 0x80, constants::NT_MAGIC);
    put16(b, 0x84, 0x8664);              // IMAGE_FILE_HEADER.Machine
    put16(b, 0x86, sections);
    put16(b, 0x94, optional_size);
    put16(b, 0x98, constants::OPT_MAGIC_PE64);
    put32(b, 0x98 + 108, directories);  // NumberOfRvaAndSizes
    return b;
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

    // A declared optional header of only two bytes must not cause the parser
    // to read later bytes as fields or use uninitialized values.
    auto short_optional = make_pe64(2, 0);
    CHECK(!Analyzer(short_optional).analyze().valid);
    auto short_pe32 = short_optional;
    put16(short_pe32, 0x98, constants::OPT_MAGIC_PE32);
    CHECK(!Analyzer(short_pe32).analyze().valid);

    // A directory count cannot extend beyond SizeOfOptionalHeader, even when
    // the file buffer itself contains bytes at those offsets.
    auto short_directories = make_pe64(112, 1);
    CHECK(!Analyzer(short_directories).analyze().valid);
    auto short_pe32_directories = make_pe64(96, 0);
    put16(short_pe32_directories, 0x98, constants::OPT_MAGIC_PE32);
    put32(short_pe32_directories, 0x98 + 92, 1);
    CHECK(!Analyzer(short_pe32_directories).analyze().valid);

    // A PE with no security directory has no safe Authenticode hash range.
    auto no_security_directory = make_pe64(120, 1);
    Info no_security = Analyzer(no_security_directory).analyze();
    CHECK(no_security.valid && !no_security.ah_ready);

    // A malicious raw pointer plus RVA delta must not wrap around to a fake
    // import descriptor in the DOS header.
    auto raw_overflow = make_pe64(128, 2, 1);
    put32(raw_overflow, 0x98 + 112 + 8, 0x1020); // import directory RVA
    const size_t section = 0x98 + 128;
    put32(raw_overflow, section + 8, 0x80);       // VirtualSize
    put32(raw_overflow, section + 12, 0x1000);    // VirtualAddress
    put32(raw_overflow, section + 16, 0x80);      // SizeOfRawData
    put32(raw_overflow, section + 20, 0xfffffff0u);
    put32(raw_overflow, 0x10 + 12, 0x40);         // fake descriptor name RVA
    const char* fake_name = "fake.dll";
    for (size_t i = 0; fake_name[i]; ++i) raw_overflow[0x40 + i] = fake_name[i];
    Info overflow = Analyzer(raw_overflow).analyze();
    CHECK(overflow.valid && overflow.imports.empty());

    // An RVA above 0xfffffff0 can still map to a section if the range check
    // is performed without 32-bit addition overflow.
    auto high_rva = make_pe64(128, 2, 1);
    put32(high_rva, 0x98 + 112 + 8, 0xfffffff5u);
    put32(high_rva, section + 8, 0x80);
    put32(high_rva, section + 12, 0xfffffff0u);
    put32(high_rva, section + 16, 0x80);
    put32(high_rva, section + 20, 0x200);
    put32(high_rva, 0x205 + 12, 0x40);
    for (size_t i = 0; fake_name[i]; ++i) high_rva[0x40 + i] = fake_name[i];
    Info high = Analyzer(high_rva).analyze();
    CHECK(high.valid && high.imports.size() == 1 &&
          high.imports[0].dll == "fake.dll");

    // Repeated descriptors that point to the same long thunk table must have
    // a shared work limit, instead of multiplying the per-DLL limit.
    auto repeated_imports = make_pe64(128, 2, 1);
    repeated_imports.resize(0x30000, 0);
    put32(repeated_imports, 0x98 + 112 + 8, 0x1100);
    put32(repeated_imports, section + 8, 0x20000);
    put32(repeated_imports, section + 12, 0x1000);
    put32(repeated_imports, section + 16, 0x20000);
    put32(repeated_imports, section + 20, 0x200);
    for (size_t i = 0; i < 5; ++i) {
        put32(repeated_imports, 0x300 + i * 20, 0x2000);      // thunk RVA
        put32(repeated_imports, 0x300 + i * 20 + 12, 0x40);  // DLL name RVA
    }
    for (size_t i = 0; i < 8192; ++i) {
        put32(repeated_imports, 0x1200 + i * 8, 1);
        put32(repeated_imports, 0x1200 + i * 8 + 4, 0x80000000u);
    }
    for (size_t i = 0; fake_name[i]; ++i) repeated_imports[0x40 + i] = fake_name[i];
    Info bounded = Analyzer(repeated_imports).analyze();
    CHECK(bounded.valid && bounded.total_imports > 0 &&
          bounded.total_imports <= 32768 && bounded.imports.size() <= 4);

    std::cout << "\n" << (failures ? std::to_string(failures)+" PE test(s) failed"
                                   : "ALL PE TESTS PASSED") << "\n";
    return failures;
}
