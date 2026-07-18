#include "core.hpp"
#include "fuzzy.hpp"
#include <iostream>

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

    std::cout << (failures ? "test_diff FAILED\n" : "test_diff ok\n");
    return failures ? 1 : 0;
}
