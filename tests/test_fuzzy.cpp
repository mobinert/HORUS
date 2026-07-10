#include "../src/fuzzy.hpp"
#include <iostream>
#include <vector>
#include <string>

using namespace horus::fuzzy;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main() {
    // a buffer with enough structure/entropy for a stable TLSH
    std::vector<uint8_t> a(8192);
    for (size_t i = 0; i < a.size(); ++i) a[i] = (uint8_t)((i * 131 + 7) ^ (i >> 3));

    std::string t1 = tlsh(a), t2 = tlsh(a);
    CHECK(t1 == t2);                                 // deterministic
    CHECK(t1.size() == 72 && t1.rfind("T1", 0) == 0);// canonical "T1" + 70 hex
    CHECK(tlsh_diff(t1, t1) == 0);                   // identical -> 0

    // a handful of byte flips should stay close (edit-resistant)
    std::vector<uint8_t> b = a;
    for (int i = 0; i < 8; ++i) b[1000 + i * 100] ^= 0xFF;
    int d = tlsh_diff(t1, tlsh(b));
    CHECK(d > 0 && d < 60);

    // below the 50-byte floor TLSH declines to produce a hash
    CHECK(tlsh(std::vector<uint8_t>(10, 0x41)).empty());

    // ssdeep: deterministic, structured, and the canonical empty result
    CHECK(ssdeep(a) == ssdeep(a));
    CHECK(ssdeep(std::vector<uint8_t>{}) == "3::");
    CHECK(ssdeep(a).find(':') != std::string::npos);

    std::cout << (failures ? std::to_string(failures) + " FUZZY test(s) failed"
                           : "ALL FUZZY TESTS PASSED") << "\n";
    return failures;
}
