#include "cache.hpp"
#include <cstdio>
#include <iostream>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main(){
    std::string p = "horus_test_cache.json";

    intel::SourceResult r;
    r.source = "VirusTotal"; r.ok = true; r.found = true;
    r.summary = "3 / 70"; r.malicious = 3; r.total = 70;
    r.details = {{"reputation","-5"},{"category","malware"}};

    cache::Store m;
    cache::Entry e; e.ts = cache::now_epoch(); e.results = {r};
    m["1.2.3.4"] = e;
    cache::save(m, p);

    // round-trip through disk
    cache::Store back = cache::load(p);
    CHECK(back.count("1.2.3.4") == 1);

    std::vector<intel::SourceResult> out;
    CHECK(cache::fresh(back, "1.2.3.4", 24, out));
    CHECK(out.size() == 1);
    CHECK(out[0].source == "VirusTotal");
    CHECK(out[0].malicious == 3 && out[0].total == 70);
    CHECK(out[0].details.size() == 2 && out[0].details[0].first == "reputation");

    // TTL semantics
    back["1.2.3.4"].ts = cache::now_epoch() - 100000;   // ~27h old
    std::vector<intel::SourceResult> out2;
    CHECK(!cache::fresh(back, "1.2.3.4", 1, out2));   // stale for a 1h TTL
    CHECK(!cache::fresh(back, "1.2.3.4", 0, out2));   // ttl 0 -> caching off
    CHECK(!cache::fresh(back, "9.9.9.9", 24, out2));  // absent key

    std::remove(p.c_str());
    std::cout << (failures ? "test_cache FAILED\n" : "test_cache ok\n");
    return failures ? 1 : 0;
}
