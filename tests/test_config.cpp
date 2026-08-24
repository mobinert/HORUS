#include "config.hpp"
#include <fstream>
#include <cstdio>
#include <iostream>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main(){
    std::string p = "horus_test_cfg.json";
    { std::ofstream f(p, std::ios::binary);
      f << "{\"vt_key\":\"ABC\",\"abuse_key\":\"XYZ\",\"cache_ttl_hours\":12}"; }

    config::Config c = config::load(p);
    CHECK(c.loaded);
    CHECK(c.vt_key == "ABC");
    CHECK(c.abuse_key == "XYZ");
    CHECK(c.cache_ttl_hours == 12);

    // precedence: an already-set flag beats config; empties get filled
    core::Options o; o.vt_key = "fromflag";
    config::apply(o, c);
    CHECK(o.vt_key == "fromflag");
    CHECK(o.abuse_key == "XYZ");
    CHECK(o.cache_ttl_hours == 12);

    core::Options off;
    off.cache_ttl_hours = 0;
    off.cache_ttl_set = true;
    config::apply(off, c);
    CHECK(off.cache_ttl_hours == 0);

    // malformed file must not throw and must not report loaded
    { std::ofstream f(p, std::ios::binary); f << "{ this is not json"; }
    config::Config bad = config::load(p);
    CHECK(!bad.loaded);

    // missing file is fine too
    config::Config none = config::load("horus_test_does_not_exist.json");
    CHECK(!none.loaded);

    std::remove(p.c_str());
    std::cout << (failures ? "test_config FAILED\n" : "test_config ok\n");
    return failures ? 1 : 0;
}
