#include "core.hpp"
#include "json.hpp"
#include <iostream>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

static bool is_json(const std::string& s){ try{ json::parse(s); return true; }catch(...){ return false; } }

int main(int argc, char** argv){
    // 1. full pipeline on our own binary (a real PE)
    core::Options o; o.target = argv[0];
    core::FileReport rep = core::analyze_file(o);
    CHECK(rep.ok);
    CHECK(rep.info.valid);
    CHECK(!rep.hashes.sha256.empty());
    CHECK(rep.final_score >= 0 && rep.final_score <= 100);

    // 2. the two JSON serialisers both emit well-formed JSON
    std::string j = core::file_json(o, rep);
    CHECK(j.find("\"sha256\"") != std::string::npos);
    CHECK(is_json(core::gui_file_json(o, rep)));

    // 3. verdict + vt score helpers
    CHECK(std::string(core::verdict_for_score(75)) == "LIKELY MALICIOUS");
    CHECK(std::string(core::verdict_for_score(40)) == "SUSPICIOUS");
    CHECK(std::string(core::verdict_for_score(0))  == "CLEAN");
    CHECK(core::vt_score_from(0) == 0);
    CHECK(core::vt_score_from(5) > 0);
    CHECK(core::compute_worst({}) == 0);

    // 4. indicator path with no keys - classifies but finds no source
    core::Options oi; oi.target = "44d88612fea8a8f36de82e1278abb02f";
    core::IndicatorReport ir = core::enrich_ioc(oi);
    CHECK(ir.ok);
    CHECK(ir.type != IocType::Unknown);
    CHECK(is_json(core::gui_indicator_json(ir)));

    // 5. a bad target is reported, not crashed
    core::Options ob; ob.target = "\?\?not-a-real-file-or-ioc\?\?";
    core::IndicatorReport br = core::enrich_ioc(ob);
    CHECK(!br.ok);

    std::cout << (failures ? "test_core FAILED\n" : "test_core ok\n");
    return failures ? 1 : 0;
}
