#include "core.hpp"
#include "json.hpp"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <atomic>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

static bool is_json(const std::string& s){ try{ json::parse(s); return true; }catch(...){ return false; } }

class MockSource final : public intel::IntelSource {
public:
    mutable std::atomic<int> calls{0};
    std::string name() const override { return "Mock"; }
    bool supports(IocType type) const override {
        return type == IocType::SHA256 || type == IocType::Url || type == IocType::IPv4;
    }
    intel::SourceResult lookup(const std::string&, IocType type) const override {
        ++calls;
        intel::SourceResult result;
        result.source = name();
        result.ok = true;
        result.found = true;
        result.summary = "mock report";
        if (type == IocType::SHA256) { result.malicious = 1; result.total = 10; }
        else result.score = 70;
        return result;
    }
};

int main(int argc, char** argv){
    // 1. full pipeline on our own binary (a real PE)
    core::Options o; o.target = argv[0];
    core::FileReport rep = core::analyze_file(o);
    CHECK(rep.ok);
    CHECK(rep.info.valid);
    CHECK(!rep.hashes.sha256.empty());
    CHECK(rep.analysis_status == core::AnalysisStatus::Complete);
    CHECK(rep.has_score);
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
    CHECK(ir.analysis_status == core::AnalysisStatus::Unknown);
    CHECK(!ir.has_score);
    CHECK(core::analysis_exit_code(ir.analysis_status, ir.has_score, ir.worst) == 3);
    CHECK(is_json(core::gui_indicator_json(ir)));

    // 5. a bad target is reported, not crashed
    core::Options ob; ob.target = "\?\?not-a-real-file-or-ioc\?\?";
    core::IndicatorReport br = core::enrich_ioc(ob);
    CHECK(!br.ok);

    // 6. Inventory-only files must not get a false CLEAN verdict.
    const char* plain_path = "horus_test_plain_file";
    { std::ofstream f(plain_path, std::ios::binary); f << "hello from a non-PE file"; }
    core::Options plain_opts; plain_opts.target = plain_path;
    core::FileReport plain = core::analyze_file(plain_opts);
    CHECK(plain.ok);
    CHECK(!plain.info.valid);
    CHECK(plain.analysis_status == core::AnalysisStatus::Unknown);
    CHECK(!plain.has_score);
    auto plain_json = json::parse(core::file_json(plain_opts, plain));
    CHECK(plain_json["final_score"].is_null());
    CHECK(plain_json["verdict"].as_string() == "UNKNOWN");
    CHECK(core::analysis_exit_code(plain.analysis_status, plain.has_score, plain.final_score) == 3);
    std::remove(plain_path);

    auto embedded = core::scan_strings({"before http:// after", "https:///bad", "https://good.example/a"});
    CHECK(embedded.urls.size() == 1);
    CHECK(embedded.urls.count("https://good.example/a") == 1);

    // 7. File and embedded-IOC enrichment is exercised through an in-memory provider.
    auto mock = std::make_shared<MockSource>();
    std::vector<std::shared_ptr<intel::IntelSource>> sources{mock};
    core::FileReport pivot;
    pivot.hashes.sha256 = std::string(64, 'a');
    pivot.emb.urls.insert("https://pivot.example/a");
    pivot.emb.ips.insert("8.8.8.8");
    core::Options enrich;
    enrich.enrich = true;
    enrich.max_lookups = 3;
    core::enrich_file_report(pivot, enrich, sources);
    CHECK(mock->calls == 3);
    CHECK(pivot.hash_intel.size() == 1);
    CHECK(pivot.embedded_intel.size() == 2);
    CHECK(is_json(core::file_json(enrich, pivot)));
    CHECK(is_json(core::gui_file_json(enrich, pivot)));

    core::FileReport limited;
    limited.hashes.sha256 = std::string(64, 'b');
    limited.emb.urls.insert("https://second.example/a");
    enrich.max_lookups = 1;
    core::enrich_file_report(limited, enrich, sources);
    CHECK(limited.hash_intel.size() == 1);
    CHECK(limited.embedded_intel.empty());
    CHECK(!limited.source_errors.empty());

    std::cout << (failures ? "test_core FAILED\n" : "test_core ok\n");
    return failures ? 1 : 0;
}
