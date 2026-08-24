#include "gui/host.hpp"
#include "encoding.hpp"

#include <iostream>
#include <string>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

static size_t occurrences(const std::string& text, const std::string& needle) {
    size_t count = 0, at = 0;
    while ((at = text.find(needle, at)) != std::string::npos) { ++count; at += needle.size(); }
    return count;
}

int main() {
    const std::string payload = "</script><script>window.horusPwned=1</script>";
    const std::string report = "{\"kind\":\"error\",\"error\":\"" + payload + "\"}";
    const std::string html = gui::render_page(report);

    CHECK(html.find(payload) == std::string::npos);
    CHECK(html.find("__HORUS_REPORT_B64__") == std::string::npos);
    CHECK(html.find(encoding::base64(report)) != std::string::npos);
    CHECK(occurrences(html, "<script>") == 1);
    CHECK(occurrences(html, "</script>") == 1);
    CHECK(html.find("innerHTML") == std::string::npos);

    core::Options opts;
    opts.target = "pdb-sample.exe";
    core::FileReport file;
    file.ok = true;
    file.info.valid = true;
    file.info.pdb_path = payload;
    file.analysis_status = core::AnalysisStatus::Complete;
    file.has_score = true;
    const std::string pdb_json = core::gui_file_json(opts, file);
    const std::string pdb_html = gui::render_page(pdb_json);
    CHECK(pdb_json.find(payload) != std::string::npos);
    CHECK(pdb_html.find(payload) == std::string::npos);
    CHECK(pdb_html.find(encoding::base64(pdb_json)) != std::string::npos);

    std::cout << (failures ? "test_report FAILED\n" : "test_report ok\n");
    return failures ? 1 : 0;
}
