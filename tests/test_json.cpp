#include "../src/json.hpp"
#include <iostream>
#include <cassert>

using namespace horus;

int failures = 0;
#define CHECK(cond) do { if(!(cond)){ std::cerr << "FAIL line " << __LINE__ << ": " #cond "\n"; ++failures; } } while(0)

int main() {
    // 1. Realistic VirusTotal v3 file-report skeleton
    std::string vt = R"({
      "data": {
        "type": "file",
        "id": "abc123",
        "attributes": {
          "meaningful_name": "invoice.exe",
          "type_description": "Win32 EXE",
          "reputation": -45,
          "last_analysis_stats": {
            "harmless": 0, "malicious": 51, "suspicious": 2,
            "undetected": 19, "timeout": 0
          },
          "names": ["invoice.exe", "\u0070ayload.bin", "to\\tricky"],
          "signature_info": { "verified": false }
        }
      }
    })";
    auto doc = json::parse(vt);
    auto& attr = doc["data"]["attributes"];
    CHECK(attr["meaningful_name"].as_string() == "invoice.exe");
    CHECK(attr["reputation"].as_int() == -45);
    CHECK(attr["last_analysis_stats"]["malicious"].as_int() == 51);
    CHECK(attr["last_analysis_stats"]["suspicious"].as_int() == 2);
    CHECK(attr["names"].size() == 3);
    CHECK(attr["names"][1].as_string() == "payload.bin");   // \u0070 -> 'p'
    CHECK(attr["names"][2].as_string() == "to\\tricky");    // JSON \\ -> literal backslash
    CHECK(attr["signature_info"]["verified"].as_bool() == false);

    // 2. Missing keys must be null-safe, not crash
    CHECK(doc["nope"]["still_nope"][3].is_null());
    CHECK(doc["data"]["attributes"]["ghost"].as_string("def") == "def");

    // 3. AbuseIPDB-shaped numbers, including scientific notation and floats
    std::string ab = R"({"data":{"abuseConfidenceScore":100,"score":1.5e2,"latitude":-37.81})";
    // (intentionally malformed - missing closing brace -> should throw)
    bool threw = false;
    try { json::parse(ab); } catch (const std::exception&) { threw = true; }
    CHECK(threw);

    std::string ab2 = R"({"data":{"abuseConfidenceScore":100,"score":1.5e2,"latitude":-37.81,"isTor":true}})";
    auto a = json::parse(ab2);
    CHECK(a["data"]["abuseConfidenceScore"].as_int() == 100);
    CHECK(a["data"]["score"].as_double() == 150.0);
    CHECK(a["data"]["latitude"].as_double() < -37.0 && a["data"]["latitude"].as_double() > -38.0);
    CHECK(a["data"]["isTor"].as_bool() == true);

    // 4. Empty containers and nesting
    auto e = json::parse("{\"a\":[],\"b\":{},\"c\":[[],[1,2,[3]]]}");
    CHECK(e["a"].is_array() && e["a"].size() == 0);
    CHECK(e["b"].is_object() && e["b"].size() == 0);
    CHECK(e["c"][1][2][0].as_int() == 3);

    // 5. Unicode above BMP (emoji, surrogate pair) -> 4-byte UTF-8
    auto u = json::parse(R"({"s":"A\uD83D\uDE00B"})");
    std::string s = u["s"].as_string();
    CHECK(s.size() == 6);            // 'A' + 4 bytes + 'B'
    CHECK((unsigned char)s[1] == 0xF0);

    // 6. Whitespace tolerance
    auto w = json::parse("   {  \"x\"  :  42  }  ");
    CHECK(w["x"].as_int() == 42);

    if (failures == 0) std::cout << "ALL JSON TESTS PASSED\n";
    else std::cout << failures << " JSON test(s) failed\n";
    return failures;
}
