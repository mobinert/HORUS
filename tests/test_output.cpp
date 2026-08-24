#include "output.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main() {
    namespace fs = std::filesystem;
    const fs::path good = "horus_test_atomic.txt";
    std::string error;
    CHECK(output::write_atomic(good, "first", error));
    CHECK(output::write_atomic(good, "second", error));
    std::ifstream in(good, std::ios::binary);
    std::ostringstream text; text << in.rdbuf();
    CHECK(text.str() == "second");
    std::error_code ec;
    fs::remove(good, ec);

    const fs::path missing = fs::path("horus_missing_parent_" +
        std::to_string(GetCurrentProcessId())) / "out.txt";
    CHECK(!output::write_atomic(missing, "nope", error));
    CHECK(!error.empty());
    CHECK(output::csv_cell("=2+2").rfind("'=", 0) == 0);
    CHECK(output::csv_cell("+2+2").rfind("'+", 0) == 0);
    CHECK(output::csv_cell("-2+2").rfind("'-", 0) == 0);
    CHECK(output::csv_cell("@SUM(A1:A2)").rfind("'@", 0) == 0);
    CHECK(output::csv_cell("\t=2+2").rfind("'\t", 0) == 0);
    CHECK(output::csv_cell("\r=2+2").rfind("\"'\r", 0) == 0);
    CHECK(output::csv_cell("line\nnext").front() == '"');

    std::cout << (failures ? "test_output FAILED\n" : "test_output ok\n");
    return failures ? 1 : 0;
}
