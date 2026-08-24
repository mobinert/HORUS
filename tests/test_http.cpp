#include "http.hpp"

#include <iostream>
#include <string>

using namespace horus;
int failures = 0;
#define CHECK(c) do{ if(!(c)){ std::cerr<<"FAIL line "<<__LINE__<<": " #c "\n"; ++failures; } }while(0)

int main() {
    http::Response response;
    CHECK(http::append_limited(response, "1234", 4, 8));
    CHECK(http::append_limited(response, "5678", 4, 8));
    CHECK(response.body == "12345678");
    CHECK(!http::append_limited(response, "9", 1, 8));
    CHECK(!response.ok);
    CHECK(response.error.find("exceeds 8 bytes") != std::string::npos);

    http::Request request;
    CHECK(request.max_response_bytes == 16u * 1024u * 1024u);
    std::cout << (failures ? "test_http FAILED\n" : "test_http ok\n");
    return failures ? 1 : 0;
}
