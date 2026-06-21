// ---------------------------------------------------------------------------
//  http.hpp  -  a tiny HTTPS client built on WinHTTP
//
//  Just enough of an HTTP surface to talk to JSON REST APIs: pick a verb, set a
//  few headers (an API key, an Accept), optionally attach a body, get the status
//  and the response text back. WinHTTP rather than libcurl so the binary stays
//  dependency-free and links only against what ships with Windows.
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <map>

namespace horus {
namespace http {

struct Request {
    std::string                        host;          // "www.virustotal.com"
    std::string                        path;          // "/api/v3/files/<id>"
    std::string                        method = "GET";
    std::map<std::string, std::string> headers;
    std::string                        body;          // POST payload, if any
    bool                               https  = true;
    int                                timeout_ms = 15000;
};

struct Response {
    bool        ok     = false;   // transport succeeded (not necessarily 2xx)
    int         status = 0;       // HTTP status code
    std::string body;
    std::string error;            // populated when ok == false
};

// Perform the request synchronously. Network/handle failures come back with
// ok=false and a human-readable error rather than throwing.
Response perform(const Request& req);

} // namespace http
} // namespace horus
