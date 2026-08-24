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
#include <cstddef>

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
    size_t                             max_response_bytes = 16u * 1024u * 1024u;
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

inline bool append_limited(Response& response, const char* data, size_t size,
                           size_t limit) {
    if (response.body.size() > limit || size > limit - response.body.size()) {
        response.ok = false;
        response.error = "HTTP response exceeds " + std::to_string(limit) + " bytes";
        return false;
    }
    response.body.append(data, size);
    return true;
}

} // namespace http
} // namespace horus
