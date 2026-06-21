// ---------------------------------------------------------------------------
//  http.cpp  -  WinHTTP implementation
// ---------------------------------------------------------------------------
#include "http.hpp"

#include <windows.h>
#include <winhttp.h>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace horus {
namespace http {
namespace {

// One RAII type for every WinHTTP handle - session, connection, request all
// close the same way, so we don't leak a handle on an early return.
struct WinHttpHandle {
    HINTERNET h = nullptr;
    WinHttpHandle() = default;
    explicit WinHttpHandle(HINTERNET hh) : h(hh) {}
    ~WinHttpHandle() { if (h) WinHttpCloseHandle(h); }
    WinHttpHandle(const WinHttpHandle&) = delete;
    WinHttpHandle& operator=(const WinHttpHandle&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int need = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(need, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], need);
    return w;
}

std::string last_error(const char* stage) {
    DWORD e = GetLastError();
    return std::string(stage) + " failed (WinHTTP error " + std::to_string(e) + ")";
}

} // namespace

Response perform(const Request& req) {
    Response resp;

    WinHttpHandle session(WinHttpOpen(L"ARGUS/1.0 (threat-intel CLI)",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) { resp.error = last_error("WinHttpOpen"); return resp; }

    WinHttpSetTimeouts(session.h, req.timeout_ms, req.timeout_ms,
                       req.timeout_ms, req.timeout_ms);

    INTERNET_PORT port = req.https ? INTERNET_DEFAULT_HTTPS_PORT
                                   : INTERNET_DEFAULT_HTTP_PORT;
    WinHttpHandle connect(WinHttpConnect(session.h, widen(req.host).c_str(), port, 0));
    if (!connect) { resp.error = last_error("WinHttpConnect"); return resp; }

    DWORD flags = req.https ? WINHTTP_FLAG_SECURE : 0;
    WinHttpHandle request(WinHttpOpenRequest(connect.h,
                                             widen(req.method).c_str(),
                                             widen(req.path).c_str(),
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request) { resp.error = last_error("WinHttpOpenRequest"); return resp; }

    // Fold the header map into the single CRLF-delimited blob WinHTTP wants.
    std::wstring header_blob;
    for (const auto& kv : req.headers)
        header_blob += widen(kv.first + ": " + kv.second + "\r\n");
    if (!header_blob.empty())
        WinHttpAddRequestHeaders(request.h, header_blob.c_str(),
                                 (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = WinHttpSendRequest(
        request.h, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        req.body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)req.body.data(),
        (DWORD)req.body.size(), (DWORD)req.body.size(), 0);
    if (!sent) { resp.error = last_error("WinHttpSendRequest"); return resp; }

    if (!WinHttpReceiveResponse(request.h, nullptr)) {
        resp.error = last_error("WinHttpReceiveResponse");
        return resp;
    }

    // Status code as a number.
    DWORD status = 0, status_sz = sizeof(status);
    WinHttpQueryHeaders(request.h,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_sz,
                        WINHTTP_NO_HEADER_INDEX);
    resp.status = (int)status;

    // Drain the body in whatever sized pieces WinHTTP hands us.
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available)) {
            resp.error = last_error("WinHttpQueryDataAvailable");
            return resp;
        }
        if (available == 0) break;

        std::vector<char> chunk(available);
        DWORD read = 0;
        if (!WinHttpReadData(request.h, chunk.data(), available, &read)) {
            resp.error = last_error("WinHttpReadData");
            return resp;
        }
        if (read == 0) break;
        resp.body.append(chunk.data(), read);
    }

    resp.ok = true;
    return resp;
}

} // namespace http
} // namespace horus
