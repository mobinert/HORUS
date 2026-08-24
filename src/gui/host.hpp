// ---------------------------------------------------------------------------
//  gui/host.hpp  -  the GUI back-end shared by horus.exe and horus-gui.exe
//
//  The glass console is a single self-contained HTML/CSS/JS page (embedded in
//  the binary at build time - see ui_html.hpp). The host runs the same core
//  engine the CLI does, splices the report JSON into the page, drops it in TEMP
//  and hands it to the shell. No sockets, no server, no third-party runtime -
//  it renders in whatever browser the box already trusts.
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "cache.hpp"
#include "config.hpp"
#include "encoding.hpp"
#include "output.hpp"
#include "gui/ui_html.hpp"     // generated: horus::gui::kIndexHtml

#include <string>

#if defined(_WIN32)
#  include <windows.h>
#  include <shellapi.h>
#  include <commdlg.h>
#endif

namespace horus {
namespace gui {

#if defined(_WIN32)
inline std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
inline std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
#endif

// Heuristic: were we double-clicked from Explorer (only process on the console)?
inline bool launched_from_gui() {
#if defined(_WIN32)
    DWORD procs[3];
    DWORD n = GetConsoleProcessList(procs, 3);
    return n <= 1;
#else
    return false;
#endif
}

// Native "open file" dialog. Empty string if cancelled.
inline std::string pick_file() {
#if defined(_WIN32)
    wchar_t buf[1024] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"All files\0*.*\0Executables\0*.exe;*.dll;*.sys\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = 1024;
    ofn.lpstrTitle  = L"HORUS - pick a file to analyze";
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) return narrow(buf);
    return {};
#else
    return {};
#endif
}

inline std::string temp_dir() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, buf);
    if (n == 0 || n > MAX_PATH) return ".";
    return narrow(std::wstring(buf, n));
#else
    return ".";
#endif
}

// The report travels as Base64 so untrusted strings never become script source.
inline std::string render_page(const std::string& json) {
    std::string html = kIndexHtml;
    const std::string marker = "__HORUS_REPORT_B64__";
    size_t at = html.find(marker);
    if (at != std::string::npos)
        html.replace(at, marker.size(), encoding::base64(json));
    return html;
}

inline bool write_report(const std::string& html, std::string& path,
                         std::string& error) {
    path = temp_dir();
    if (!path.empty() && path.back() != '\\' && path.back() != '/') path += "\\";
#if defined(_WIN32)
    path += "horus-report-" + std::to_string(GetCurrentProcessId()) + ".html";
#else
    path += "horus-report.html";
#endif
    return output::write_atomic(std::filesystem::path(path), html, error);
}

inline bool open_in_browser(const std::string& path) {
#if defined(_WIN32)
    return reinterpret_cast<INT_PTR>(ShellExecuteW(
        nullptr, L"open", widen(path).c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32;
#else
    (void)path;
    return false;
#endif
}

struct PageData {
    std::string json = "null";
    int exit_code = 0;
};

inline PageData analyze(core::Options opts) {
    PageData page;
    if (opts.target.empty()) return page;
    if (core::file_exists(opts.target)) {
        core::FileReport rep = core::analyze_file(opts);
        if (!rep.ok) {
            page.json = "{\"kind\":\"error\",\"error\":\"" + core::json_escape(rep.error) + "\"}";
            page.exit_code = 2;
            return page;
        }
        page.json = core::gui_file_json(opts, rep);
        page.exit_code = core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.final_score);
        return page;
    }
    core::IndicatorReport rep = opts.enrich && opts.cache_ttl_hours > 0
                              ? cache::enrich_cached(opts) : core::enrich_ioc(opts);
    if (!rep.ok) {
        page.json = "{\"kind\":\"error\",\"error\":\"" + core::json_escape(rep.error) + "\"}";
        page.exit_code = 2;
        return page;
    }
    page.json = core::gui_indicator_json(rep);
    page.exit_code = core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.worst);
    return page;
}

inline std::string analyze_to_json(core::Options opts) {
    return analyze(std::move(opts)).json;
}

// Write the glass report to a specific file and don't touch the browser.
// Powers `horus --html report.html` - a shareable, offline report export.
inline int write_html(core::Options opts, const std::string& path) {
    config::apply(opts, config::load());
    if (opts.target.empty()) {
        std::string picked = pick_file();
        if (picked.empty()) return 0;
        opts.target = picked;
    }
    PageData page = analyze(opts);
    std::string error;
    if (!output::write_atomic(std::filesystem::path(path), render_page(page.json), error))
        return 2;
    return page.exit_code;
}

// Entry point. Returns a process exit code.
inline int launch(core::Options opts) {
    config::apply(opts, config::load());

    if (opts.target.empty() && opts.diff_a.empty() && opts.scan_dir.empty()) {
        std::string picked = pick_file();
        if (picked.empty()) return 0;   // user cancelled - not an error
        opts.target = picked;
    }

    PageData page = analyze(opts);
    std::string path, error;
    if (!write_report(render_page(page.json), path, error)) return 2;
    if (!open_in_browser(path)) return 2;
    return page.exit_code;
}

} // namespace gui
} // namespace horus
