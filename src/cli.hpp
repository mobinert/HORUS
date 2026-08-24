// ---------------------------------------------------------------------------
//  cli.hpp  -  argument parsing + dispatch, shared by horus-cli and horus
//
//  Kept out of any single main() so the pure-CLI build and the unified build
//  run identical command handling. The only thing the unified build adds on top
//  is the --gui launch, which it checks before calling run().
// ---------------------------------------------------------------------------
#pragma once

#include "core.hpp"
#include "render.hpp"
#include "config.hpp"
#include "cache.hpp"
#include "clip.hpp"
#include "diff.hpp"
#include "batch.hpp"
#include "case.hpp"
#include "console.hpp"

#include <iostream>
#include <cerrno>
#include <climits>
#include <string>

namespace horus {
namespace cli {

inline void usage() {
    std::cout <<
    "HORUS v3.0 - PE analysis, similarity hashing (TLSH/ssdeep), ATT&CK + GUI\n\n"
    "usage: horus <indicator-or-file> [options]\n"
    "       horus --case <dir> [--case-out dir] [--gui]\n"
    "       horus --scan <dir> [--csv f] [--json-out f]\n"
    "       horus --diff <a> <b>\n"
    "       horus --clip\n\n"
    "  <indicator-or-file>   a hash / IP / domain / URL / email, OR a file path\n\n"
    "options:\n"
    "  --case <dir>          create or refresh a persistent analysis case\n"
    "  --case-out <dir>      case workspace (default: <dir>.horus-case)\n"
    "  --case-name <name>    analyst-facing case name\n"
    "  --cluster-mode <m>    conservative, balanced (default), or broad\n"
    "  --verify              re-hash cached case files before reuse\n"
    "  --rebuild             ignore cached analysis and rebuild the case\n"
    "  --prune               drop missing files from case history\n"
    "  --enrich              query configured providers; files are never uploaded\n"
    "  --max-lookups <n>     live case lookup cap (default: 100)\n"
    "  --max-file-mb <n>     per-file analysis limit (default: 512)\n"
    "  --online-trust        allow online Authenticode revocation checks\n"
    "  --scan <dir>          triage every file in a folder, worst-first\n"
    "  --diff <a> <b>        compare two PEs (imphash / TLSH / sections)\n"
    "  --clip                read the indicator from the clipboard\n"
    "  --html <file>         write the glass-console report to an HTML file\n"
    "  --no-recurse          with --scan, stay in the top folder only\n"
    "  --csv <file>          with --scan, also write a CSV\n"
    "  --json-out <file>     with --scan, also write a JSON array\n"
    "  --cache-ttl <hours>   cache intel lookups for N hours (0 = off)\n"
    "  --vt-key <key>        VirusTotal API key   (or env VT_API_KEY)\n"
    "  --abuse-key <key>     AbuseIPDB API key     (or env ABUSEIPDB_API_KEY)\n"
    "  --strings             dump extracted strings\n"
    "  --profile             verbose UEBA signal breakdown\n"
    "  --json                machine-readable JSON output\n"
    "  --no-color            disable ANSI colour\n"
    "  -h, --help            this help\n\n"
    "examples:\n"
    "  horus suspicious.exe\n"
    "  horus --scan .\\samples --csv out.csv\n"
    "  horus --diff a.exe b.exe\n"
    "  horus 44d88612fea8a8f36de82e1278abb02f --cache-ttl 24\n"
    "  horus 185.220.101.5 --abuse-key $env:ABUSEIPDB_API_KEY\n";
}

[[noreturn]] inline void argument_error(const std::string& message) {
    std::cerr << "error: " << message << "\n";
    std::exit(2);
}

inline unsigned long long parse_uint(const std::string& text, const char* option,
                                     unsigned long long min,
                                     unsigned long long max) {
    if (text.empty() || text[0] == '-') argument_error(std::string(option) + " needs a valid number");
    errno = 0;
    char* end = nullptr;
    unsigned long long value = std::strtoull(text.c_str(), &end, 10);
    if (errno == ERANGE || !end || *end != '\0' || value < min || value > max)
        argument_error(std::string(option) + " is outside the supported range");
    return value;
}

inline core::Options parse_args(int argc, char** argv) {
    core::Options o;
    o.vt_key    = core::get_env("VT_API_KEY");
    o.abuse_key = core::get_env("ABUSEIPDB_API_KEY");
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "error: " << what << " needs a value\n"; std::exit(2); }
            return argv[++i];
        };
        if      (a == "-h" || a == "--help") o.help = true;
        else if (a == "--json")              o.json = true;
        else if (a == "--strings")           o.strings = true;
        else if (a == "--no-color")          o.no_color = true;
        else if (a == "--profile")           o.profile = true;
        else if (a == "--gui")               o.gui = true;
        else if (a == "--clip")              o.clip = true;
        else if (a == "--no-recurse")        o.recurse = false;
        else if (a == "--case")              o.case_dir = next("--case");
        else if (a == "--case-out")          o.case_out = next("--case-out");
        else if (a == "--case-name")         o.case_name = next("--case-name");
        else if (a == "--cluster-mode")      o.cluster_mode = next("--cluster-mode");
        else if (a == "--verify")            o.verify = true;
        else if (a == "--rebuild")           o.rebuild = true;
        else if (a == "--prune")             o.prune = true;
        else if (a == "--enrich")            o.enrich = true;
        else if (a == "--online-trust")      o.online_trust = true;
        else if (a == "--max-lookups")       o.max_lookups = static_cast<int>(parse_uint(next("--max-lookups"), "--max-lookups", 0, INT_MAX));
        else if (a == "--max-file-mb")       o.max_file_mb = parse_uint(next("--max-file-mb"), "--max-file-mb", 1, 1048576);
        else if (a == "--scan")              o.scan_dir = next("--scan");
        else if (a == "--csv")               o.csv_out  = next("--csv");
        else if (a == "--json-out")          o.json_out = next("--json-out");
        else if (a == "--html")              o.html_out = next("--html");
        else if (a == "--cache-ttl")       { o.cache_ttl_hours = static_cast<int>(parse_uint(next("--cache-ttl"), "--cache-ttl", 0, 87600)); o.cache_ttl_set = true; }
        else if (a == "--vt-key")            o.vt_key    = next("--vt-key");
        else if (a == "--abuse-key")         o.abuse_key = next("--abuse-key");
        else if (a == "--diff") {
            o.diff_a = next("--diff");
            o.diff_b = next("--diff");
        }
        else if (!a.empty() && a[0] == '-')  argument_error("unknown option: " + a);
        else if (!o.target.empty())           argument_error("multiple input targets were supplied");
        else                                  o.target = a;
    }

    int modes = (!o.target.empty() || o.clip ? 1 : 0) + (!o.case_dir.empty() ? 1 : 0) +
                (!o.scan_dir.empty() ? 1 : 0) + (!o.diff_a.empty() ? 1 : 0);
    if (modes > 1) argument_error("choose one of direct input, --case, --scan, or --diff");
    if (o.clip && !o.target.empty()) argument_error("--clip cannot be combined with a direct target");
    if (o.verify && o.rebuild) argument_error("--verify and --rebuild cannot be used together");
    if (o.case_dir.empty() && (!o.case_out.empty() || !o.case_name.empty() || o.verify || o.rebuild || o.prune))
        argument_error("case options require --case");
    if (o.scan_dir.empty() && (!o.csv_out.empty() || !o.json_out.empty()))
        argument_error("--csv and --json-out require --scan");
    if (!o.case_dir.empty() && !o.html_out.empty())
        argument_error("Case Mode always writes report.html; --html is for direct input");
    return o;
}

// Everything except the GUI. Returns a process exit code.
inline int run(const core::Options& in) {
    core::Options opts = in;
    config::apply(opts, config::load());

    ui::init();
    if (opts.no_color) ui::color_enabled() = false;

    if (opts.help) { ui::banner(); usage(); return 0; }

    // sub-commands first
    if (!opts.diff_a.empty()) {
        if (!opts.json) ui::banner();
        return diffs::run(opts, opts.diff_a, opts.diff_b);
    }
    if (!opts.case_dir.empty()) {
        if (!opts.json && !opts.gui) ui::banner();
        return casework::run(opts);
    }
    if (!opts.scan_dir.empty()) {
        if (!opts.json) ui::banner();
        return batch::run(opts);
    }
    if (opts.clip) {
        std::string c = clip::read();
        if (c.empty()) { std::cerr << "error: clipboard is empty or holds no text\n"; return 2; }
        opts.target = c;
    }

    if (opts.target.empty()) { ui::banner(); usage(); return 2; }

    if (!opts.json) ui::banner();

    if (core::file_exists(opts.target)) {
        core::FileReport rep = core::analyze_file(opts);
        if (!rep.ok) { std::cerr << "error: " << rep.error << "\n"; return 2; }
        if (opts.json) {
            std::cout << core::file_json(opts, rep);
            return core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.final_score);
        }
        return render::render_file(opts, rep);
    }

    core::IndicatorReport rep = (opts.enrich && opts.cache_ttl_hours > 0)
                              ? cache::enrich_cached(opts)
                              : core::enrich_ioc(opts);
    if (!rep.ok) { std::cerr << "error: " << rep.error << "\n"; return 2; }
    if (opts.json) {
        std::cout << core::indicator_json(rep);
        return core::analysis_exit_code(rep.analysis_status, rep.has_score, rep.worst);
    }
    return render::render_indicator(opts, rep);
}

inline int run(int argc, char** argv) { return run(parse_args(argc, argv)); }

} // namespace cli
} // namespace horus
