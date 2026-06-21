// ---------------------------------------------------------------------------
//  signatures.hpp  -  the "why should I care" layer on top of the raw PE data
//
//  A list of imported functions is just trivia until you know what those
//  functions *let a program do*. This is a curated map from Windows API names
//  to the capability they imply - process injection, persistence, anti-analysis
//  and so on - plus a heuristic that rolls the imports, the section entropy,
//  the memory flags and a few packer tells into a single risk verdict.
//
//  None of this is a detonation or a signature match against known malware. It
//  is the same reasoning a human reverser does in the first sixty seconds with
//  a sample: "it allocates RWX memory, resolves APIs at runtime, and talks to
//  the network - that combination is worth a closer look." Benign tools trip
//  one or two of these; it's the *stacking* of capabilities that moves the
//  needle, which is exactly how the scoring is weighted.
// ---------------------------------------------------------------------------
#pragma once

#include "pe.hpp"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <algorithm>

namespace argus {
namespace sig {

// small helper, defined at the bottom of the file
inline std::string fmt1(double v);

enum class Capability {
    ProcessInjection,
    MemoryExecution,
    ProcessManipulation,
    DynamicResolution,
    AntiDebug,
    AntiAnalysis,
    Persistence,
    Networking,
    Cryptography,
    InputCapture,
    ScreenCapture,
    TokenPrivilege,
    ServiceControl,
    Reconnaissance,
    DefenseEvasion
};

struct CapabilityMeta {
    const char* label;
    int         weight;     // contribution toward the risk score
    const char* blurb;      // one-liner shown in the report
};

inline const CapabilityMeta& meta(Capability c) {
    // Weights are deliberately uneven. The rare, hard-to-explain-away primitives
    // (injection, keystroke capture) carry real weight; the dual-use ones that
    // show up in half of all benign binaries (timing calls, LoadLibrary, a debug
    // check) are kept low and are only counted at all when the evidence isn't a
    // well-known "common" API - see is_common_api() and score().
    static const std::map<Capability, CapabilityMeta> m = {
        { Capability::ProcessInjection,   {"Process Injection",     22, "writes into and runs code in another process"} },
        { Capability::MemoryExecution,    {"Dynamic Code / RWX",     8, "allocates or re-flags executable memory at runtime"} },
        { Capability::ProcessManipulation,{"Process Creation",       4, "spawns or opens other processes"} },
        { Capability::DynamicResolution,  {"API Hiding",             6, "resolves API addresses at runtime to dodge static imports"} },
        { Capability::AntiDebug,          {"Anti-Debugging",         6, "checks for an attached debugger"} },
        { Capability::AntiAnalysis,       {"Anti-Analysis / Timing", 4, "stalls or fingerprints the analysis environment"} },
        { Capability::Persistence,        {"Persistence",           14, "writes autostart keys or installs itself to survive reboot"} },
        { Capability::Networking,         {"Network Activity",       8, "opens sockets or fetches remote content (C2 / download)"} },
        { Capability::Cryptography,       {"Cryptography",           8, "encrypts data - benign, or ransomware/payload packing"} },
        { Capability::InputCapture,       {"Input Capture",         20, "reads keystrokes or installs input hooks (keylogger)"} },
        { Capability::ScreenCapture,      {"Screen Capture",        12, "grabs the screen or window contents"} },
        { Capability::TokenPrivilege,     {"Privilege / Token",     14, "adjusts privileges or steals/impersonates tokens"} },
        { Capability::ServiceControl,     {"Service Control",        8, "creates or controls Windows services"} },
        { Capability::Reconnaissance,     {"Host Reconnaissance",    4, "enumerates host, user, or domain details"} },
        { Capability::DefenseEvasion,     {"Defense Evasion",       12, "tampers with logging, files, or its own footprint"} },
    };
    return m.at(c);
}

// The knowledge base. Keys are lowercase, with any trailing A/W kept separate
// where it matters less - we also strip a single trailing 'a'/'w' at lookup
// time so CreateProcessA and CreateProcessW both resolve to one entry.
inline const std::unordered_map<std::string, Capability>& api_table() {
    static const std::unordered_map<std::string, Capability> t = {
        // --- process injection ---
        {"virtualallocex",        Capability::ProcessInjection},
        {"writeprocessmemory",    Capability::ProcessInjection},
        {"createremotethread",    Capability::ProcessInjection},
        {"createremotethreadex",  Capability::ProcessInjection},
        {"ntcreatethreadex",      Capability::ProcessInjection},
        {"rtlcreateuserthread",   Capability::ProcessInjection},
        {"queueuserapc",          Capability::ProcessInjection},
        {"ntqueueapcthread",      Capability::ProcessInjection},
        {"ntmapviewofsection",    Capability::ProcessInjection},
        {"ntunmapviewofsection",  Capability::ProcessInjection},
        {"setthreadcontext",      Capability::ProcessInjection},
        {"resumethread",          Capability::ProcessInjection},

        // --- dynamic code / memory ---
        {"virtualalloc",          Capability::MemoryExecution},
        {"virtualprotect",        Capability::MemoryExecution},
        {"virtualprotectex",      Capability::MemoryExecution},
        {"ntallocatevirtualmemory",Capability::MemoryExecution},
        {"ntprotectvirtualmemory",Capability::MemoryExecution},
        {"heapcreate",            Capability::MemoryExecution},

        // --- process / shell ---
        {"createprocess",         Capability::ProcessManipulation},
        {"createprocessinternal", Capability::ProcessManipulation},
        {"ntcreateprocess",       Capability::ProcessManipulation},
        {"openprocess",           Capability::ProcessManipulation},
        {"shellexecute",          Capability::ProcessManipulation},
        {"shellexecuteex",        Capability::ProcessManipulation},
        {"winexec",               Capability::ProcessManipulation},
        {"createprocessasuser",   Capability::ProcessManipulation},

        // --- dynamic API resolution ---
        {"loadlibrary",           Capability::DynamicResolution},
        {"loadlibraryex",         Capability::DynamicResolution},
        {"getprocaddress",        Capability::DynamicResolution},
        {"ldrloaddll",            Capability::DynamicResolution},
        {"ldrgetprocedureaddress",Capability::DynamicResolution},
        {"getmodulehandle",       Capability::DynamicResolution},

        // --- anti-debug ---
        {"isdebuggerpresent",          Capability::AntiDebug},
        {"checkremotedebuggerpresent", Capability::AntiDebug},
        {"ntqueryinformationprocess",  Capability::AntiDebug},
        {"outputdebugstring",          Capability::AntiDebug},
        {"ntsetinformationthread",     Capability::AntiDebug},
        {"debugactiveprocess",         Capability::AntiDebug},

        // --- anti-analysis / timing / sandbox ---
        {"gettickcount",          Capability::AntiAnalysis},
        {"gettickcount64",        Capability::AntiAnalysis},
        {"queryperformancecounter",Capability::AntiAnalysis},
        {"getsystemfirmwaretable",Capability::AntiAnalysis},
        {"sleepex",               Capability::AntiAnalysis},
        {"getcursorpos",          Capability::AntiAnalysis},

        // --- persistence ---
        {"regsetvalueex",         Capability::Persistence},
        {"regcreatekeyex",        Capability::Persistence},
        {"regsetkeyvalue",        Capability::Persistence},
        {"createservice",         Capability::Persistence},   // also service control

        // --- networking ---
        {"socket",                Capability::Networking},
        {"wsasocket",             Capability::Networking},
        {"connect",               Capability::Networking},
        {"send",                  Capability::Networking},
        {"recv",                  Capability::Networking},
        {"wsastartup",            Capability::Networking},
        {"gethostbyname",         Capability::Networking},
        {"getaddrinfo",           Capability::Networking},
        {"internetopen",          Capability::Networking},
        {"internetconnect",       Capability::Networking},
        {"internetopenurl",       Capability::Networking},
        {"internetreadfile",      Capability::Networking},
        {"httpopenrequest",       Capability::Networking},
        {"httpsendrequest",       Capability::Networking},
        {"urldownloadtofile",     Capability::Networking},
        {"winhttpopen",           Capability::Networking},
        {"winhttpconnect",        Capability::Networking},

        // --- cryptography ---
        {"cryptacquirecontext",   Capability::Cryptography},
        {"cryptencrypt",          Capability::Cryptography},
        {"cryptdecrypt",          Capability::Cryptography},
        {"cryptgenkey",           Capability::Cryptography},
        {"crypthashdata",         Capability::Cryptography},
        {"bcryptencrypt",         Capability::Cryptography},
        {"bcryptgeneratesymmetrickey", Capability::Cryptography},

        // --- input capture / keylogging ---
        {"getasynckeystate",      Capability::InputCapture},
        {"setwindowshookex",      Capability::InputCapture},   // global keyboard/mouse hook
        {"getkeystate",           Capability::InputCapture},
        {"getkeyboardstate",      Capability::InputCapture},
        {"registerrawinputdevices",Capability::InputCapture},
        {"getforegroundwindow",   Capability::InputCapture},
        {"attachthreadinput",     Capability::InputCapture},

        // --- screen capture ---
        {"bitblt",                Capability::ScreenCapture},
        {"getdc",                 Capability::ScreenCapture},
        {"getwindowdc",           Capability::ScreenCapture},
        {"createcompatibledc",    Capability::ScreenCapture},
        {"createcompatiblebitmap",Capability::ScreenCapture},

        // --- token / privilege ---
        {"adjusttokenprivileges", Capability::TokenPrivilege},
        {"openprocesstoken",      Capability::TokenPrivilege},
        {"lookupprivilegevalue",  Capability::TokenPrivilege},
        {"duplicatetokenex",      Capability::TokenPrivilege},
        {"impersonateloggedonuser",Capability::TokenPrivilege},
        {"setthreadtoken",        Capability::TokenPrivilege},

        // --- service control ---
        {"openscmanager",         Capability::ServiceControl},
        {"controlservice",        Capability::ServiceControl},
        {"startservicectrldispatcher", Capability::ServiceControl},

        // --- recon ---
        {"getcomputername",       Capability::Reconnaissance},
        {"getusername",           Capability::Reconnaissance},
        {"getsysteminfo",         Capability::Reconnaissance},
        {"getversionex",          Capability::Reconnaissance},
        {"netuseradd",            Capability::Reconnaissance},

        // --- defense evasion ---
        {"deletefile",            Capability::DefenseEvasion},
        {"ntsetinformationprocess",Capability::DefenseEvasion},
        {"setfileattributes",     Capability::DefenseEvasion},
        {"eventwrite",            Capability::DefenseEvasion},
    };
    return t;
}

// These APIs are so common in ordinary, benign binaries - the C runtime startup
// alone pulls in a debug check, a timing call and a module-handle lookup - that
// seeing them tells you almost nothing on their own. We still detect and display
// the capability, but its evidence has to include at least one *non-common* API
// before it adds to the score. (Stored in normalize_api() form: lowercased, with
// a trailing A/W already stripped.)
inline bool is_common_api(const std::string& normalized) {
    static const std::vector<std::string> common = {
        "isdebuggerpresent", "queryperformancecounter", "gettickcount", "gettickcount64",
        "getmodulehandle", "getprocaddress", "loadlibrary", "loadlibraryex",
        "createprocess", "getforegroundwindow", "getcursorpos", "sleepex",
        "getcomputername", "getusername", "getversionex"
    };
    for (auto& c : common) if (normalized == c) return true;
    return false;
}

// Common packer / protector section names. UPX is the obvious one; the rest
// show up around commodity crypters.
inline bool is_packer_section(const std::string& name) {
    static const std::vector<std::string> known = {
        "upx0", "upx1", "upx2", ".aspack", ".adata", "aspack",
        ".nsp0", ".nsp1", ".petite", "pebundle", ".mpress1", ".mpress2",
        ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2", "fsg!", ".taz"
    };
    std::string n = name;
    std::transform(n.begin(), n.end(), n.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    for (auto& k : known) if (n == k) return true;
    return false;
}

// ---- the result of scoring a sample ----
struct Finding {
    std::string text;
    int         weight;
};

struct CapabilityHit {
    Capability               cap;
    std::vector<std::string> apis;        // the matching imported functions
    bool                     significant = true;  // false = common/dual-use only
};

enum class Verdict { Clean, Low, Suspicious, Malicious };

inline const char* verdict_name(Verdict v) {
    switch (v) {
        case Verdict::Clean:      return "CLEAN";
        case Verdict::Low:        return "LOW RISK";
        case Verdict::Suspicious: return "SUSPICIOUS";
        case Verdict::Malicious:  return "LIKELY MALICIOUS";
    }
    return "?";
}

struct ScoreResult {
    int                                  score = 0;     // 0..100 (clamped)
    Verdict                              verdict = Verdict::Clean;
    std::vector<CapabilityHit>           capabilities;
    std::vector<Finding>                 findings;       // entropy/section/etc.
};

// Normalise a function name for table lookup: lowercase, then drop one trailing
// 'a' or 'w' (the ANSI/Unicode suffix) so both variants map to one entry.
inline std::string normalize_api(const std::string& fn) {
    std::string s = fn;
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    if (s.size() > 1 && (s.back() == 'a' || s.back() == 'w')) {
        std::string trimmed = s.substr(0, s.size() - 1);
        if (api_table().count(trimmed)) return trimmed;
    }
    return s;
}

inline ScoreResult score(const pe::Info& info) {
    ScoreResult r;
    std::map<Capability, std::vector<std::string>> hits;

    // 1. capability detection from the import table
    for (const auto& imp : info.imports) {
        for (const auto& fn : imp.functions) {
            std::string key = normalize_api(fn);
            auto it = api_table().find(key);
            if (it != api_table().end())
                hits[it->second].push_back(fn);
        }
    }

    // Score each capability once. A category only contributes its weight when at
    // least one piece of evidence is a non-common API; otherwise it is recorded
    // as a dual-use observation worth nothing on its own. Combination bonuses
    // below still fire on mere *presence*, which is the whole point - "resolves
    // APIs at runtime" is noise by itself but damning next to injection.
    for (auto& kv : hits) {
        bool significant = false;
        for (const auto& fn : kv.second)
            if (!is_common_api(normalize_api(fn))) { significant = true; break; }

        r.capabilities.push_back({kv.first, kv.second, significant});
        if (significant) r.score += meta(kv.first).weight;
    }

    // The dangerous part is combinations. Injection + dynamic resolution, or
    // crypto + networking, is a meaningfully worse signal than either alone.
    auto has = [&](Capability c){ return hits.count(c) > 0; };
    if (has(Capability::ProcessInjection) && has(Capability::DynamicResolution)) {
        r.findings.push_back({"Injection primitives paired with runtime API resolution", 15});
        r.score += 15;
    }
    if (has(Capability::Cryptography) && has(Capability::Networking)) {
        r.findings.push_back({"Encryption combined with network I/O (exfil / ransomware pattern)", 12});
        r.score += 12;
    }
    if (has(Capability::InputCapture) && has(Capability::Networking)) {
        r.findings.push_back({"Input capture combined with network I/O (keylogger pattern)", 15});
        r.score += 15;
    }

    // 2. entropy / packing heuristics
    int high_entropy_sections = 0;
    int entropy_budget = 24;        // cap runaway scoring from many fat sections
    for (const auto& s : info.sections) {
        if (s.entropy >= 7.2 && s.raw_size > 0) {
            ++high_entropy_sections;
            int add = std::min(12, entropy_budget);
            entropy_budget -= add;
            if (add > 0) {
                r.findings.push_back({"High-entropy section '" + s.name +
                                      "' (H=" + fmt1(s.entropy) + ") - likely packed/encrypted", add});
                r.score += add;
            }
        }
        if (s.is_rwx()) {
            r.findings.push_back({"Section '" + s.name +
                                  "' is writable AND executable (RWX)", 18});
            r.score += 18;
        }
        if (is_packer_section(s.name)) {
            r.findings.push_back({"Known packer section name '" + s.name + "'", 16});
            r.score += 16;
        }
    }

    // A packed file with almost no visible imports is a classic crypter shape.
    if (info.total_imports > 0 && info.total_imports < 8 && high_entropy_sections > 0) {
        r.findings.push_back({"Very small import table on a packed binary (imports likely resolved at runtime)", 12});
        r.score += 12;
    }

    // 3. header oddities
    if (info.timestamp_suspicious)
        r.findings.push_back({"Compile timestamp is zeroed or implausible", 3}), r.score += 3;

    // entry point should live in an executable section
    if (!info.sections.empty()) {
        bool ep_in_exec = false;
        for (const auto& s : info.sections) {
            uint32_t span = std::max(s.virtual_size, s.raw_size);
            if (info.entry_point_rva >= s.virtual_addr &&
                info.entry_point_rva <  s.virtual_addr + span) {
                ep_in_exec = s.executable;
                break;
            }
        }
        if (!ep_in_exec) {
            r.findings.push_back({"Entry point is not inside an executable section", 12});
            r.score += 12;
        }
    }

    // 4. clamp + bucket
    if (r.score > 100) r.score = 100;
    if      (r.score >= 60) r.verdict = Verdict::Malicious;
    else if (r.score >= 30) r.verdict = Verdict::Suspicious;
    else if (r.score >= 10) r.verdict = Verdict::Low;
    else                    r.verdict = Verdict::Clean;

    return r;
}

inline std::string fmt1(double v) {
    char b[32];
    std::snprintf(b, sizeof(b), "%.2f", v);
    return b;
}

} // namespace sig
} // namespace argus
