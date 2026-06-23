// ---------------------------------------------------------------------------
//  ueba.hpp  -  User/Entity Behavior Analytics  (static edition)
//
//  Real UEBA watches entities over time and builds baselines. This does the
//  static half: maps a PE's import/section/string profile onto a library of
//  known software archetypes (installer, keylogger, RAT, etc.) and returns
//  a risk modifier and a human-readable rationale string. The modifier is
//  applied on top of the raw static score so context reduces false positives
//  without hiding genuinely malicious capability combinations.
//
//  Design notes:
//    - Malicious archetypes are checked FIRST and return early, so decoy
//      "installer" strings in a genuine keylogger don't get it a free pass.
//    - All archetype checks use sig::ScoreResult::capabilities (which are
//      present even if the capability wasn't "significant") combined with
//      file-level context (subsystem, import count, string scan).
//    - Confidence is advisory; the modifier is what actually changes the score.
// ---------------------------------------------------------------------------
#pragma once

#include "pe.hpp"
#include "signatures.hpp"
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace horus {
namespace ueba {

enum class Archetype {
    Unknown,
    Installer,        // setup wizards, self-extracting packages
    AutomationTool,   // AHK / AutoIt / macro scripting tools
    SystemTool,       // sysadmin utilities, diagnostics
    SecurityTool,     // AV, scanners, pentest utilities
    Loader,           // unpacking stub, self-extractor
    Downloader,       // fetches next stage, minimal other behaviour
    Dropper,          // delivers a payload into another process
    RAT,              // remote access trojan
    Keylogger,        // input capture + network exfil
    Ransomware,       // encrypt-then-ransom
    Spyware,          // screen/input capture + exfil
    Cryptominer,      // heavy crypto + C2, no UI
};

struct Profile {
    Archetype   type       = Archetype::Unknown;
    float       confidence = 0.f;   // 0–1  (advisory)
    int         modifier   = 0;     // added to raw static score
    std::string label;
    std::string reasoning;
};

inline const char* archetype_label(Archetype a) {
    switch (a) {
        case Archetype::Installer:     return "Installer";
        case Archetype::AutomationTool:return "AutomationTool";
        case Archetype::SystemTool:    return "SystemTool";
        case Archetype::SecurityTool:  return "SecurityTool";
        case Archetype::Loader:        return "Loader/Unpacker";
        case Archetype::Downloader:    return "Downloader";
        case Archetype::Dropper:       return "Dropper";
        case Archetype::RAT:           return "RAT";
        case Archetype::Keylogger:     return "Keylogger";
        case Archetype::Ransomware:    return "Ransomware";
        case Archetype::Spyware:       return "Spyware";
        case Archetype::Cryptominer:   return "CryptoMiner";
        default:                        return "Unknown";
    }
}

// Returns true if the capability was triggered by at least one import,
// regardless of whether it's "significant" (i.e., common or not).
static inline bool has_cap(const sig::ScoreResult& sr, sig::Capability c) {
    for (const auto& h : sr.capabilities)
        if (h.cap == c) return true;
    return false;
}

// Returns true only if the capability has at least one non-common-API trigger.
static inline bool has_sig_cap(const sig::ScoreResult& sr, sig::Capability c) {
    for (const auto& h : sr.capabilities)
        if (h.cap == c && h.significant) return true;
    return false;
}

// --- string keyword scans (case-insensitive, plain ASCII) ---

static inline bool str_has_any(const std::vector<std::string>& strs,
                                std::initializer_list<const char*> keywords) {
    for (const auto& s : strs) {
        std::string lo = s;
        std::transform(lo.begin(), lo.end(), lo.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        for (const char* kw : keywords)
            if (lo.find(kw) != std::string::npos) return true;
    }
    return false;
}

static inline bool has_installer_strings(const std::vector<std::string>& s) {
    return str_has_any(s, {
        "setup", "install", "uninstall", "wizard", "nsis", "inno setup",
        "bootstrapper", "vcredist", "redistributable", "7-zip sfx",
        "winrar sfx", "setupapi", "installer"
    });
}

static inline bool has_automation_strings(const std::vector<std::string>& s) {
    return str_has_any(s, {
        "autohotkey", "autoit", "ahk2", "macro", "hotkey", "sendkeys",
        "keystroke", "automation script"
    });
}

static inline bool has_security_tool_strings(const std::vector<std::string>& s) {
    return str_has_any(s, {
        "virus", "malware", "sandbox", "antivirus", "disassemble",
        "debugger", "signature", "heuristic", "detection engine", "scanner"
    });
}

static inline bool has_crypto_miner_strings(const std::vector<std::string>& s) {
    return str_has_any(s, {
        "stratum+tcp", "xmrig", "monero", "nicehash", "pool.minexmr",
        "cryptonight", "randomx", "hashrate"
    });
}

// ---------------------------------------------------------------------------
//  Main profiling function
//  Checks archetypes from most-malicious to most-benign; returns on first match
//  so that decoy strings in malware don't downgrade the verdict.
// ---------------------------------------------------------------------------
inline Profile profile(const pe::Info& info,
                        const sig::ScoreResult& caps,
                        const std::vector<std::string>& strings,
                        bool has_upx)
{
    using Cap = sig::Capability;
    Profile p;

    bool net    = has_cap(caps, Cap::Networking);
    bool inj    = has_sig_cap(caps, Cap::ProcessInjection);
    bool input  = has_sig_cap(caps, Cap::InputCapture);
    bool scr    = has_cap(caps, Cap::ScreenCapture);
    bool crypt  = has_cap(caps, Cap::Cryptography);
    bool recon  = has_cap(caps, Cap::Reconnaissance);
    bool dyn    = has_cap(caps, Cap::DynamicResolution);
    bool adbg   = has_cap(caps, Cap::AntiDebug);
    bool evade  = has_cap(caps, Cap::DefenseEvasion);
    bool persist= has_sig_cap(caps, Cap::Persistence);
    bool svc    = has_sig_cap(caps, Cap::ServiceControl);
    bool priv   = has_sig_cap(caps, Cap::TokenPrivilege);

    bool is_gui = (info.subsystem == 2);
    bool small_imports = (info.total_imports > 0 && info.total_imports < 8);
    bool minimal_imports = (info.total_imports > 0 && info.total_imports < 4);

    bool inst_str  = has_installer_strings(strings);
    bool auto_str  = has_automation_strings(strings);
    bool sec_str   = has_security_tool_strings(strings);
    bool miner_str = has_crypto_miner_strings(strings);

    // --- malicious archetypes (checked first, no early-exit below these) ---

    // Keylogger: input capture + network exfil is almost never legitimate
    if (input && net) {
        p.type       = Archetype::Keylogger;
        p.confidence = (scr || recon) ? 0.88f : 0.72f;
        p.modifier   = scr ? 25 : 18;
        p.reasoning  = "input capture combined with network exfil";
        if (scr)   p.reasoning += " + screen recording";
        if (recon) p.reasoning += " + host enumeration";
        p.label = archetype_label(p.type);
        return p;
    }

    // RAT: process injection + C2 networking + runtime API resolution
    if (inj && net && dyn) {
        p.type       = Archetype::RAT;
        p.confidence = adbg ? 0.92f : 0.80f;
        p.modifier   = adbg ? 28 : 22;
        p.reasoning  = "process injection + C2 networking + runtime API resolution";
        if (adbg)  p.reasoning += " + anti-debug";
        if (evade) p.reasoning += " + defense evasion";
        p.label = archetype_label(p.type);
        return p;
    }

    // Spyware: screen capture + networking + host recon, no injection
    if (scr && net && recon && !inj) {
        p.type       = Archetype::Spyware;
        p.confidence = 0.74f;
        p.modifier   = 18;
        p.reasoning  = "screen capture + networking + host reconnaissance";
        p.label = archetype_label(p.type);
        return p;
    }

    // Dropper: injection + packed + very few visible imports
    if (inj && has_upx && minimal_imports) {
        p.type       = Archetype::Dropper;
        p.confidence = 0.68f;
        p.modifier   = 20;
        p.reasoning  = "process injection in a packed binary with minimal import table";
        p.label = archetype_label(p.type);
        return p;
    }

    // Cryptominer: specific pool strings, crypto, networking, no UI
    if (miner_str && crypt && net) {
        p.type       = Archetype::Cryptominer;
        p.confidence = 0.90f;
        p.modifier   = 30;
        p.reasoning  = "crypto-mining pool strings + encryption + networking";
        p.label = archetype_label(p.type);
        return p;
    }

    // Ransomware: crypto + network + file ops, no installer markers
    if (crypt && net && !inst_str && !sec_str && !auto_str) {
        p.type       = Archetype::Ransomware;
        p.confidence = 0.50f;
        p.modifier   = 12;
        p.reasoning  = "encryption + network I/O (possible ransomware / exfil tool)";
        p.label = archetype_label(p.type);
        return p;
    }

    // Rootkit / backdoor: privilege escalation + service install + defense evasion
    if (priv && svc && (evade || adbg) && !inst_str) {
        p.type       = Archetype::RAT;
        p.confidence = 0.72f;
        p.modifier   = 20;
        p.reasoning  = "privilege escalation + service manipulation + evasion (rootkit/backdoor pattern)";
        p.label = archetype_label(p.type);
        return p;
    }

    // Persistent bot / implant: networking + persistence + privilege, no installer
    if (persist && net && priv && !inst_str) {
        p.type       = Archetype::RAT;
        p.confidence = 0.65f;
        p.modifier   = 18;
        p.reasoning  = "persistence + networking + privilege escalation (implant pattern)";
        p.label = archetype_label(p.type);
        return p;
    }

    // Downloader: network + runtime resolution + packed + small imports, no other caps
    if (net && dyn && has_upx && small_imports && !inj && !input && !scr) {
        p.type       = Archetype::Downloader;
        p.confidence = 0.62f;
        p.modifier   = 10;
        p.reasoning  = "packed network stub with small import table (likely stage-1 downloader)";
        p.label = archetype_label(p.type);
        return p;
    }

    // --- benign archetypes ---

    // Automation tool installer: AHK/AutoIt setup binary
    if (auto_str && is_gui && has_upx) {
        p.type       = Archetype::AutomationTool;
        p.confidence = 0.84f;
        p.modifier   = -20;
        p.reasoning  = "automation/scripting tool installer (AutoHotkey / AutoIt pattern)";
        p.label = archetype_label(p.type);
        return p;
    }

    // Installer: GUI packed binary with setup strings
    if ((inst_str || auto_str) && (is_gui || has_upx)) {
        p.type       = Archetype::Installer;
        p.confidence = inst_str ? 0.78f : 0.65f;
        p.modifier   = -18;
        p.reasoning  = inst_str ? "packed installer (setup strings present)"
                                : "packed GUI binary with automation markers";
        p.label = archetype_label(p.type);
        return p;
    }

    // Security / analysis tool
    if (sec_str && !inj) {
        p.type       = Archetype::SecurityTool;
        p.confidence = 0.58f;
        p.modifier   = -8;
        p.reasoning  = "security tool pattern (scanner / analyzer)";
        p.label = archetype_label(p.type);
        return p;
    }

    // Loader / unpacking stub: packed, no suspicious capability combo
    if (has_upx && !net && !inj && !input) {
        p.type       = Archetype::Loader;
        p.confidence = 0.52f;
        p.modifier   = 0;   // neutral - can't tell benign from loader without more context
        p.reasoning  = "UPX-packed stub with no suspicious capability combination";
        p.label = archetype_label(p.type);
        return p;
    }

    p.type      = Archetype::Unknown;
    p.confidence= 0.f;
    p.modifier  = 0;
    p.reasoning = "no strong archetype match";
    p.label     = archetype_label(p.type);
    return p;
}

} // namespace ueba
} // namespace horus
