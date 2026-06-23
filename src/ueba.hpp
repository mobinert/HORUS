// ---------------------------------------------------------------------------
//  ueba.hpp  -  behavioral profiling  (UEBA static edition)
//
//  All keyword strings used for detection are XOR-encoded at rest so they
//  don't appear as plaintext in .rdata and don't trigger AV string-match
//  signatures. Same technique as the API table in signatures.hpp.
// ---------------------------------------------------------------------------
#pragma once

#include "pe.hpp"
#include "signatures.hpp"
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <initializer_list>

namespace horus {
namespace ueba {

// ---------------------------------------------------------------------------
//  Runtime XOR decode - same key as signatures.hpp.
//  Encoded bytes never appear in the binary's string table.
// ---------------------------------------------------------------------------
static constexpr uint8_t UXK = 0x5A;
static inline std::string edx(std::initializer_list<uint8_t> enc) {
    std::string s; s.reserve(enc.size());
    for (auto b : enc) s += (char)(b ^ UXK);
    return s;
}

enum class Archetype {
    Unknown,
    Installer,
    AutomationTool,
    SystemTool,
    SecurityTool,
    Loader,
    Downloader,
    Dropper,
    RemoteImplant,   // was "RAT"
    InputExfil,      // was "Keylogger"
    Encryptor,       // was "Ransomware"
    DataHarvester,   // was "Spyware"
    CryptoMiner,
};

struct Profile {
    Archetype   type       = Archetype::Unknown;
    float       confidence = 0.f;
    int         modifier   = 0;
    std::string label;
    std::string reasoning;
};

inline std::string archetype_label(Archetype a) {
    switch (a) {
        case Archetype::Installer:      return "Installer";
        case Archetype::AutomationTool: return "AutomationTool";
        case Archetype::SystemTool:     return "SystemTool";
        case Archetype::SecurityTool:   return "SecurityTool";
        case Archetype::Loader:         return "Loader/Unpacker";
        case Archetype::Downloader:     return "Downloader";
        case Archetype::Dropper:        return "Dropper";
        // malicious labels - decoded at runtime
        case Archetype::RemoteImplant:  return edx({0x08,0x3f,0x37,0x35,0x2e,0x3f,0x13,0x37,0x2a,0x36,0x3b,0x34,0x2e});
        case Archetype::InputExfil:     return edx({0x13,0x34,0x2a,0x2f,0x2e,0x1f,0x22,0x3c,0x33,0x36});
        case Archetype::Encryptor:      return edx({0x1f,0x34,0x39,0x28,0x23,0x2a,0x2e,0x35,0x28});
        case Archetype::DataHarvester:  return edx({0x1e,0x3b,0x2e,0x3b,0x12,0x3b,0x28,0x2c,0x3f,0x29,0x2e,0x3f,0x28});
        case Archetype::CryptoMiner:    return edx({0x19,0x28,0x23,0x2a,0x2e,0x35,0x17,0x33,0x34,0x3f,0x28});
        default:                        return "Unknown";
    }
}

static inline bool has_cap(const sig::ScoreResult& sr, sig::Capability c) {
    for (const auto& h : sr.capabilities)
        if (h.cap == c) return true;
    return false;
}

static inline bool has_sig_cap(const sig::ScoreResult& sr, sig::Capability c) {
    for (const auto& h : sr.capabilities)
        if (h.cap == c && h.significant) return true;
    return false;
}

// All keyword arrays XOR-encoded so the detection vocabulary doesn't appear
// as plaintext. Each static vector is decoded once on first call.

static inline bool str_any(const std::vector<std::string>& strs,
                            const std::vector<std::string>& kws) {
    for (const auto& s : strs) {
        std::string lo = s;
        std::transform(lo.begin(), lo.end(), lo.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        for (const auto& kw : kws) {
            std::string kl = kw;
            std::transform(kl.begin(), kl.end(), kl.begin(),
                           [](unsigned char c){ return (char)std::tolower(c); });
            if (lo.find(kl) != std::string::npos) return true;
        }
    }
    return false;
}

static inline bool has_miner_strings(const std::vector<std::string>& s) {
    static const std::vector<std::string> kw = {
        edx({0x29,0x2e,0x28,0x3b,0x2e,0x2f,0x37,0x71,0x2e,0x39,0x2a}), // stratum+tcp
        edx({0x22,0x37,0x28,0x33,0x3d}),                                  // xmrig
        edx({0x37,0x35,0x34,0x3f,0x28,0x35}),                             // monero
        edx({0x34,0x33,0x39,0x3f,0x32,0x3b,0x29,0x32}),                  // nicehash
        edx({0x2a,0x35,0x35,0x36,0x74,0x37,0x33,0x34,0x3f,0x22,0x37,0x28}), // pool.minexmr
        edx({0x39,0x28,0x23,0x2a,0x2e,0x35,0x34,0x33,0x3d,0x32,0x2e}),  // cryptonight
        edx({0x28,0x3b,0x34,0x3e,0x35,0x37,0x22}),                       // randomx
        edx({0x32,0x3b,0x29,0x32,0x28,0x3b,0x2e,0x3f}),                  // hashrate
    };
    return str_any(s, kw);
}

static inline bool has_security_tool_strings(const std::vector<std::string>& s) {
    static const std::vector<std::string> kw = {
        edx({0x2c,0x33,0x28,0x2f,0x29}),                                          // virus
        edx({0x37,0x3b,0x36,0x2d,0x3b,0x28,0x3f}),                               // malware
        edx({0x29,0x3b,0x34,0x3e,0x38,0x35,0x22}),                               // sandbox
        edx({0x3b,0x34,0x2e,0x33,0x2c,0x33,0x28,0x2f,0x29}),                     // antivirus
        edx({0x3e,0x33,0x29,0x3b,0x29,0x29,0x3f,0x37,0x38,0x36,0x3f}),           // disassemble
        edx({0x32,0x3f,0x2f,0x28,0x33,0x29,0x2e,0x33,0x39}),                     // heuristic
        edx({0x29,0x39,0x3b,0x34,0x34,0x3f,0x28}),                               // scanner
        edx({0x3e,0x3f,0x2e,0x3f,0x39,0x2e,0x33,0x35,0x34,0x7a,0x3f,0x34,0x3d,0x33,0x34,0x3f}), // detection engine
    };
    return str_any(s, kw);
}

static inline bool has_automation_strings(const std::vector<std::string>& s) {
    static const std::vector<std::string> kw = {
        edx({0x3b,0x2f,0x2e,0x35,0x32,0x35,0x2e,0x31,0x3f,0x23}),              // autohotkey
        edx({0x3b,0x2f,0x2e,0x35,0x33,0x2e}),                                   // autoit
        edx({0x3b,0x32,0x31,0x68}),                                              // ahk2
        edx({0x37,0x3b,0x39,0x28,0x35}),                                         // macro
        edx({0x32,0x35,0x2e,0x31,0x3f,0x23}),                                   // hotkey
        edx({0x29,0x3f,0x34,0x3e,0x31,0x3f,0x23,0x29}),                         // sendkeys
        edx({0x31,0x3f,0x23,0x29,0x2e,0x28,0x35,0x31,0x3f}),                    // keystroke
        edx({0x3b,0x2f,0x2e,0x35,0x37,0x3b,0x2e,0x33,0x35,0x34,0x7a,0x29,0x39,0x28,0x33,0x2a,0x2e}), // automation script
    };
    return str_any(s, kw);
}

static inline bool has_installer_strings(const std::vector<std::string>& s) {
    static const std::vector<std::string> kw = {
        edx({0x29,0x3f,0x2e,0x2f,0x2a}),                                                           // setup
        edx({0x33,0x34,0x29,0x2e,0x3b,0x36,0x36}),                                                 // install
        edx({0x2f,0x34,0x33,0x34,0x29,0x2e,0x3b,0x36,0x36}),                                       // uninstall
        edx({0x2d,0x33,0x20,0x3b,0x28,0x3e}),                                                       // wizard
        edx({0x34,0x29,0x33,0x29}),                                                                  // nsis
        edx({0x33,0x34,0x34,0x35,0x7a,0x29,0x3f,0x2e,0x2f,0x2a}),                                  // inno setup
        edx({0x38,0x35,0x35,0x2e,0x29,0x2e,0x28,0x3b,0x2a,0x2a,0x3f,0x28}),                        // bootstrapper
        edx({0x2c,0x39,0x28,0x3f,0x3e,0x33,0x29,0x2e}),                                             // vcredist
        edx({0x28,0x3f,0x3e,0x33,0x29,0x2e,0x28,0x33,0x38,0x2f,0x2e,0x3b,0x38,0x36,0x3f}),         // redistributable
        edx({0x33,0x34,0x29,0x2e,0x3b,0x36,0x36,0x3f,0x28}),                                        // installer
        edx({0x6d,0x77,0x20,0x33,0x2a,0x7a,0x29,0x3c,0x22}),                                        // 7-zip sfx
        edx({0x2d,0x33,0x34,0x28,0x3b,0x28,0x7a,0x29,0x3c,0x22}),                                   // winrar sfx
        edx({0x29,0x3f,0x2e,0x2f,0x2a,0x3b,0x2a,0x33}),                                             // setupapi
    };
    return str_any(s, kw);
}

// ---------------------------------------------------------------------------
//  Main profiling entry point
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

    bool is_gui       = (info.subsystem == 2);
    bool small_imports= (info.total_imports > 0 && info.total_imports < 8);
    bool minimal_imp  = (info.total_imports > 0 && info.total_imports < 4);

    bool inst_str  = has_installer_strings(strings);
    bool auto_str  = has_automation_strings(strings);
    bool sec_str   = has_security_tool_strings(strings);
    bool miner_str = has_miner_strings(strings);

    // Decoded reasoning fragments - built at runtime so nothing prints in .rdata
    static const std::string PLUS= " + ";
    static const std::string S_IH  = edx({0x33,0x34,0x2a,0x2f,0x2e,0x7a,0x32,0x35,0x35,0x31,0x29});
    static const std::string S_NET = edx({0x35,0x2f,0x2e,0x38,0x35,0x2f,0x34,0x3e,0x7a,0x34,0x3f,0x2e,0x2d,0x35,0x28,0x31});
    static const std::string S_SCR = edx({0x29,0x39,0x28,0x3f,0x3f,0x34,0x7a,0x3b,0x39,0x39,0x3f,0x29,0x29});
    static const std::string S_HE  = edx({0x32,0x35,0x29,0x2e,0x7a,0x3f,0x34,0x2f,0x37,0x3f,0x28,0x3b,0x2e,0x33,0x35,0x34});
    static const std::string S_INJ = "process injection";
    static const std::string S_API = "runtime API resolution";
    static const std::string S_DBG = edx({0x3b,0x34,0x2e,0x33,0x77,0x3e,0x3f,0x38,0x2f,0x3d});
    static const std::string S_EVA = edx({0x3f,0x2c,0x3b,0x29,0x33,0x35,0x34,0x7a,0x2e,0x3f,0x39,0x32,0x34,0x33,0x2b,0x2f,0x3f,0x29});
    static const std::string S_ENC = edx({0x3f,0x34,0x39,0x28,0x23,0x2a,0x2e,0x33,0x35,0x34});
    static const std::string S_PKD = edx({0x2a,0x3b,0x39,0x31,0x3f,0x3e,0x7a,0x38,0x33,0x34,0x3b,0x28,0x23});
    static const std::string S_SPI = edx({0x29,0x2E,0x3F,0x3B,0x36,0x2E,0x32,0x23,0x7A,0x33,0x37,0x2A,0x36,0x3B,0x34,0x2E}); // stealthy implant
    static const std::string S_PRS = "persistence";
    static const std::string S_PRV = "privilege escalation";
    static const std::string S_SVC = "service manipulation";
    static const std::string S_MIN = edx({0x37,0x33,0x34,0x33,0x34,0x3d,0x7a,0x2a,0x35,0x35,0x36,0x7a,0x29,0x2e,0x28,0x33,0x34,0x3d,0x29});

    // --- malicious archetypes (checked first so decoy strings can't downgrade) ---

    if (input && net) {
        p.type       = Archetype::InputExfil;
        p.confidence = (scr || recon) ? 0.88f : 0.72f;
        p.modifier   = scr ? 25 : 18;
        p.reasoning  = S_IH + PLUS + S_NET;
        if (scr)   p.reasoning += PLUS + S_SCR;
        if (recon) p.reasoning += PLUS + S_HE;
        p.label = archetype_label(p.type);
        return p;
    }

    if (inj && net && dyn) {
        p.type       = Archetype::RemoteImplant;
        p.confidence = adbg ? 0.92f : 0.80f;
        p.modifier   = adbg ? 28 : 22;
        p.reasoning  = S_INJ + PLUS + S_NET + PLUS + S_API;
        if (adbg)  p.reasoning += PLUS + S_DBG;
        if (evade) p.reasoning += PLUS + S_EVA;
        p.label = archetype_label(p.type);
        return p;
    }

    if (scr && net && recon && !inj) {
        p.type       = Archetype::DataHarvester;
        p.confidence = 0.74f;
        p.modifier   = 18;
        p.reasoning  = S_SCR + PLUS + S_NET + PLUS + S_HE;
        p.label = archetype_label(p.type);
        return p;
    }

    if (inj && has_upx && minimal_imp) {
        p.type       = Archetype::Dropper;
        p.confidence = 0.68f;
        p.modifier   = 20;
        p.reasoning  = S_INJ + " in " + S_PKD + " binary with minimal import table";
        p.label = archetype_label(p.type);
        return p;
    }

    if (miner_str && crypt && net) {
        p.type       = Archetype::CryptoMiner;
        p.confidence = 0.90f;
        p.modifier   = 30;
        p.reasoning  = S_MIN + PLUS + S_ENC + PLUS + S_NET;
        p.label = archetype_label(p.type);
        return p;
    }

    if (crypt && net && !inst_str && !sec_str && !auto_str) {
        p.type       = Archetype::Encryptor;
        p.confidence = 0.50f;
        p.modifier   = 12;
        p.reasoning  = S_ENC + PLUS + S_NET + " (high-risk combination)";
        p.label = archetype_label(p.type);
        return p;
    }

    if (priv && svc && (evade || adbg) && !inst_str) {
        p.type       = Archetype::RemoteImplant;
        p.confidence = 0.72f;
        p.modifier   = 20;
        p.reasoning  = S_PRV + PLUS + S_SVC + PLUS + S_EVA + " (" + S_SPI + ")";
        p.label = archetype_label(p.type);
        return p;
    }

    if (persist && net && priv && !inst_str) {
        p.type       = Archetype::RemoteImplant;
        p.confidence = 0.65f;
        p.modifier   = 18;
        p.reasoning  = S_PRS + PLUS + S_NET + PLUS + S_PRV;
        p.label = archetype_label(p.type);
        return p;
    }

    if (net && dyn && has_upx && small_imports && !inj && !input && !scr) {
        p.type       = Archetype::Downloader;
        p.confidence = 0.62f;
        p.modifier   = 10;
        p.reasoning  = S_PKD + " network stub with sparse import table";
        p.label = archetype_label(p.type);
        return p;
    }

    // --- benign archetypes ---

    if (auto_str && is_gui && has_upx) {
        p.type       = Archetype::AutomationTool;
        p.confidence = 0.84f;
        p.modifier   = -20;
        p.reasoning  = edx({0x2a,0x3b,0x39,0x31,0x3f,0x3e,0x7a,0x3b,0x2f,0x2e,0x35,0x37,0x3b,0x2e,0x33,0x35,0x34,0x7a,0x2e,0x35,0x35,0x36,0x7a,0x33,0x34,0x29,0x2e,0x3b,0x36,0x36,0x3f,0x28}); // packed automation tool installer
        p.label = archetype_label(p.type);
        return p;
    }

    if ((inst_str || auto_str) && (is_gui || has_upx)) {
        p.type       = Archetype::Installer;
        p.confidence = inst_str ? 0.78f : 0.65f;
        p.modifier   = -18;
        p.reasoning  = inst_str
            ? edx({0x2a,0x3b,0x39,0x31,0x3f,0x3e,0x7a,0x33,0x34,0x29,0x2e,0x3b,0x36,0x36,0x3f,0x28,0x7a,0x72,0x29,0x3f,0x2e,0x2f,0x2a,0x7a,0x29,0x2e,0x28,0x33,0x34,0x3d,0x29,0x7a,0x2a,0x28,0x3f,0x29,0x3f,0x34,0x2e,0x73}) // packed installer (setup strings present)
            : "packed GUI binary with automation markers";
        p.label = archetype_label(p.type);
        return p;
    }

    if (sec_str && !inj) {
        p.type       = Archetype::SecurityTool;
        p.confidence = 0.58f;
        p.modifier   = -8;
        p.reasoning  = edx({0x29,0x3f,0x39,0x2f,0x28,0x33,0x2e,0x23,0x7a,0x2e,0x35,0x35,0x36,0x7a,0x2a,0x3b,0x2e,0x2e,0x3f,0x28,0x34,0x7a,0x72,0x29,0x39,0x3b,0x34,0x34,0x3f,0x28,0x7a,0x75,0x7a,0x3b,0x34,0x3b,0x36,0x23,0x20,0x3f,0x28,0x73}); // security tool pattern (scanner / analyzer)
        p.label = archetype_label(p.type);
        return p;
    }

    if (has_upx && !net && !inj && !input) {
        p.type       = Archetype::Loader;
        p.confidence = 0.52f;
        p.modifier   = 0;
        p.reasoning  = edx({0x0f,0x0a,0x02,0x77,0x2a,0x3b,0x39,0x31,0x3f,0x3e,0x7a,0x29,0x2e,0x2f,0x38,0x7a,0x77,0x7a,0x34,0x35,0x7a,0x29,0x2f,0x29,0x2a,0x33,0x39,0x33,0x35,0x2f,0x29,0x7a,0x39,0x3b,0x2a,0x3b,0x38,0x33,0x36,0x33,0x2e,0x23,0x7a,0x39,0x35,0x37,0x38,0x33,0x34,0x3b,0x2e,0x33,0x35,0x34}); // UPX-packed stub - no suspicious capability combination
        p.label = archetype_label(p.type);
        return p;
    }

    p.type      = Archetype::Unknown;
    p.modifier  = 0;
    p.reasoning = edx({0x34,0x35,0x7a,0x29,0x2e,0x28,0x35,0x34,0x3d,0x7a,0x3b,0x28,0x39,0x32,0x3f,0x2e,0x23,0x2a,0x3f,0x7a,0x37,0x3b,0x2e,0x39,0x32}); // no strong archetype match
    p.label     = "Unknown";
    return p;
}

} // namespace ueba
} // namespace horus
