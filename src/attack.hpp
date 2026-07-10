// ---------------------------------------------------------------------------
//  attack.hpp  -  MITRE ATT&CK technique mapping
//
//  Turns the capability findings into the technique IDs an analyst actually
//  pivots on. Only *significant* capabilities and the combos that fired
//  contribute, so the list stays tight instead of tagging every dual-use API.
// ---------------------------------------------------------------------------
#pragma once

#include "signatures.hpp"
#include <string>
#include <vector>
#include <set>

namespace horus {
namespace attack {

struct Technique {
    std::string id;
    std::string name;
};

inline void map_capability(sig::Capability c, std::vector<Technique>& out) {
    using C = sig::Capability;
    auto add = [&](const char* id, const char* n){ out.push_back({id, n}); };
    switch (c) {
        case C::ProcessInjection:    add("T1055",     "Process Injection");                break;
        case C::MemoryExecution:     add("T1620",     "Reflective Code Loading");          break;
        case C::ProcessManipulation: add("T1106",     "Native API");                       break;
        case C::DynamicResolution:   add("T1027.007", "Dynamic API Resolution");           break;
        case C::AntiDebug:           add("T1622",     "Debugger Evasion");                 break;
        case C::AntiAnalysis:        add("T1497",     "Virtualization/Sandbox Evasion");   break;
        case C::Persistence:         add("T1547.001", "Registry Run Keys / Startup Folder");break;
        case C::Networking:          add("T1071",     "Application Layer Protocol");       break;
        case C::Cryptography:        add("T1573",     "Encrypted Channel");                break;
        case C::InputCapture:        add("T1056.001", "Keylogging");                       break;
        case C::ScreenCapture:       add("T1113",     "Screen Capture");                   break;
        case C::TokenPrivilege:      add("T1134",     "Access Token Manipulation");        break;
        case C::ServiceControl:      add("T1543.003", "Windows Service");                  break;
        case C::Reconnaissance:      add("T1082",     "System Information Discovery");     break;
        case C::DefenseEvasion:      add("T1070",     "Indicator Removal");                break;
    }
}

// De-duplicated technique list for a scored PE.
inline std::vector<Technique> techniques(const sig::ScoreResult& r) {
    std::vector<Technique> out;
    std::set<std::string> seen;
    auto push = [&](const Technique& t){ if (seen.insert(t.id).second) out.push_back(t); };

    bool net = false, crypt = false, input = false, screen = false;
    for (const auto& h : r.capabilities) {
        if (!h.significant) continue;
        switch (h.cap) {
            case sig::Capability::Networking:    net = true;    break;
            case sig::Capability::Cryptography:  crypt = true;  break;
            case sig::Capability::InputCapture:  input = true;  break;
            case sig::Capability::ScreenCapture: screen = true; break;
            default: break;
        }
        std::vector<Technique> ts;
        map_capability(h.cap, ts);
        for (auto& t : ts) push(t);
    }

    // combinations that imply a higher-order technique
    if (crypt && net)  push({"T1486", "Data Encrypted for Impact"});
    if (input && net)  push({"T1041", "Exfiltration Over C2 Channel"});
    if (screen && net) push({"T1041", "Exfiltration Over C2 Channel"});

    return out;
}

} // namespace attack
} // namespace horus
