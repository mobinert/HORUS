// ---------------------------------------------------------------------------
//  intel.hpp  -  threat-intelligence enrichment
//
//  The lookups all share a shape - take an indicator, ask a provider, come back
//  with "known/unknown" and a few numbers - so they sit behind one interface.
//  Adding URLhaus or OTX later is just another subclass; nothing else changes.
//  enrich() fans the applicable sources out across threads, because waiting on
//  three REST APIs one after another when they could all run at once is silly.
// ---------------------------------------------------------------------------
#pragma once

#include "ioc.hpp"
#include <string>
#include <vector>
#include <memory>
#include <utility>

namespace horus {
namespace intel {

// A normalised answer from one provider about one indicator.
struct SourceResult {
    std::string source;        // "VirusTotal", "AbuseIPDB", ...
    bool        ok      = false;   // the query itself worked
    bool        found   = false;   // the provider had something on this indicator
    std::string summary;           // one-line headline for the report
    std::vector<std::pair<std::string, std::string>> details;  // key/value rows

    // Whichever of these the source actually provides; -1 means "not applicable".
    int         malicious = -1;    // engines/flags calling it bad
    int         total     = -1;    // engines that weighed in
    int         score     = -1;    // 0-100 reputation/abuse confidence

    std::string error;             // populated when ok == false
};

// The interface every provider implements.
class IntelSource {
public:
    virtual ~IntelSource() = default;
    virtual std::string name() const = 0;
    virtual bool        supports(IocType type) const = 0;
    virtual SourceResult lookup(const std::string& indicator, IocType type) const = 0;
};

// --- VirusTotal v3: files/hashes, IPs, domains, URLs ---
class VirusTotal : public IntelSource {
public:
    explicit VirusTotal(std::string api_key) : key_(std::move(api_key)) {}
    std::string name() const override { return "VirusTotal"; }
    bool supports(IocType type) const override;
    SourceResult lookup(const std::string& indicator, IocType type) const override;
private:
    std::string key_;
};

// --- AbuseIPDB v2: IP reputation only ---
class AbuseIPDB : public IntelSource {
public:
    explicit AbuseIPDB(std::string api_key) : key_(std::move(api_key)) {}
    std::string name() const override { return "AbuseIPDB"; }
    bool supports(IocType type) const override;
    SourceResult lookup(const std::string& indicator, IocType type) const override;
private:
    std::string key_;
};

// Run every source that supports this indicator type, in parallel, and collect
// the results. Sources that don't apply are simply skipped.
std::vector<SourceResult> enrich(
    const std::vector<std::shared_ptr<IntelSource>>& sources,
    const std::string& indicator,
    IocType type);

// base64url with no padding - used to form the VT URL-report identifier.
std::string base64url_nopad(const std::string& in);

} // namespace intel
} // namespace horus
