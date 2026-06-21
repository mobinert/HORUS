// ---------------------------------------------------------------------------
//  intel.cpp  -  VirusTotal + AbuseIPDB implementations
// ---------------------------------------------------------------------------
#include "intel.hpp"
#include "http.hpp"
#include "json.hpp"

#include <future>
#include <sstream>

namespace horus {
namespace intel {

// ---------------------------------------------------------------------------
//  base64url (RFC 4648 §5) without the '=' padding, which is exactly the form
//  VirusTotal wants for a URL identifier.
// ---------------------------------------------------------------------------
std::string base64url_nopad(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    size_t i = 0;
    while (i + 3 <= in.size()) {
        uint32_t n = (uint8_t)in[i] << 16 | (uint8_t)in[i+1] << 8 | (uint8_t)in[i+2];
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6)  & 63];
        out += tbl[n & 63];
        i += 3;
    }
    size_t rem = in.size() - i;
    if (rem == 1) {
        uint32_t n = (uint8_t)in[i] << 16;
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
    } else if (rem == 2) {
        uint32_t n = (uint8_t)in[i] << 16 | (uint8_t)in[i+1] << 8;
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6)  & 63];
    }
    return out;
}

namespace {

std::string commas(long long v) {            // 12345 -> "12,345", easier to read
    std::string s = std::to_string(v);
    int insert = (int)s.size() - 3;
    while (insert > 0) { s.insert(insert, ","); insert -= 3; }
    return s;
}

} // namespace

// ===========================================================================
//  VirusTotal
// ===========================================================================
bool VirusTotal::supports(IocType type) const {
    switch (type) {
        case IocType::MD5: case IocType::SHA1: case IocType::SHA256:
        case IocType::IPv4: case IocType::IPv6:
        case IocType::Domain: case IocType::Url:
            return true;
        default:
            return false;
    }
}

SourceResult VirusTotal::lookup(const std::string& indicator, IocType type) const {
    SourceResult r; r.source = name();
    if (key_.empty()) { r.error = "no API key set (VT_API_KEY)"; return r; }

    // Pick the right v3 collection and resource id for the indicator type.
    std::string path;
    switch (type) {
        case IocType::MD5: case IocType::SHA1: case IocType::SHA256:
            path = "/api/v3/files/" + indicator; break;
        case IocType::IPv4: case IocType::IPv6:
            path = "/api/v3/ip_addresses/" + indicator; break;
        case IocType::Domain:
            path = "/api/v3/domains/" + indicator; break;
        case IocType::Url:
            path = "/api/v3/urls/" + base64url_nopad(indicator); break;
        default:
            r.error = "unsupported indicator type for VirusTotal"; return r;
    }

    http::Request req;
    req.host = "www.virustotal.com";
    req.path = path;
    req.headers["x-apikey"] = key_;
    req.headers["Accept"]   = "application/json";

    http::Response resp = http::perform(req);
    if (!resp.ok) { r.error = resp.error; return r; }

    if (resp.status == 404) {                 // VT's "never seen this" answer
        r.ok = true; r.found = false;
        r.summary = "not found in VirusTotal's dataset";
        return r;
    }
    if (resp.status == 401) { r.error = "VirusTotal rejected the API key (401)"; return r; }
    if (resp.status == 429) { r.error = "VirusTotal rate limit hit (429) - try again shortly"; return r; }
    if (resp.status != 200) { r.error = "VirusTotal returned HTTP " + std::to_string(resp.status); return r; }

    json::Value doc;
    try { doc = json::parse(resp.body); }
    catch (const std::exception& e) { r.error = std::string("malformed VT JSON: ") + e.what(); return r; }

    const auto& attr  = doc["data"]["attributes"];
    const auto& stats = attr["last_analysis_stats"];

    r.ok    = true;
    r.found = true;
    r.malicious = (int)stats["malicious"].as_int(0) + (int)stats["suspicious"].as_int(0);
    r.total = r.malicious
            + (int)stats["undetected"].as_int(0)
            + (int)stats["harmless"].as_int(0)
            + (int)stats["timeout"].as_int(0);

    std::ostringstream sum;
    sum << r.malicious << "/" << r.total << " engines flagged this";
    r.summary = sum.str();

    // A few context rows that differ by indicator type.
    if (attr.contains("meaningful_name"))
        r.details.push_back({"name", attr["meaningful_name"].as_string()});
    if (attr.contains("type_description"))
        r.details.push_back({"type", attr["type_description"].as_string()});
    if (attr.contains("reputation"))
        r.details.push_back({"reputation", std::to_string(attr["reputation"].as_int(0))});
    if (attr.contains("as_owner"))
        r.details.push_back({"AS owner", attr["as_owner"].as_string()});
    if (attr.contains("country"))
        r.details.push_back({"country", attr["country"].as_string()});

    return r;
}

// ===========================================================================
//  AbuseIPDB
// ===========================================================================
bool AbuseIPDB::supports(IocType type) const {
    return type == IocType::IPv4 || type == IocType::IPv6;
}

SourceResult AbuseIPDB::lookup(const std::string& indicator, IocType type) const {
    SourceResult r; r.source = name();
    if (!supports(type)) { r.error = "AbuseIPDB only handles IP addresses"; return r; }
    if (key_.empty())    { r.error = "no API key set (ABUSEIPDB_API_KEY)"; return r; }

    http::Request req;
    req.host = "api.abuseipdb.com";
    req.path = "/api/v2/check?ipAddress=" + indicator + "&maxAgeInDays=90";
    req.headers["Key"]    = key_;
    req.headers["Accept"] = "application/json";

    http::Response resp = http::perform(req);
    if (!resp.ok) { r.error = resp.error; return r; }
    if (resp.status == 401) { r.error = "AbuseIPDB rejected the API key (401)"; return r; }
    if (resp.status == 429) { r.error = "AbuseIPDB rate limit hit (429)"; return r; }
    if (resp.status != 200) { r.error = "AbuseIPDB returned HTTP " + std::to_string(resp.status); return r; }

    json::Value doc;
    try { doc = json::parse(resp.body); }
    catch (const std::exception& e) { r.error = std::string("malformed AbuseIPDB JSON: ") + e.what(); return r; }

    const auto& d = doc["data"];
    r.ok    = true;
    r.found = true;
    r.score = (int)d["abuseConfidenceScore"].as_int(0);

    int reports = (int)d["totalReports"].as_int(0);
    std::ostringstream sum;
    sum << "abuse confidence " << r.score << "% across " << commas(reports) << " report(s)";
    r.summary = sum.str();

    if (d.contains("countryCode")) r.details.push_back({"country", d["countryCode"].as_string()});
    if (d.contains("isp"))         r.details.push_back({"ISP", d["isp"].as_string()});
    if (d.contains("domain"))      r.details.push_back({"domain", d["domain"].as_string()});
    if (d.contains("usageType"))   r.details.push_back({"usage", d["usageType"].as_string()});
    r.details.push_back({"reports (90d)", commas(reports)});

    return r;
}

// ===========================================================================
//  Parallel fan-out
// ===========================================================================
std::vector<SourceResult> enrich(
    const std::vector<std::shared_ptr<IntelSource>>& sources,
    const std::string& indicator,
    IocType type)
{
    std::vector<std::future<SourceResult>> pending;
    for (const auto& src : sources) {
        if (!src->supports(type)) continue;
        // Each lookup is independent network I/O - run them at the same time.
        pending.push_back(std::async(std::launch::async,
            [src, indicator, type]() { return src->lookup(indicator, type); }));
    }

    std::vector<SourceResult> results;
    results.reserve(pending.size());
    for (auto& f : pending) results.push_back(f.get());
    return results;
}

} // namespace intel
} // namespace horus
