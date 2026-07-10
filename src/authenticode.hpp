// ---------------------------------------------------------------------------
//  authenticode.hpp  -  real signature verification, not just presence
//
//  pe.hpp only tells you whether a certificate table exists. This actually runs
//  the signature through WinVerifyTrust - so a file whose bytes were changed
//  after signing (or a forged/self-signed blob) comes back INVALID / UNTRUSTED
//  instead of "signed: yes" - and pulls the signer's common name out of the
//  PKCS#7 for attribution. Windows-only, links wintrust + crypt32 (both ship
//  with the OS, so the zero-third-party-dependency promise holds).
// ---------------------------------------------------------------------------
#pragma once

#include <string>

namespace horus {
namespace authcode {

enum class Status {
    NotSigned,   // no signature at all
    Valid,       // signature verifies and chains to a trusted root
    Invalid,     // digest mismatch - file altered after signing / forged
    Untrusted,   // signature parses but chain isn't trusted (self-signed etc.)
    Expired,     // signing certificate has expired
    Revoked,     // signing certificate was revoked
    Malformed,   // certificate present but unparseable
    Error        // verification could not be completed
};

struct Result {
    Status      status = Status::NotSigned;
    std::string status_text;
    std::string signer;     // subject CN of the signing certificate
    std::string issuer;     // issuer CN
    bool        embedded = false;   // signature was embedded in the PE
    bool        catalog  = false;   // verified via a security catalog instead
};

const char* status_label(Status s);

// Verify the file at `path` (UTF-8). `has_embedded_cert` comes from the PE
// parser and separates "genuinely unsigned" from "signature present but failed".
Result verify(const std::string& path_utf8, bool has_embedded_cert);

} // namespace authcode
} // namespace horus
