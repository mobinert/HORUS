// ---------------------------------------------------------------------------
//  crypto.hpp  -  file hashing via the Windows CNG (BCrypt) provider
//
//  Every hash in the tool - the three file digests an analyst pastes into a
//  ticket, plus the MD5 that turns the import string into an imphash - goes
//  through one code path here. No OpenSSL, no bundled MD5: this calls the same
//  crypto provider the OS itself uses (BCrypt*/CNG), which is the right way to
//  do it on modern Windows and means there's a single implementation to trust.
// ---------------------------------------------------------------------------
#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace argus {
namespace crypto {

// The three digests an analyst almost always wants off a sample at once.
struct FileHashes {
    bool        ok = false;
    std::string md5;
    std::string sha1;
    std::string sha256;
};

// Lowercase hex digest of an arbitrary buffer. Empty string on failure.
std::string md5_hex   (const uint8_t* data, size_t len);
std::string sha1_hex  (const uint8_t* data, size_t len);
std::string sha256_hex(const uint8_t* data, size_t len);

// Convenience overload for hashing the imphash canonical string.
std::string md5_hex(const std::string& text);

// Compute all three digests in one pass over the buffer.
FileHashes hash_buffer(const std::vector<uint8_t>& data);

} // namespace crypto
} // namespace argus
