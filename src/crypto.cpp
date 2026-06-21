// ---------------------------------------------------------------------------
//  crypto.cpp  -  CNG/BCrypt implementation
// ---------------------------------------------------------------------------
#include "crypto.hpp"

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace horus {
namespace crypto {
namespace {

constexpr size_t HASH_CHUNK = 1u << 20;   // feed the hash in 1 MiB bites

std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

// RAII for the algorithm provider handle - closes itself no matter how we leave.
struct AlgProvider {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgProvider() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

// RAII for the hash object handle.
struct HashObject {
    BCRYPT_HASH_HANDLE h = nullptr;
    ~HashObject() { if (h) BCryptDestroyHash(h); }
};

// The single hashing routine. `alg` is one of the BCRYPT_*_ALGORITHM strings.
// Returns the raw digest bytes, or empty on any failure (callers treat empty as
// "couldn't hash" rather than crashing).
std::vector<uint8_t> digest(LPCWSTR alg, const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;

    AlgProvider provider;
    if (BCryptOpenAlgorithmProvider(&provider.h, alg, nullptr, 0) != STATUS_SUCCESS)
        return result;

    DWORD obj_len = 0, written = 0;
    if (BCryptGetProperty(provider.h, BCRYPT_OBJECT_LENGTH,
                          reinterpret_cast<PUCHAR>(&obj_len), sizeof(obj_len),
                          &written, 0) != STATUS_SUCCESS)
        return result;

    DWORD hash_len = 0;
    if (BCryptGetProperty(provider.h, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len),
                          &written, 0) != STATUS_SUCCESS)
        return result;

    std::vector<uint8_t> obj_buffer(obj_len);
    HashObject hash;
    if (BCryptCreateHash(provider.h, &hash.h,
                         obj_buffer.data(), obj_len,
                         nullptr, 0, 0) != STATUS_SUCCESS)
        return result;

    // Stream the buffer through in chunks so a multi-gigabyte sample never tries
    // to pass a length that overflows the ULONG parameter.
    size_t offset = 0;
    while (offset < len) {
        ULONG chunk = static_cast<ULONG>(len - offset < HASH_CHUNK ? len - offset : HASH_CHUNK);
        if (BCryptHashData(hash.h,
                           const_cast<PUCHAR>(data + offset), chunk, 0) != STATUS_SUCCESS)
            return result;
        offset += chunk;
    }

    result.resize(hash_len);
    if (BCryptFinishHash(hash.h, result.data(), hash_len, 0) != STATUS_SUCCESS) {
        result.clear();
        return result;
    }
    return result;
}

std::string hex_digest(LPCWSTR alg, const uint8_t* data, size_t len) {
    auto d = digest(alg, data, len);
    return d.empty() ? std::string() : to_hex(d);
}

} // namespace

std::string md5_hex(const uint8_t* data, size_t len) {
    return hex_digest(BCRYPT_MD5_ALGORITHM, data, len);
}
std::string sha1_hex(const uint8_t* data, size_t len) {
    return hex_digest(BCRYPT_SHA1_ALGORITHM, data, len);
}
std::string sha256_hex(const uint8_t* data, size_t len) {
    return hex_digest(BCRYPT_SHA256_ALGORITHM, data, len);
}

std::string md5_hex(const std::string& text) {
    return md5_hex(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

FileHashes hash_buffer(const std::vector<uint8_t>& data) {
    FileHashes h;
    h.md5    = md5_hex(data.data(), data.size());
    h.sha1   = sha1_hex(data.data(), data.size());
    h.sha256 = sha256_hex(data.data(), data.size());
    h.ok     = !h.md5.empty() && !h.sha1.empty() && !h.sha256.empty();
    return h;
}

} // namespace crypto
} // namespace horus
