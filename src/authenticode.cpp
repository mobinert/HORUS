// ---------------------------------------------------------------------------
//  authenticode.cpp  -  WinVerifyTrust + crypt32 signer extraction
// ---------------------------------------------------------------------------
#include "authenticode.hpp"

// Catalog verification uses the current Windows trust API surface.
#ifdef _WIN32_WINNT
#  undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0A00

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace horus {
namespace authcode {

static std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int need = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(need, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], need);
    return w;
}

const char* status_label(Status s) {
    switch (s) {
        case Status::NotSigned: return "unsigned";
        case Status::Valid:     return "valid";
        case Status::Invalid:   return "INVALID";
        case Status::Untrusted: return "untrusted";
        case Status::Expired:   return "expired";
        case Status::Revoked:   return "revoked";
        case Status::Malformed: return "malformed";
        default:                return "error";
    }
}

// Pull the signer + issuer common name out of the embedded PKCS#7. Runs
// independently of the trust decision so we can name the signer even when the
// chain doesn't verify.
static std::string extract_signer(const std::wstring& path, std::string& issuer_out) {
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG  hMsg   = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
            &hStore, &hMsg, nullptr))
        return {};

    std::string subject;
    DWORD si_size = 0;
    if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &si_size) && si_size) {
        std::vector<BYTE> buf(si_size);
        if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &si_size)) {
            auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
            CERT_INFO ci;
            ci.Issuer       = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(hStore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                CERT_FIND_SUBJECT_CERT, &ci, nullptr);
            if (cert) {
                char name[256] = {0};
                if (CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                       nullptr, name, sizeof(name)))
                    subject = name;
                char iss[256] = {0};
                if (CertGetNameStringA(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                       CERT_NAME_ISSUER_FLAG, nullptr, iss, sizeof(iss)))
                    issuer_out = iss;
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (hMsg)   CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);
    return subject;
}

// Fall back to the security catalogs (how most OS binaries are signed - they
// carry no embedded certificate). Locate the catalog whose hash matches this
// file, then verify against it and read the catalog's signer.
static bool verify_catalog(const std::wstring& path, Result& r, bool online_revocation) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HCATADMIN hAdmin = nullptr;
    if (!CryptCATAdminAcquireContext2(&hAdmin, nullptr, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) {
        CloseHandle(hFile);
        return false;
    }

    bool matched = false;
    DWORD hash_len = 0;
    CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hash_len, nullptr, 0);
    if (hash_len > 0) {
        std::vector<BYTE> hash(hash_len);
        if (CryptCATAdminCalcHashFromFileHandle2(hAdmin, hFile, &hash_len, hash.data(), 0)) {
            std::wstring tag;
            tag.reserve(hash_len * 2);
            const wchar_t* HX = L"0123456789ABCDEF";
            for (DWORD i = 0; i < hash_len; ++i) { tag += HX[hash[i] >> 4]; tag += HX[hash[i] & 0xF]; }

            HCATINFO hCat = CryptCATAdminEnumCatalogFromHash(hAdmin, hash.data(), hash_len, 0, nullptr);
            if (hCat) {
                CATALOG_INFO ci;
                ci.cbStruct = sizeof(ci);
                if (CryptCATCatalogInfoFromContext(hCat, &ci, 0)) {
                    WINTRUST_CATALOG_INFO wci = {0};
                    wci.cbStruct             = sizeof(wci);
                    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                    wci.pcwszMemberFilePath  = path.c_str();
                    wci.pcwszMemberTag       = tag.c_str();
                    wci.hMemberFile          = hFile;
                    wci.pbCalculatedFileHash = hash.data();
                    wci.cbCalculatedFileHash = hash_len;
                    wci.hCatAdmin            = hAdmin;

                    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    WINTRUST_DATA wd = {0};
                    wd.cbStruct            = sizeof(wd);
                    wd.dwUIChoice          = WTD_UI_NONE;
                    wd.fdwRevocationChecks = online_revocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
                    wd.dwUnionChoice       = WTD_CHOICE_CATALOG;
                    wd.pCatalog            = &wci;
                    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
                    wd.dwProvFlags         = WTD_SAFER_FLAG |
                        (online_revocation ? WTD_REVOCATION_CHECK_CHAIN : WTD_CACHE_ONLY_URL_RETRIEVAL);

                    LONG st = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
                    wd.dwStateAction = WTD_STATEACTION_CLOSE;
                    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

                    matched = true;
                    r.catalog = true;
                    if (st == 0) {
                        r.status = Status::Valid;
                        r.status_text = online_revocation
                            ? "valid, catalog-signed with online revocation check"
                            : "valid, catalog-signed using cached trust data; revocation not checked";
                    } else if (static_cast<DWORD>(st) == TRUST_E_BAD_DIGEST) {
                        r.status = Status::Invalid;
                        r.status_text = "catalog digest mismatch - file altered";
                    } else {
                        r.status = Status::Untrusted;
                        char b[80];
                        std::snprintf(b, sizeof(b), "catalog verify failed (0x%08lX)",
                                      static_cast<unsigned long>(st));
                        r.status_text = b;
                    }
                    std::string issuer;
                    std::string signer = extract_signer(ci.wszCatalogFile, issuer);
                    if (!signer.empty()) { r.signer = signer; r.issuer = issuer; }
                }
                CryptCATAdminReleaseCatalogContext(hAdmin, hCat, 0);
            }
        }
    }

    CryptCATAdminReleaseContext(hAdmin, 0);
    CloseHandle(hFile);
    return matched;
}

Result verify(const std::string& path_utf8, bool has_embedded_cert,
              bool online_revocation) {
    Result r;
    r.embedded = has_embedded_cert;
    r.revocation_checked = online_revocation;
    std::wstring path = widen(path_utf8);

    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct      = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = {0};
    wd.cbStruct            = sizeof(wd);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = online_revocation ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fi;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG |
        (online_revocation ? WTD_REVOCATION_CHECK_CHAIN : WTD_CACHE_ONLY_URL_RETRIEVAL);

    LONG st = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    switch (static_cast<DWORD>(st)) {
        case 0:
            r.status = Status::Valid;
            r.status_text = online_revocation
                ? "valid, chain and revocation checked online"
                : "valid using cached trust data; revocation not checked";
            break;
        case TRUST_E_NOSIGNATURE:
            if (has_embedded_cert) {
                r.status = Status::Malformed;
                r.status_text = "certificate present but did not verify (tampered or corrupt)";
            } else {
                r.status = Status::NotSigned;
                r.status_text = "no embedded Authenticode signature";
            }
            break;
        case TRUST_E_BAD_DIGEST:
            r.status = Status::Invalid;
            r.status_text = "digest mismatch - file altered after signing or forged";
            break;
        case CERT_E_EXPIRED:
            r.status = Status::Expired;
            r.status_text = "signing certificate has expired";
            break;
        case CERT_E_REVOKED:
            r.status = Status::Revoked;
            r.status_text = "signing certificate was revoked";
            break;
        case CERT_E_UNTRUSTEDROOT:
        case CERT_E_CHAINING:
            r.status = Status::Untrusted;
            r.status_text = "chain does not reach a trusted root (self-signed?)";
            break;
        case TRUST_E_EXPLICIT_DISTRUST:
            r.status = Status::Untrusted;
            r.status_text = "signer is explicitly distrusted";
            break;
        case TRUST_E_SUBJECT_NOT_TRUSTED:
            r.status = Status::Untrusted;
            r.status_text = "subject is not trusted";
            break;
        default: {
            char b[80];
            std::snprintf(b, sizeof(b), "verification failed (0x%08lX)", static_cast<unsigned long>(st));
            r.status = has_embedded_cert ? Status::Invalid : Status::Error;
            r.status_text = b;
            break;
        }
    }

    // No embedded signature? Most Windows binaries are catalog-signed instead.
    if (r.status == Status::NotSigned)
        verify_catalog(path, r, online_revocation);

    if (has_embedded_cert)
        r.signer = extract_signer(path, r.issuer);

    return r;
}

} // namespace authcode
} // namespace horus
