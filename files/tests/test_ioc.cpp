#include "../src/ioc.hpp"
#include <iostream>

using namespace argus;
int failures = 0;
#define EXPECT(input, want) do { \
    IocType got = classify(input); \
    if (got != (want)) { \
        std::cerr << "FAIL: classify(\"" << (input) << "\") = " << ioc_type_name(got) \
                  << ", wanted " << ioc_type_name(want) << "\n"; \
        ++failures; \
    } } while(0)

int main() {
    // Hashes
    EXPECT("d41d8cd98f00b204e9800998ecf8427e", IocType::MD5);            // 32 hex
    EXPECT("da39a3ee5e6b4b0d3255bfef95601890afd80709", IocType::SHA1);   // 40 hex
    EXPECT("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IocType::SHA256);
    EXPECT("ABCDEF0123456789abcdef0123456789", IocType::MD5);            // mixed case ok
    EXPECT("xyz123", IocType::Unknown);                                  // not hex
    EXPECT("deadbeef", IocType::Unknown);                                // hex but wrong width

    // IPv4
    EXPECT("8.8.8.8", IocType::IPv4);
    EXPECT("192.168.1.1", IocType::IPv4);
    EXPECT("255.255.255.255", IocType::IPv4);
    EXPECT("256.1.1.1", IocType::Unknown);     // out of range
    EXPECT("1.2.3", IocType::Unknown);          // too few octets
    EXPECT("1.2.3.4.5", IocType::Unknown);      // too many
    EXPECT("01.2.3.4", IocType::Unknown);       // leading zero

    // IPv6
    EXPECT("2001:0db8:85a3:0000:0000:8a2e:0370:7334", IocType::IPv6);
    EXPECT("::1", IocType::IPv6);
    EXPECT("fe80::1", IocType::IPv6);
    EXPECT("2001:db8::ff00:42:8329", IocType::IPv6);
    EXPECT("1::2::3", IocType::Unknown);        // double "::" twice

    // URLs
    EXPECT("http://evil.example.com/payload.bin", IocType::Url);
    EXPECT("https://malware.test/a?b=c", IocType::Url);
    EXPECT("HTTPS://CAPS.EXAMPLE.ORG", IocType::Url);

    // Email
    EXPECT("attacker@phishing-domain.com", IocType::Email);
    EXPECT("a.b+tag@mail.example.co", IocType::Email);
    EXPECT("not@an@email.com", IocType::Unknown);   // two '@'

    // Domains
    EXPECT("example.com", IocType::Domain);
    EXPECT("sub.domain.example.org", IocType::Domain);
    EXPECT("xn--punycode.io", IocType::Domain);
    EXPECT("-bad.com", IocType::Unknown);           // label starts with hyphen
    EXPECT("nodot", IocType::Unknown);              // no TLD
    EXPECT("trailing.dot.", IocType::Unknown);

    // Whitespace tolerance
    EXPECT("   8.8.4.4   ", IocType::IPv4);

    if (failures == 0) std::cout << "ALL IOC TESTS PASSED\n";
    else std::cout << failures << " IOC test(s) failed\n";
    return failures;
}
