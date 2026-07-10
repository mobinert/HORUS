// ---------------------------------------------------------------------------
//  fuzzy.hpp  -  locality-sensitive / context-triggered hashing
//
//  Two families of "similarity" hash, both computed straight off the raw file
//  bytes so HORUS can cluster related samples instead of only scoring one:
//
//    * TLSH   - Trend Micro Locality Sensitive Hash. Bucketed Pearson triplets
//               over a 5-byte sliding window, quantised against the bucket
//               quartiles. Two near-identical files land a few units apart;
//               identical files score 0. Output is the canonical "T1.." digest,
//               byte-for-byte compatible with libtlsh (128 buckets / 1B cksum).
//
//    * ssdeep - context-triggered piecewise hashing (Tridgell's spamsum). A
//               rolling hash chops the input at content-defined boundaries and
//               an FNV hash summarises each piece. Output "blocksize:h1:h2" is
//               compatible with the ssdeep tool.
//
//  Self-contained, no third-party code - the tables/constants are reproduced
//  from the reference algorithms.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <array>

namespace horus {
namespace fuzzy {

// ===========================================================================
//  TLSH
// ===========================================================================
namespace tlsh_detail {

// Pearson sample table (identical to libtlsh v_table)
static const unsigned char VT[256] = {
    1,87,49,12,176,178,102,166,121,193,6,84,249,230,44,163,
    14,197,213,181,161,85,218,80,64,239,24,226,236,142,38,200,
    110,177,104,103,141,253,255,50,77,101,81,18,45,96,31,222,
    25,107,190,70,86,237,240,34,72,242,20,214,244,227,149,235,
    97,234,57,22,60,250,82,175,208,5,127,199,111,62,135,248,
    174,169,211,58,66,154,106,195,245,171,17,187,182,179,0,243,
    132,56,148,75,128,133,158,100,130,126,91,13,153,246,216,219,
    119,68,223,78,83,88,201,99,122,11,92,32,136,114,52,10,
    138,30,48,183,156,35,61,26,143,74,251,94,129,162,63,152,
    170,7,115,167,241,206,3,150,55,59,151,220,90,53,23,131,
    125,173,15,238,79,95,89,16,105,137,225,224,217,160,37,123,
    118,73,2,157,46,116,9,145,134,228,207,212,202,215,69,229,
    27,188,67,124,168,252,42,4,29,108,21,247,19,205,39,203,
    233,40,186,147,198,192,155,33,164,191,98,204,165,180,117,76,
    140,36,210,172,41,54,159,8,185,232,113,196,231,47,146,120,
    51,65,28,144,254,221,93,189,194,139,112,43,71,109,184,209
};

// topval table used by l_capturing (length -> log bucket)
static const unsigned int TOPVAL[170] = {
    1,2,3,5,7,11,17,25,38,57,86,129,194,291,437,656,854,1110,1443,1876,
    2439,3171,3475,3823,4205,4626,5088,5597,6157,6772,7450,8195,9014,9916,
    10907,11998,13198,14518,15970,17567,19323,21256,23382,25720,28292,31121,
    34233,37656,41422,45564,50121,55133,60646,66711,73382,80721,88793,97672,
    107439,118183,130002,143002,157302,173032,190335,209369,230306,253337,
    278670,306538,337191,370911,408002,448802,493682,543050,597356,657091,
    722800,795081,874589,962048,1058252,1164078,1280486,1408534,1549388,
    1704327,1874759,2062236,2268459,2495305,2744836,3019320,3321252,3653374,
    4018711,4420582,4862641,5348905,5883796,6472176,7119394,7831333,8614467,
    9475909,10423501,11465851,12612437,13873681,15261050,16787154,18465870,
    20312458,22343706,24578077,27035886,29739474,32713425,35984770,39583245,
    43541573,47895730,52685306,57953837,63749221,70124148,77136564,84850228,
    93335252,102668779,112935659,124229227,136652151,150317384,165349128,
    181884040,200072456,220079703,242087671,266296456,292926096,322218735,
    354440623,389884688,428873168,471760495,518936559,570830240,627913311,
    690704607,759775136,835752671,919327967,1011260767,1112386880,1223623232,
    1345985727,1480584256,1628642751,1791507135,1970657856,2167723648,
    2384496256,2622945920,2885240448,3173764736,3491141248,3840255616,4224281216u
};

inline unsigned char fastb(unsigned char s, unsigned char i, unsigned char j, unsigned char k) {
    return VT[ VT[ VT[(unsigned char)(s ^ i)] ^ j ] ^ k ];
}

inline unsigned char swapb(unsigned char in) {
    return (unsigned char)(((in & 0xF0) >> 4) | ((in & 0x0F) << 4));
}

inline unsigned char l_capturing(unsigned int len) {
    int bottom = 0, top = 170;
    unsigned char idx = 85;
    for (;;) {
        if (idx == 0) return 0;
        if (len <= TOPVAL[idx] && len > TOPVAL[idx-1]) return idx;
        if (len < TOPVAL[idx]) top = idx - 1;
        else                   bottom = idx + 1;
        idx = (unsigned char)((bottom + top) / 2);
    }
}

inline int mod_diff(unsigned int x, unsigned int y, unsigned int R) {
    int dl, dr;
    if (y > x) { dl = (int)(y - x); dr = (int)(x + R - y); }
    else       { dl = (int)(x - y); dr = (int)(y + R - x); }
    return dl > dr ? dr : dl;
}

inline int pairbit(int a, int b) {
    int d = a - b; if (d < 0) d = -d;
    if (d == 0) return 0;
    if (d == 1) return 1;
    if (d == 2) return 2;
    return 6;
}
inline int byte_diff(unsigned char x, unsigned char y) {
    int h1=x/16, oh1=y/16, h2=x%16, oh2=y%16;
    return pairbit(h1/4,oh1/4) + pairbit(h1%4,oh1%4)
         + pairbit(h2/4,oh2/4) + pairbit(h2%4,oh2%4);
}

} // namespace tlsh_detail

// Returns the 72-char "T1..." digest, or "" when the input is too small /
// too uniform for a stable hash (mirrors libtlsh's own bail-outs).
inline std::string tlsh(const uint8_t* data, size_t len) {
    using namespace tlsh_detail;
    if (len < 50) return {};

    std::vector<unsigned int> bucket(256, 0);
    unsigned char sw[5] = {0,0,0,0,0};
    unsigned char checksum = 0;
    int j = 0;
    for (size_t i = 0; i < len; ++i) {
        sw[j] = data[i];
        if (i >= 4) {
            int j1=(j+4)%5, j2=(j+3)%5, j3=(j+2)%5, j4=(j+1)%5;
            checksum = fastb(1, sw[j], sw[j1], checksum);
            bucket[fastb(49,  sw[j], sw[j1], sw[j2])]++;
            bucket[fastb(12,  sw[j], sw[j1], sw[j3])]++;
            bucket[fastb(178, sw[j], sw[j2], sw[j3])]++;
            bucket[fastb(166, sw[j], sw[j2], sw[j4])]++;
            bucket[fastb(84,  sw[j], sw[j1], sw[j4])]++;
            bucket[fastb(230, sw[j], sw[j3], sw[j4])]++;
        }
        j = (j + 1) % 5;
    }

    // quartiles over the first 128 buckets
    std::array<unsigned int,128> cp;
    for (int i = 0; i < 128; ++i) cp[i] = bucket[i];
    std::sort(cp.begin(), cp.end());
    unsigned int q1 = cp[31], q2 = cp[63], q3 = cp[95];
    if (q3 == 0) return {};

    int nonzero = 0;
    for (int i = 0; i < 128; ++i) if (bucket[i] > 0) ++nonzero;
    if (nonzero <= 64) return {};

    unsigned char code[32];
    for (int i = 0; i < 32; ++i) {
        unsigned char h = 0;
        for (int b = 0; b < 4; ++b) {
            unsigned int k = bucket[4*i + b];
            if      (q3 < k) h += (unsigned char)(3 << (b*2));
            else if (q2 < k) h += (unsigned char)(2 << (b*2));
            else if (q1 < k) h += (unsigned char)(1 << (b*2));
        }
        code[i] = h;
    }

    unsigned char lvalue = l_capturing((unsigned int)len);
    unsigned char q1r = (unsigned char)(((unsigned long long)q1 * 100 / q3) % 16);
    unsigned char q2r = (unsigned char)(((unsigned long long)q2 * 100 / q3) % 16);

    unsigned char out[35];
    out[0] = swapb(checksum);
    out[1] = swapb(lvalue);
    out[2] = (unsigned char)((q2r << 4) | q1r);   // hi nibble = Q2ratio, lo = Q1ratio
    for (int i = 0; i < 32; ++i) out[3 + i] = code[31 - i];

    static const char* H = "0123456789ABCDEF";
    std::string s = "T1";
    for (int i = 0; i < 35; ++i) { s += H[out[i] >> 4]; s += H[out[i] & 0xF]; }
    return s;
}

inline std::string tlsh(const std::vector<uint8_t>& d) { return tlsh(d.data(), d.size()); }

// Distance between two "T1.." digests. 0 == identical; higher == more distant.
// Returns -1 for malformed input. Matches libtlsh totalDiff (len_diff on).
inline int tlsh_diff(const std::string& a, const std::string& b) {
    using namespace tlsh_detail;
    auto unpack = [](const std::string& s, unsigned char out[35]) -> bool {
        size_t off = (s.size() == 72 && s[0]=='T') ? 2 : 0;
        if (s.size() - off != 70) return false;
        auto hx = [](char c)->int{
            if (c>='0'&&c<='9') return c-'0';
            if (c>='a'&&c<='f') return c-'a'+10;
            if (c>='A'&&c<='F') return c-'A'+10;
            return -1;
        };
        for (int i = 0; i < 35; ++i) {
            int hi = hx(s[off+2*i]), lo = hx(s[off+2*i+1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = (unsigned char)((hi<<4)|lo);
        }
        return true;
    };
    unsigned char ba[35], bb[35];
    if (!unpack(a, ba) || !unpack(b, bb)) return -1;

    auto L  = [](const unsigned char x[35]){ return (unsigned)swapb(x[1]); };
    auto CK = [](const unsigned char x[35]){ return swapb(x[0]); };
    auto Q1 = [](const unsigned char x[35]){ return (unsigned)(x[2] & 0xF); };
    auto Q2 = [](const unsigned char x[35]){ return (unsigned)(x[2] >> 4); };

    int diff = 0;
    int ld = mod_diff(L(ba), L(bb), 256);
    if      (ld == 0) diff += 0;
    else if (ld == 1) diff += 1;
    else              diff += ld * 12;

    int q1d = mod_diff(Q1(ba), Q1(bb), 16);
    diff += (q1d <= 1) ? q1d : (q1d - 1) * 12;
    int q2d = mod_diff(Q2(ba), Q2(bb), 16);
    diff += (q2d <= 1) ? q2d : (q2d - 1) * 12;

    if (CK(ba) != CK(bb)) diff += 1;

    // body: 32 code bytes, stored reversed in the digest - order is irrelevant
    // for a symmetric sum so compare positionally.
    for (int i = 0; i < 32; ++i) diff += byte_diff(ba[3+i], bb[3+i]);
    return diff;
}

// ===========================================================================
//  ssdeep  (spamsum)
// ===========================================================================
namespace ss_detail {
static const char* B64 =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr int      SPAMSUM_LENGTH = 64;
constexpr uint32_t HASH_PRIME     = 0x01000193u;
constexpr uint32_t HASH_INIT      = 0x28021967u;
constexpr int      ROLLING_WINDOW = 7;
constexpr uint32_t MIN_BLOCKSIZE  = 3;

struct Roll {
    unsigned char window[ROLLING_WINDOW] = {0};
    uint32_t h1 = 0, h2 = 0, h3 = 0, n = 0;
    void push(unsigned char c) {
        h2 -= h1;
        h2 += ROLLING_WINDOW * (uint32_t)c;
        h1 += (uint32_t)c;
        h1 -= (uint32_t)window[n];
        window[n] = c;
        if (++n == ROLLING_WINDOW) n = 0;
        h3 = (h3 << 5) ^ c;
    }
    uint32_t sum() const { return h1 + h2 + h3; }
};
} // namespace ss_detail

inline std::string ssdeep(const uint8_t* data, size_t len) {
    using namespace ss_detail;
    uint32_t bs = MIN_BLOCKSIZE;
    while ((uint64_t)bs * SPAMSUM_LENGTH < len) bs *= 2;

    std::string s1, s2;
    for (;;) {
        s1.clear(); s2.clear();
        Roll roll;
        uint32_t h1 = HASH_INIT, h2 = HASH_INIT;
        uint32_t rs = 0;
        for (size_t i = 0; i < len; ++i) {
            unsigned char c = data[i];
            h1 = (h1 * HASH_PRIME) ^ c;
            h2 = (h2 * HASH_PRIME) ^ c;
            roll.push(c);
            rs = roll.sum();
            if (rs % bs == bs - 1) {
                if (s1.size() < (size_t)SPAMSUM_LENGTH - 1) {
                    s1 += B64[h1 % 64];
                    h1 = HASH_INIT;
                }
            }
            if (rs % (bs * 2) == bs * 2 - 1) {
                if (s2.size() < (size_t)SPAMSUM_LENGTH / 2 - 1) {
                    s2 += B64[h2 % 64];
                    h2 = HASH_INIT;
                }
            }
        }
        if (rs != 0) {
            s1 += B64[h1 % 64];
            s2 += B64[h2 % 64];
        }
        if (bs > MIN_BLOCKSIZE && s1.size() < (size_t)SPAMSUM_LENGTH / 2) {
            bs /= 2;
            continue;
        }
        break;
    }
    return std::to_string(bs) + ":" + s1 + ":" + s2;
}

inline std::string ssdeep(const std::vector<uint8_t>& d) { return ssdeep(d.data(), d.size()); }

} // namespace fuzzy
} // namespace horus
