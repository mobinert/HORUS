// ---------------------------------------------------------------------------
//  pe.hpp  -  static analysis of a Portable Executable, straight off disk
//
//  Most PE parsers you find casually cast the file buffer straight onto
//  IMAGE_NT_HEADERS. That's a trap: those structs are baked to the *compiler's*
//  bitness, so a 64-bit build chokes on 32-bit files and vice-versa, and a
//  malformed header walks you right off the end of the mapping. So this parser
//  reads every field by hand, little-endian, with a bounds check in front of
//  each access. It never trusts a size or an offset that came out of the file.
//
//  What it pulls out:
//    * headers      - bitness, machine, subsystem, characteristics, build time
//    * sections     - sizes, R/W/X flags, and Shannon entropy (packing tell)
//    * imports       - every DLL and the functions pulled from each
//    * imphash      - the canonical comma-joined string (MD5'd elsewhere)
//    * strings      - printable ASCII and UTF-16LE runs, for the IOC pivot
//
//  Deliberately portable C++17 so the guts can be unit-tested off-box against
//  real binaries before it ever sees a Windows toolchain.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace horus {
namespace pe {

// ---- the bits of winnt.h we actually care about, named for clarity ---------
namespace constants {
    constexpr uint16_t DOS_MAGIC      = 0x5A4D;       // "MZ"
    constexpr uint32_t NT_MAGIC       = 0x00004550;   // "PE\0\0"
    constexpr uint16_t OPT_MAGIC_PE32 = 0x010B;
    constexpr uint16_t OPT_MAGIC_PE64 = 0x020B;

    constexpr uint16_t FILE_DLL       = 0x2000;
    constexpr uint16_t FILE_EXE_IMAGE = 0x0002;

    constexpr uint32_t SCN_MEM_EXECUTE = 0x20000000;
    constexpr uint32_t SCN_MEM_READ    = 0x40000000;
    constexpr uint32_t SCN_MEM_WRITE   = 0x80000000;

    constexpr int DIR_IMPORT = 1;                     // DataDirectory[1]
}

struct Section {
    std::string name;
    uint32_t    virtual_size   = 0;
    uint32_t    virtual_addr   = 0;
    uint32_t    raw_size       = 0;
    uint32_t    raw_ptr        = 0;
    uint32_t    characteristics= 0;
    double      entropy        = 0.0;
    bool        readable       = false;
    bool        writable       = false;
    bool        executable     = false;

    // Writable *and* executable is a textbook self-modifying / unpacking tell.
    bool is_rwx() const { return writable && executable; }
};

struct Import {
    std::string              dll;
    std::vector<std::string> functions;   // by-name; ordinals shown as "ord<N>"
};

struct Info {
    bool        valid = false;
    std::string error;

    bool        is_64bit = false;
    uint16_t    machine = 0;
    std::string machine_name;
    uint16_t    characteristics = 0;
    bool        is_dll = false;
    uint16_t    subsystem = 0;
    std::string subsystem_name;

    uint32_t    timestamp = 0;
    std::string compile_time;             // human readable UTC, or a note
    bool        timestamp_suspicious = false;

    uint64_t    image_base = 0;
    uint32_t    entry_point_rva = 0;
    size_t      file_size = 0;

    std::vector<Section> sections;
    std::vector<Import>  imports;

    std::string imphash_string;           // canonical pre-hash string
    double      overall_entropy = 0.0;
    size_t      total_imports = 0;

    uint32_t    rsrc_rva  = 0;            // resource section RVA (0 if absent)
    uint32_t    rsrc_size = 0;
    bool        has_authenticode = false; // DataDirectory[4] size > 0

    // ---- Rich header (MSVC build fingerprint, sits before the PE header) ----
    struct RichEntry { uint16_t prod_id = 0; uint16_t build_id = 0; uint32_t count = 0; };
    bool                    has_rich = false;
    uint32_t                rich_xor_key = 0;
    std::vector<RichEntry>  rich_entries;
    std::vector<uint8_t>    rich_clear;       // decoded bytes, hashed elsewhere

    // ---- debug directory (dir 6) -> CodeView PDB path + GUID/age ----
    bool        has_debug = false;
    std::string pdb_path;
    std::string codeview_guid;
    uint32_t    codeview_age = 0;

    // ---- TLS callbacks (dir 9) ----
    bool        has_tls = false;
    size_t      tls_callback_count = 0;

    // ---- exports (dir 0) ----
    bool                     has_exports = false;
    std::string              export_dll_name;
    size_t                   export_count = 0;
    std::vector<std::string> export_names;      // capped sample

    // ---- overlay (appended data past the last mapped section) ----
    uint64_t    overlay_offset = 0;
    uint64_t    overlay_size   = 0;
    double      overlay_entropy = 0.0;

    // ---- managed / .NET (dir 14, COM descriptor) ----
    bool        is_dotnet = false;

    // ---- byte ranges the Authenticode hash must skip (file offsets) ----
    size_t      ah_checksum_off = 0;    // OptionalHeader.CheckSum, 4 bytes
    size_t      ah_secdir_off   = 0;    // DataDirectory[4] entry, 8 bytes
    size_t      ah_cert_off     = 0;    // attribute certificate table (0 = none)
    size_t      ah_cert_size    = 0;
    bool        ah_ready        = false;
};

// ---------------------------------------------------------------------------
//  Shannon entropy over a byte range, 0.0 (uniform) .. 8.0 (max disorder).
//  Compressed or encrypted blobs sit up near 8; normal code is ~4.5-6.5.
// ---------------------------------------------------------------------------
inline double shannon_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    size_t freq[256] = {0};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    double H = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / (double)len;
        H -= p * std::log2(p);
    }
    return H;
}

class Analyzer {
public:
    explicit Analyzer(std::vector<uint8_t> bytes) : buf_(std::move(bytes)) {}

    Info analyze() {
        Info info;
        info.file_size = buf_.size();

        uint16_t dosmag;
        if (!rd16(0, dosmag) || dosmag != constants::DOS_MAGIC)
            return err(info, "not a PE file (missing MZ signature)");

        uint32_t e_lfanew;
        if (!rd32(0x3C, e_lfanew))
            return err(info, "truncated DOS header");

        uint32_t ntsig;
        if (!rd32(e_lfanew, ntsig) || ntsig != constants::NT_MAGIC)
            return err(info, "not a PE file (missing PE signature)");

        const size_t fh = e_lfanew + 4;            // IMAGE_FILE_HEADER
        uint16_t num_sections, opt_size;
        if (!rd16(fh + 2, num_sections) ||
            !rd32(fh + 4, info.timestamp) ||
            !rd16(fh + 16, opt_size)     ||
            !rd16(fh + 0, info.machine)  ||
            !rd16(fh + 18, info.characteristics))
            return err(info, "truncated file header");

        info.machine_name = machine_name(info.machine);
        info.is_dll = (info.characteristics & constants::FILE_DLL) != 0;
        decode_timestamp(info);

        const size_t opt = fh + 20;                // IMAGE_OPTIONAL_HEADER
        uint16_t optmagic;
        if (!rd16(opt, optmagic))
            return err(info, "truncated optional header");

        size_t dir_base;                           // file offset of DataDirectory[0]
        if (optmagic == constants::OPT_MAGIC_PE64) {
            info.is_64bit = true;
            uint32_t ib_lo, ib_hi;
            rd32(opt + 0x18, ib_lo); rd32(opt + 0x1C, ib_hi);
            info.image_base = ((uint64_t)ib_hi << 32) | ib_lo;
            rd32(opt + 0x10, info.entry_point_rva);
            dir_base = opt + 112;                  // PE32+ DataDirectory
        } else if (optmagic == constants::OPT_MAGIC_PE32) {
            info.is_64bit = false;
            uint32_t ib; rd32(opt + 0x1C, ib);
            info.image_base = ib;
            rd32(opt + 0x10, info.entry_point_rva);
            dir_base = opt + 96;                   // PE32 DataDirectory
        } else {
            return err(info, "unknown optional header magic");
        }

        uint16_t subsys; rd16(opt + 68, subsys);
        info.subsystem = subsys;
        info.subsystem_name = subsystem_name(subsys);

        // ---- section table ----
        const size_t sec_table = opt + opt_size;
        if (!parse_sections(info, sec_table, num_sections))
            return err(info, "section table runs past end of file");

        info.overall_entropy = shannon_entropy(buf_.data(), buf_.size());

        // ---- imports (DataDirectory[1]) ----
        uint32_t imp_rva = 0, imp_sz = 0;
        rd32(dir_base + 8 * constants::DIR_IMPORT,     imp_rva);
        rd32(dir_base + 8 * constants::DIR_IMPORT + 4, imp_sz);
        if (imp_rva != 0)
            parse_imports(info, imp_rva);          // best-effort; never fatal

        build_imphash_string(info);

        // ---- resource directory (DataDirectory[2]) ----
        rd32(dir_base + 8 * 2,     info.rsrc_rva);
        rd32(dir_base + 8 * 2 + 4, info.rsrc_size);

        // ---- Authenticode (DataDirectory[4]) - just presence, not validation ----
        uint32_t auth_sz = 0;
        rd32(dir_base + 8 * 4 + 4, auth_sz);
        info.has_authenticode = (auth_sz > 0);

        // how many data directories the file actually declares
        uint32_t num_rva = 0;
        rd32(dir_base - 4, num_rva);

        // ---- byte ranges the Authenticode digest skips ----
        info.ah_checksum_off = opt + 64;
        info.ah_secdir_off   = dir_base + 8 * 4;
        {
            uint32_t cva = 0, csz = 0;
            rd32(dir_base + 8 * 4,     cva);   // security dir VA == raw file offset
            rd32(dir_base + 8 * 4 + 4, csz);
            info.ah_cert_off  = cva;
            info.ah_cert_size = csz;
        }
        info.ah_ready = true;

        // ---- managed / .NET (dir 14) ----
        if (num_rva > 14) {
            uint32_t clr_rva = 0;
            rd32(dir_base + 8 * 14, clr_rva);
            info.is_dotnet = (clr_rva != 0);
        }

        parse_rich(info, e_lfanew);
        if (num_rva > 6) parse_debug(info, dir_base);
        if (num_rva > 9) parse_tls(info, dir_base);
        if (num_rva > 0) parse_exports(info, dir_base);
        compute_overlay(info);

        info.valid = true;
        return info;
    }

    // String extraction is its own pass over the raw bytes - handy both for the
    // report and for feeding embedded URLs/IPs back into the intel lookups.
    std::vector<std::string> extract_strings(size_t min_len = 4) const {
        std::vector<std::string> out;

        // printable ASCII runs
        std::string cur;
        for (uint8_t b : buf_) {
            if (b >= 0x20 && b <= 0x7E) {
                cur += (char)b;
            } else {
                if (cur.size() >= min_len) out.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= min_len) out.push_back(cur);

        // UTF-16LE runs (ascii char followed by a 0x00) - common in PE resources
        cur.clear();
        for (size_t i = 0; i + 1 < buf_.size(); i += 2) {
            uint8_t lo = buf_[i], hi = buf_[i + 1];
            if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E) {
                cur += (char)lo;
            } else {
                if (cur.size() >= min_len) out.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= min_len) out.push_back(cur);

        return out;
    }

    const std::vector<uint8_t>& bytes() const { return buf_; }

private:
    std::vector<uint8_t> buf_;

    // ---- bounds-checked little-endian readers ----
    bool rd16(size_t off, uint16_t& out) const {
        if (off + 2 > buf_.size()) return false;
        out = (uint16_t)(buf_[off] | (buf_[off + 1] << 8));
        return true;
    }
    bool rd32(size_t off, uint32_t& out) const {
        if (off + 4 > buf_.size()) return false;
        out = (uint32_t)buf_[off] | ((uint32_t)buf_[off + 1] << 8) |
              ((uint32_t)buf_[off + 2] << 16) | ((uint32_t)buf_[off + 3] << 24);
        return true;
    }
    bool rd64(size_t off, uint64_t& out) const {
        uint32_t lo, hi;
        if (!rd32(off, lo) || !rd32(off + 4, hi)) return false;
        out = ((uint64_t)hi << 32) | lo;
        return true;
    }

    static Info& err(Info& i, const std::string& msg) { i.valid = false; i.error = msg; return i; }

    // Map a relative virtual address to a raw file offset using the section
    // table. RVAs inside the header region map 1:1.
    bool rva_to_offset(const Info& info, uint32_t rva, size_t& off) const {
        for (const auto& s : info.sections) {
            uint32_t span = std::max(s.virtual_size, s.raw_size);
            if (rva >= s.virtual_addr && rva < s.virtual_addr + span) {
                off = s.raw_ptr + (rva - s.virtual_addr);
                return off < buf_.size();
            }
        }
        if (rva < buf_.size()) { off = rva; return true; }   // header-resident
        return false;
    }

    std::string read_cstr(size_t off, size_t cap = 512) const {
        std::string s;
        while (off < buf_.size() && s.size() < cap) {
            char c = (char)buf_[off++];
            if (c == '\0') break;
            s += c;
        }
        return s;
    }

    bool parse_sections(Info& info, size_t table, uint16_t count) {
        for (uint16_t i = 0; i < count; ++i) {
            size_t base = table + (size_t)i * 40;
            if (base + 40 > buf_.size()) return false;

            Section s;
            char raw_name[9] = {0};
            for (int k = 0; k < 8; ++k) raw_name[k] = (char)buf_[base + k];
            s.name = raw_name;                       // trims at first NUL

            rd32(base + 8,  s.virtual_size);
            rd32(base + 12, s.virtual_addr);
            rd32(base + 16, s.raw_size);
            rd32(base + 20, s.raw_ptr);
            rd32(base + 36, s.characteristics);

            s.executable = (s.characteristics & constants::SCN_MEM_EXECUTE) != 0;
            s.readable   = (s.characteristics & constants::SCN_MEM_READ)    != 0;
            s.writable   = (s.characteristics & constants::SCN_MEM_WRITE)   != 0;

            // Entropy over whatever raw bytes the section actually occupies,
            // clamped to the file so a lying SizeOfRawData can't run us off.
            if (s.raw_ptr < buf_.size() && s.raw_size > 0) {
                size_t avail = std::min<size_t>(s.raw_size, buf_.size() - s.raw_ptr);
                s.entropy = shannon_entropy(buf_.data() + s.raw_ptr, avail);
            }
            info.sections.push_back(std::move(s));
        }
        return true;
    }

    void parse_imports(Info& info, uint32_t import_rva) {
        size_t desc_off;
        if (!rva_to_offset(info, import_rva, desc_off)) return;

        for (int idx = 0; idx < 4096; ++idx) {        // sane upper bound
            size_t base = desc_off + (size_t)idx * 20;
            uint32_t oft, name_rva, first;
            if (!rd32(base + 0,  oft)  ||
                !rd32(base + 12, name_rva) ||
                !rd32(base + 16, first))
                break;
            if (oft == 0 && name_rva == 0 && first == 0) break;   // null terminator

            Import imp;
            size_t name_off;
            if (rva_to_offset(info, name_rva, name_off))
                imp.dll = read_cstr(name_off, 256);

            // Prefer the Import Lookup Table (OriginalFirstThunk); fall back to
            // the IAT (FirstThunk) when the ILT was stripped.
            uint32_t thunk_rva = oft ? oft : first;
            if (thunk_rva)
                read_thunks(info, thunk_rva, imp);

            info.total_imports += imp.functions.size();
            info.imports.push_back(std::move(imp));
        }
    }

    void read_thunks(const Info& info, uint32_t thunk_rva, Import& imp) {
        size_t toff;
        if (!rva_to_offset(info, thunk_rva, toff)) return;

        const bool is64 = info.is_64bit;
        const uint64_t ord_flag = is64 ? 0x8000000000000000ULL : 0x80000000ULL;
        const size_t   step     = is64 ? 8 : 4;

        for (int i = 0; i < 8192; ++i) {               // sane upper bound
            size_t entry = toff + (size_t)i * step;
            uint64_t val;
            if (is64) { if (!rd64(entry, val)) break; }
            else      { uint32_t v; if (!rd32(entry, v)) break; val = v; }
            if (val == 0) break;                        // end of this DLL's thunks

            if (val & ord_flag) {
                uint16_t ordinal = (uint16_t)(val & 0xFFFF);
                imp.functions.push_back("ord" + std::to_string(ordinal));
            } else {
                uint32_t hint_name_rva = (uint32_t)(val & 0x7FFFFFFF);
                size_t hn_off;
                if (rva_to_offset(info, hint_name_rva, hn_off)) {
                    // IMAGE_IMPORT_BY_NAME: WORD hint, then the ASCII name
                    imp.functions.push_back(read_cstr(hn_off + 2, 256));
                }
            }
        }
    }

    // ---- Rich header: MSVC stamps a XOR-obfuscated build fingerprint between
    //      the DOS stub and the PE header. Decode it - the (compiler,count)
    //      pairs are a strong attribution / clustering signal. ----
    void parse_rich(Info& info, uint32_t e_lfanew) {
        if (e_lfanew < 0x80 || e_lfanew > buf_.size()) return;

        size_t rich_off = 0;
        for (size_t i = 0x80; i + 8 <= e_lfanew; i += 4) {
            if (buf_[i]=='R' && buf_[i+1]=='i' && buf_[i+2]=='c' && buf_[i+3]=='h') {
                rich_off = i; break;
            }
        }
        if (!rich_off) return;

        uint32_t key = 0;
        if (!rd32(rich_off + 4, key)) return;

        const uint32_t DANS = 0x536E6144;   // 'DanS'
        size_t dans_off = 0;
        for (size_t p = rich_off; p >= 0x84; ) {
            p -= 4;
            uint32_t v = 0;
            if (!rd32(p, v)) break;
            if ((v ^ key) == DANS) { dans_off = p; break; }
        }
        if (!dans_off) return;

        info.has_rich     = true;
        info.rich_xor_key = key;

        // decoded [DanS .. Rich) bytes feed the rich hash
        for (size_t p = dans_off; p + 4 <= rich_off; p += 4) {
            uint32_t v = 0; rd32(p, v);
            uint32_t d = v ^ key;
            info.rich_clear.push_back((uint8_t)(d));
            info.rich_clear.push_back((uint8_t)(d >> 8));
            info.rich_clear.push_back((uint8_t)(d >> 16));
            info.rich_clear.push_back((uint8_t)(d >> 24));
        }
        // (comp_id, count) pairs follow DanS + 3 padding dwords
        for (size_t p = dans_off + 16; p + 8 <= rich_off; p += 8) {
            uint32_t comp = 0, cnt = 0;
            rd32(p, comp);     comp ^= key;
            rd32(p + 4, cnt);  cnt  ^= key;
            Info::RichEntry e;
            e.prod_id  = (uint16_t)(comp >> 16);
            e.build_id = (uint16_t)(comp & 0xFFFF);
            e.count    = cnt;
            info.rich_entries.push_back(e);
        }
    }

    // ---- debug directory -> CodeView (RSDS) PDB path, GUID and age ----
    void parse_debug(Info& info, size_t dir_base) {
        uint32_t rva = 0, sz = 0;
        rd32(dir_base + 8 * 6,     rva);
        rd32(dir_base + 8 * 6 + 4, sz);
        if (!rva || !sz) return;
        size_t off;
        if (!rva_to_offset(info, rva, off)) return;
        info.has_debug = true;

        uint32_t count = sz / 28;
        for (uint32_t i = 0; i < count && i < 64; ++i) {
            size_t base = off + (size_t)i * 28;
            uint32_t type = 0, praw = 0;
            if (!rd32(base + 12, type) || !rd32(base + 24, praw)) break;
            if (type != 2) continue;               // IMAGE_DEBUG_TYPE_CODEVIEW
            uint32_t sig = 0;
            if (!rd32(praw, sig) || sig != 0x53445352) continue;   // 'RSDS'
            if (praw + 24 > buf_.size()) continue;
            uint32_t d1 = 0; uint16_t d2 = 0, d3 = 0;
            rd32(praw + 4, d1); rd16(praw + 8, d2); rd16(praw + 10, d3);
            char g[64];
            std::snprintf(g, sizeof(g),
                "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                d1, d2, d3,
                buf_[praw+12], buf_[praw+13], buf_[praw+14], buf_[praw+15],
                buf_[praw+16], buf_[praw+17], buf_[praw+18], buf_[praw+19]);
            info.codeview_guid = g;
            rd32(praw + 20, info.codeview_age);
            info.pdb_path = read_cstr(praw + 24, 260);
            return;
        }
    }

    // ---- TLS callback table (executes before the entry point) ----
    void parse_tls(Info& info, size_t dir_base) {
        uint32_t rva = 0;
        rd32(dir_base + 8 * 9, rva);
        if (!rva) return;
        size_t off;
        if (!rva_to_offset(info, rva, off)) return;
        info.has_tls = true;

        uint64_t cb_va = 0;
        if (info.is_64bit) { if (!rd64(off + 24, cb_va)) return; }
        else               { uint32_t v; if (!rd32(off + 12, v)) return; cb_va = v; }
        if (cb_va == 0 || cb_va < info.image_base) return;

        uint32_t cb_rva = (uint32_t)(cb_va - info.image_base);
        size_t cb_off;
        if (!rva_to_offset(info, cb_rva, cb_off)) return;
        for (int i = 0; i < 512; ++i) {
            uint64_t ptr = 0;
            if (info.is_64bit) { if (!rd64(cb_off + (size_t)i*8, ptr)) break; }
            else               { uint32_t v; if (!rd32(cb_off + (size_t)i*4, v)) break; ptr = v; }
            if (ptr == 0) break;
            ++info.tls_callback_count;
        }
    }

    // ---- export table (a DLL's own name + exported symbols) ----
    void parse_exports(Info& info, size_t dir_base) {
        uint32_t rva = 0;
        rd32(dir_base + 0, rva);
        if (!rva) return;
        size_t off;
        if (!rva_to_offset(info, rva, off)) return;
        info.has_exports = true;

        uint32_t name_rva = 0, num_funcs = 0, num_names = 0, names_rva = 0;
        rd32(off + 12, name_rva);
        rd32(off + 20, num_funcs);
        rd32(off + 24, num_names);
        rd32(off + 32, names_rva);
        info.export_count = num_funcs;

        size_t noff;
        if (name_rva && rva_to_offset(info, name_rva, noff))
            info.export_dll_name = read_cstr(noff, 256);

        size_t names_off;
        if (names_rva && rva_to_offset(info, names_rva, names_off)) {
            for (uint32_t i = 0; i < num_names && i < 4096 && info.export_names.size() < 32; ++i) {
                uint32_t nrva = 0;
                if (!rd32(names_off + (size_t)i*4, nrva)) break;
                size_t o;
                if (rva_to_offset(info, nrva, o)) info.export_names.push_back(read_cstr(o, 256));
            }
        }
    }

    // ---- overlay: bytes appended after the last mapped section ----
    void compute_overlay(Info& info) {
        uint64_t end = 0;
        for (const auto& s : info.sections) {
            if (s.raw_size == 0) continue;
            uint64_t e = (uint64_t)s.raw_ptr + s.raw_size;
            if (e > end) end = e;
        }
        uint64_t limit = buf_.size();
        // the attribute certificate table lives past the sections too - don't
        // count the signature blob as overlay.
        if (info.ah_cert_off > 0 && info.ah_cert_size > 0 &&
            info.ah_cert_off >= end && info.ah_cert_off <= buf_.size())
            limit = info.ah_cert_off;
        if (end < limit) {
            info.overlay_offset = end;
            info.overlay_size   = limit - end;
            size_t n = (size_t)info.overlay_size;
            if (info.overlay_offset + n <= buf_.size())
                info.overlay_entropy = shannon_entropy(buf_.data() + (size_t)info.overlay_offset, n);
        }
    }

    // Mandiant/pefile imphash recipe: lowercase "dll.func" pairs (DLL extension
    // stripped for dll/ocx/sys), joined with commas, in import order. We build
    // the string here; the MD5 is taken by the crypto layer so there's a single
    // hashing implementation in the whole program.
    void build_imphash_string(Info& info) {
        std::ostringstream os;
        bool first = true;
        for (const auto& imp : info.imports) {
            std::string lib = lower(imp.dll);
            auto dot = lib.rfind('.');
            if (dot != std::string::npos) {
                std::string ext = lib.substr(dot + 1);
                if (ext == "dll" || ext == "ocx" || ext == "sys")
                    lib = lib.substr(0, dot);
            }
            for (const auto& fn : imp.functions) {
                if (!first) os << ',';
                os << lib << '.' << lower(fn);
                first = false;
            }
        }
        info.imphash_string = os.str();
    }

    static std::string lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c){ return (char)std::tolower(c); });
        return s;
    }

    void decode_timestamp(Info& info) {
        if (info.timestamp == 0) {
            info.compile_time = "not set (zeroed)";
            info.timestamp_suspicious = true;
            return;
        }
        std::time_t t = (std::time_t)info.timestamp;
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char b[64];
        std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S UTC", &tm);
        info.compile_time = b;

        // Compilers doing reproducible builds stuff a content hash in here, so
        // an absurd year is a hint the field is meaningless rather than a date.
        int year = tm.tm_year + 1900;
        if (year < 1995 || year > 2035) info.timestamp_suspicious = true;
    }

    static std::string machine_name(uint16_t m) {
        switch (m) {
            case 0x014c: return "x86 (i386)";
            case 0x8664: return "x64 (AMD64)";
            case 0x01c0: return "ARM";
            case 0x01c4: return "ARMv7 (Thumb-2)";
            case 0xaa64: return "ARM64";
            case 0x0200: return "Itanium";
            default:     return "unknown";
        }
    }

    static std::string subsystem_name(uint16_t s) {
        switch (s) {
            case 1:  return "Native";
            case 2:  return "Windows GUI";
            case 3:  return "Windows Console";
            case 5:  return "OS/2 Console";
            case 7:  return "POSIX Console";
            case 9:  return "Windows CE GUI";
            case 10: return "EFI Application";
            case 14: return "Xbox";
            default: return "unknown";
        }
    }
};

} // namespace pe
} // namespace horus
