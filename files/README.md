<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0f0f,50:1a1a2e,100:16213e&height=200&section=header&text=ARGUS&fontSize=90&fontColor=00ff88&fontAlignY=38&desc=IOC%20Enrichment%20%E2%80%A2%20PE%20Static%20Analysis%20%E2%80%A2%20Threat%20Intel&descAlignY=62&descSize=18&descColor=8892b0&animation=fadeIn" width="100%"/>

<br/>

[![Platform](https://img.shields.io/badge/platform-Windows-0078D7?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/mobinert/ARGUS/releases)
[![Language](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=cplusplus&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=for-the-badge)](https://github.com/mobinert/ARGUS)
[![Release](https://img.shields.io/github/v/release/mobinert/ARGUS?style=for-the-badge&color=ff6b6b)](https://github.com/mobinert/ARGUS/releases/latest)

<br/>

> **Hand it an indicator or a file — it figures out the rest.**

</div>

---

## What is ARGUS?

ARGUS is a **self-contained Windows CLI** for malware triage. Drop it on any Windows machine, point it at a suspicious file or an indicator (hash / IP / domain / URL / email) and it gives you a threat verdict in seconds — no Python, no dependencies, no installers.

```
argus suspicious.exe
argus 185.220.101.5
argus 44d88612fea8a8f36de82e1278abb02f
argus https://sketchy.example/drop.bin --json
```

---

## Live Demo

<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║  ▄▄▄       ██▀███    ▄████  █    ██   ██████                    ║
║ ▒████▄    ▓██ ▒ ██▒ ██▒ ▀█▒ ██  ▓██▒▒██    ▒                   ║
║ ▒██  ▀█▄  ▓██ ░▄█ ▒▒██░▄▄▄░▓██  ▒██░░ ▓██▄                     ║
║ ░██▄▄▄▄██ ▒██▀▀█▄  ░▓█  ██▓▓▓█  ░██░  ▒   ██▒                  ║
║  ▓█   ▓██▒░██▓ ▒██▒░▒▓███▀▒▒▒█████▓ ▒██████▒▒                  ║
║  ▒▒   ▓▒█░░ ▒▓ ░▒▓░ ░▒   ▒ ░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░                  ║
║   ▒   ▒▒ ░  ░▒ ░ ▒░  ░   ░ ░░▒░ ░ ░ ░ ░▒  ░ ░                  ║
║   ░   ▒     ░░   ░ ░ ░   ░  ░░░ ░ ░ ░  ░  ░                    ║
║       ░  ░   ░           ░    ░           ░                     ║
╚══════════════════════════════════════════════════════════════════╝

$ argus malware_sample.exe --vt-key $VT_KEY

── FILE ─────────────────────────────────────────────────────────
  path      malware_sample.exe
  size      102,400 bytes
  MD5       a3f5d1e2c7b849d60e14a2b8f93c5d17
  SHA-1     4b2e8a91c3d056f7e820b4a19c6d3f7e2b085c40
  SHA-256   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

── PE HEADER ────────────────────────────────────────────────────
  type      executable
  bitness   64-bit (PE32+)
  machine   x64 (AMD64)
  subsystem Windows Console
  compiled  2024-03-15 08:22:41 UTC  ⚑ (suspicious)
  imphash   9a4f2c8d1e7b3056a82c914d6e0f5b17

── SECTIONS ─────────────────────────────────────────────────────
  .text     r-x  H=6.21 [##########........]
  .rdata    r--  H=4.87 [########..........]
  .data     rw-  H=4.12 [#######...........]
  .UPX0     rwx  H=7.94 [##################] RWX!   ← packed

── CAPABILITIES ─────────────────────────────────────────────────
  [Process Injection]       writes into and runs code in another process
      VirtualAllocEx  WriteProcessMemory  CreateRemoteThread
  [API Hiding]              resolves API addresses at runtime
      GetProcAddress  LoadLibraryA
  [Persistence]             writes autostart keys to survive reboot
      RegSetValueExA  RegCreateKeyExA
  [Network Activity]        opens sockets or fetches remote content
      WinHttpOpen  WinHttpConnect  WinHttpSendRequest

  ! Injection primitives paired with runtime API resolution   [+15]
  ! High-entropy section '.UPX0' (H=7.94) — likely packed    [+12]
  ! Section '.UPX0' is writable AND executable (RWX)          [+18]
  ! Known packer section name '.UPX0'                         [+16]

── EMBEDDED INDICATORS ──────────────────────────────────────────
  url    http://185.220.101.5:8080/gate.php
  ip     185.220.101.5
  tokens  cmd.exe  powershell  schtasks

── VIRUSTOTAL ───────────────────────────────────────────────────
  VirusTotal  48/72 engines flagged this as malicious
      category: trojan
      name:     Trojan.GenericKD.71234567

── VERDICT ──────────────────────────────────────────────────────
  ╔═══════════════════════╗
  ║  LIKELY MALICIOUS 🔴  ║   risk 94 / 100
  ╚═══════════════════════╝
  static analysis: LIKELY MALICIOUS (76)
  virustotal: 48/72 engines
```

</div>

---

## Features

<table>
<tr>
<td width="50%">

### File Analysis
- Computes **MD5 / SHA-1 / SHA-256** via Windows CNG
- Full **PE32 / PE32+** parser — works on both 32-bit and 64-bit binaries
- Per-section **Shannon entropy** with visual bars (packed sections glow)
- Complete **import table** → ~110 APIs mapped to capabilities
- **Imphash** for malware family clustering
- Embedded **URL / IP pivot** — finds hidden IOCs in strings and enriches them
- Optional **VirusTotal** file reputation by SHA-256

</td>
<td width="50%">

### IOC Enrichment
- **Auto-classifies** any indicator — no type flag needed
- Supported types: MD5 · SHA-1 · SHA-256 · IPv4 · domain · URL · email
- **Parallel** fan-out across all configured sources
- **VirusTotal v3** — files, hashes, IPs, domains, URLs
- **AbuseIPDB v2** — IP confidence scores
- **Extensible** — adding URLhaus, OTX, or GreyNoise is one subclass

</td>
</tr>
</table>

### Risk Scoring — the interesting part

ARGUS doesn't just list what a binary imports. It scores the *combinations* that matter:

| What it detects | Score impact |
|---|---|
| Injection primitives (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) | +22 |
| **Injection + runtime API resolution** together | +37 total (+15 combo bonus) |
| **Keylogger** (`SetWindowsHookEx`, `GetAsyncKeyState`) **+ network I/O** | +43 total (+15 combo bonus) |
| **Crypto + network I/O** (exfil / ransomware pattern) | +20 total (+12 combo bonus) |
| RWX section (writable + executable) | +18 |
| High-entropy section ≥ 7.2 bits | +12 per section |
| Known packer section name (UPX, Themida, VMProtect…) | +16 |
| Common dual-use APIs (`LoadLibrary`, `CreateProcess`) **alone** | ±0 |

Common APIs are shown but don't move the score unless paired with rare primitives. That keeps ordinary binaries reading **CLEAN** instead of crying wolf.

---

## Installation

### Option 1 — Download the pre-built binary (fastest)

Grab `argus.exe` from the [**latest release**](https://github.com/mobinert/ARGUS/releases/latest) and drop it anywhere on your PATH. No installer, no dependencies.

### Option 2 — Build from source

**Requirements:** Windows, Visual Studio 2019 or later (the free Community edition works fine)

**MSVC Developer Command Prompt:**
```bat
cl /EHsc /std:c++17 /O2 /DNOMINMAX /D_WIN32_WINNT=0x0601 ^
   src\main.cpp src\crypto.cpp src\http.cpp src\intel.cpp ^
   /I src /Fe:argus.exe bcrypt.lib winhttp.lib
```

**CMake (generates a Visual Studio solution or Ninja build):**
```bat
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

Result: a single self-contained `argus.exe`.

---

## API Keys

Live lookups need free API keys. Without them, ARGUS still does all static PE analysis and hashing — it just skips that source.

| Source | Free key | How ARGUS reads it |
|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Sign in → API key | `VT_API_KEY` env or `--vt-key` |
| [AbuseIPDB](https://www.abuseipdb.com) | Account → API | `ABUSEIPDB_API_KEY` env or `--abuse-key` |

```powershell
$env:VT_API_KEY        = "your_virustotal_key_here"
$env:ABUSEIPDB_API_KEY = "your_abuseipdb_key_here"
```

---

## Usage

```
argus <indicator-or-file> [options]

  <indicator-or-file>   hash / IP / domain / URL / email  -or-  a path to a file

options:
  --vt-key    <key>     VirusTotal API key   (or env VT_API_KEY)
  --abuse-key <key>     AbuseIPDB API key    (or env ABUSEIPDB_API_KEY)
  --strings             dump extracted strings when analysing a file
  --json                machine-readable output (pipeable)
  --no-color            disable ANSI colour
  -h, --help            show this help
```

### Examples

```bat
:: Full analysis of a suspicious binary, including VT reputation
argus malware.exe

:: Look up a file hash across all configured intel sources
argus 44d88612fea8a8f36de82e1278abb02f

:: IP reputation from VirusTotal + AbuseIPDB simultaneously
argus 185.220.101.5

:: Domain lookup
argus evil-c2-domain.ru

:: Machine-readable output for piping into SIEM/scripts
argus suspicious.dll --json | jq .verdict

:: Scan a binary and dump its string table too
argus dropper.exe --strings
```

---

## Architecture

Everything ships as one `.exe`. Zero external libraries. Zero runtime dependencies.

```
src/
  json.hpp          zero-dependency JSON parser (recursive descent)
  ioc.hpp           indicator type auto-detection (regex-free, hand-rolled)
  pe.hpp            PE32 / PE32+ parser with per-field bounds checking
  signatures.hpp    110-API knowledge base + capability scoring engine
  crypto.cpp/hpp    MD5 / SHA-1 / SHA-256 via Windows BCrypt/CNG
  http.cpp/hpp      HTTPS client via Windows WinHTTP
  intel.cpp/hpp     VirusTotal v3 + AbuseIPDB v2 (extensible IntelSource)
  console.hpp       ANSI colour / formatted terminal output
  main.cpp          CLI, orchestration, report rendering

tests/
  test_ioc.cpp      indicator classifier unit tests
  test_json.cpp     JSON parser unit tests
  test_pe.cpp       PE parser unit tests
  test_score.cpp    risk scoring unit tests
```

### Adding a new intel source

The `IntelSource` interface is three methods. Drop a new subclass in `intel.cpp` and wire it into `build_sources()` — nothing else changes:

```cpp
class URLhaus : public IntelSource {
public:
    explicit URLhaus(std::string api_key) : key_(std::move(api_key)) {}
    std::string name() const override { return "URLhaus"; }
    bool supports(IocType t) const override { return t == IocType::URL || t == IocType::Domain; }
    SourceResult lookup(const std::string& ioc, IocType t) const override {
        // one HTTP call, parse JSON, fill SourceResult
    }
private:
    std::string key_;
};
```

---

## Output Modes

**Human-readable (default)** — coloured, section-based, readable at a glance.

**JSON (`--json`)** — flat object, one line per field, pipeable:

```json
{
  "target": "sample.exe",
  "size": 102400,
  "md5": "a3f5d1e2c7b849d60e14a2b8f93c5d17",
  "sha1": "4b2e8a91c3d056f7e820b4a19c6d3f7e2b085c40",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "is_pe": true,
  "bitness": 64,
  "imphash": "9a4f2c8d1e7b3056a82c914d6e0f5b17",
  "static_score": 76,
  "vt_detections": 48,
  "final_score": 94,
  "verdict": "LIKELY MALICIOUS"
}
```

Exit code `0` = clean/unknown, `1` = suspicious or malicious (score ≥ 30), `2` = usage error. Scripting-friendly by design.

---

## Safety Note

ARGUS is a **read-only, defensive** analysis tool.

- It reads files and queries reputation APIs. It does not execute, modify, pack, or generate anything.
- The PE parser treats every offset and length from the file as hostile and bounds-checks before each read. Pointing it at a malformed or actively malicious sample is safe.
- The static risk score is a **triage aid**, not a production verdict. Pair with VirusTotal consensus and, for anything that matters, a sandbox detonation.

---

## License

MIT — see [LICENSE](LICENSE). Free for personal, commercial, and research use.

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:16213e,50:1a1a2e,100:0f0f0f&height=120&section=footer" width="100%"/>

**Built for defenders. Free forever.**

</div>
