## Horus v3.0.0

Same engine, three ways to run it, and a GUI that finally does the analysis justice.

### The glass console (GUI)

- A self-contained **glassmorphism** report — frosted cards, a glowing risk ring, an
  animated **threat graph** wiring the sample to its capabilities, ATT&CK techniques
  and embedded IOCs, plus a **MITRE ATT&CK heatmap** that lights up what it found.
- Everything is inline HTML/CSS/JS — no CDN, no WebView runtime, nothing leaves the
  box. It renders in the browser the machine already trusts.
- Three ways in: `horus-gui.exe` (drag a file on it), `horus --gui`, or
  `horus --html report.html` to export a shareable report.

### Three binaries from one core

- `horus-cli.exe` — the pure command line, zero third-party dependencies.
- `horus-gui.exe` — the GUI build.
- `horus.exe` — both; CLI by default, `--gui` opens the glass console.
- Internally the analysis engine was split out of `main` into a shared core, so the
  CLI, the GUI and the JSON all read from the exact same report — they can't drift.

### New workflows

- **`--scan <dir>`** — walk a folder, score everything, worst-first table, with
  `--csv` / `--json-out` exports.
- **`--diff a.exe b.exe`** — imphash, rich-hash, section-entropy drift and TLSH
  distance side by side.
- **`--clip`** — read the indicator straight off the clipboard.
- **`~/.horus.json`** — keep API keys and a `cache_ttl_hours` in a dotfile; repeat
  intel lookups are served from a local cache instead of burning quota.

### Fewer false positives

- Real version resource + application manifest on every binary, no packing, clean
  imports. See `docs/false-positive-report.md` for the vendor whitelist notes.

The `--json` contract from v2.1 is unchanged, so existing scripts keep working.

---

## Horus v2.1.0

### What's new in v2.1

**Similarity / fuzzy hashing**
- **TLSH** (Trend Micro Locality Sensitive Hash) and **ssdeep** digests, computed
  straight off the file bytes. Both are byte-for-byte compatible with the
  reference tools — verified against libtlsh and ssdeep on real Windows binaries.
- TLSH turns "score one file" into "recognise the family": identical files score
  0, a few edits stay a couple of units apart, unrelated files sit hundreds apart.
- **authentihash** (the PE hash the Authenticode signature covers) — lets you
  match signed-malware campaigns even when the payload bytes differ.
- **rich hash** — MD5 of the decoded MSVC Rich header, a compiler/linker build
  fingerprint useful for clustering and attribution.

**Real Authenticode verification (not just presence)**
- Runs the signature through `WinVerifyTrust` for both embedded and
  **catalog-signed** files, so OS binaries are correctly reported as signed.
- Extracts the signer's common name from the PKCS#7 (e.g. `Microsoft Windows`).
- A file that carries a certificate but no longer verifies is scored as a
  tamper/forgery signal instead of being trusted.

**MITRE ATT&CK mapping**
- Each significant capability (and the combos that fire) is tagged with its
  technique ID — Injection→T1055, Input Capture→T1056.001, Networking→T1071,
  Crypto+Net→T1486, Token→T1134, and so on — in both the report and the JSON.

**More of the PE parsed**
- Rich header decode (toolchain records), CodeView **PDB path** + GUID/age,
  **TLS callbacks**, export table, appended **overlay** (offset/size/entropy),
  and **.NET / CLR** image detection.

**Still zero third-party dependencies** — the new verification path links only
`wintrust` and `crypt32`, which ship with Windows.

### Quick start (v2.1)

```
horus suspicious.exe                 # hashes + TLSH/ssdeep + signature + ATT&CK
horus suspicious.exe --json          # same, machine-readable
```

---

## Horus v2.0.0

### Download

| File | Description |
|------|-------------|
| `horus.exe` | Pre-built Windows x64 binary — drop it anywhere and run. No installer, no dependencies. |

### What's new in v2

**UEBA behavioral profiling**
- Matches the PE's capability/import/string profile against a library of software archetypes:
  Installer, AutomationTool, SystemTool, Loader, Downloader, Dropper, RAT, Keylogger,
  Ransomware, Spyware, CryptoMiner, SecurityTool
- Each archetype produces a risk modifier (+/−) applied to the static base score, so a
  legitimate packed installer doesn't score the same as a packed RAT
- `--profile` flag shows the full signal breakdown used to pick the archetype

**False-positive fix: UPX scoring overhaul**
- v1 double-penalized UPX sections: each got +18 (RWX) + +16 (packer name) = +34 per section
- Two UPX sections alone added 68 points before any import was even checked
- v2: when a section has a known packer name AND is RWX, only one penalty applies
- UPX (open-source, widely used by clean software) now gets a lower weight than commercial
  obfuscators like Themida or VMProtect
- VirtualProtect is backed out of the score when UPX is present without process injection
  (it's the UPX unpack stub calling it, not malware)
- Result: AutoHotkey 2.x installer goes from 100/100 MALICIOUS → 26/100 LOW RISK

**Software hint detection**
- Scans embedded strings for known product/category keywords
- Reports detected type (automation tool, installer, security tool) alongside the UPX note

**Authenticode directory check**
- PE header now checked for the security directory — reports whether a signature is present
  (presence only, not validation — bring in WinVerifyTrust yourself if you need that)

**Improved capability scoring**
- ScreenCapture weight reduced from 12 → 6 (BitBlt is common in any GUI app)
- New combo: ScreenCapture + Networking → +10 (spyware pattern when combined)
- Small-import-table check split: <4 imports = +16, 4–7 imports = +8 (better graduation)

### What's carried over from v1

- PE32 / PE32+ static analysis with per-section Shannon entropy visual bars
- 110-API capability knowledge base (XOR-encoded so it doesn't trigger AV on the tool itself)
- Imphash calculation matching the Mandiant/pefile recipe
- Embedded IOC pivot: URLs and IPs extracted from strings, AbuseIPDB enrichment
- VirusTotal v3 integration (files, hashes, IPs, domains, URLs)
- AbuseIPDB v2 integration
- Parallel intel fan-out across all configured sources
- JSON output mode with scripting-friendly exit codes
- Zero external dependencies — BCrypt + WinHTTP ship with Windows

### Requirements

- Windows 7 x64 or later
- No runtime install needed

### Quick start

```
horus suspicious.exe
horus suspicious.exe --profile
horus AutoHotkey_2.0.26_setup.exe
horus 185.220.101.5
horus 44d88612fea8a8f36de82e1278abb02f
horus malware.exe --vt-key $env:VT_API_KEY --json
```

---

## Horus v1.0.0

- Initial release: PE static analysis + IOC enrichment
