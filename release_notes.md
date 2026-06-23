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
