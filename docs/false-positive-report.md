# Horus — false-positive notes for AV / EDR vendors

Horus is an **open-source (MIT) Windows security-triage tool**. It is read-only:
it hashes files, parses PE headers, and queries public reputation APIs. It never
injects, persists, drops, or executes anything. Source is public at
<https://github.com/mobinert/HORUS>.

Security tooling gets flagged as *hacktool / riskware* by heuristics because of
what it *reads*, not what it *does*. If your engine flags a Horus binary, it is a
false positive. This note is here to make a whitelist request quick.

## Why a scanner sometimes trips on it

- It carries a table of malware-related API names and behavioural keywords (its
  detection vocabulary). These are **XOR-encoded at rest** (see `signatures.hpp`,
  `ueba.hpp`, `core.hpp`) precisely so they don't sit in `.rdata` as plaintext and
  match string signatures — but generic ML models can still react.
- It imports `BCrypt` (hashing), `WinHTTP` (HTTPS), `WinVerifyTrust` /`crypt32`
  (signature checking). Normal, documented Windows APIs; no injection primitives.

## What we do on our side to keep it clean

- **No packing / no obfuscation** of the binary itself (packing raises detection).
- **No RWX sections, no runtime API resolution** of sensitive calls.
- A real **version resource + application manifest** on every binary (`horus.rc`,
  `horus.manifest`) so it doesn't look like an anonymous unsigned blob.
- Releases are built from the tagged source with MSVC `/O2` — reproducible.

## Submitting a false-positive / whitelist request

Have the SHA-256 ready (`horus-cli.exe <thefile>` prints it), then:

| Vendor | Submit at |
|---|---|
| Microsoft Defender | <https://www.microsoft.com/en-us/wdsi/filesubmission> |
| VirusTotal (contact the engine) | <https://www.virustotal.com/gui/contact-us/false-positive> |
| Others | most vendors have a "report a false positive" form on their site |

## Verifying a build yourself

```bat
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

If you maintain an engine and want a heads-up before releases, open an issue.
