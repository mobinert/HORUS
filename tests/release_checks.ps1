param(
    [Parameter(Mandatory=$true)][string]$BinDir,
    [Parameter(Mandatory=$true)][string]$ExpectedVersion
)

$ErrorActionPreference = 'Stop'
$expectedQuad = "$ExpectedVersion.0"
$binaries = @('horus.exe', 'horus-cli.exe', 'horus-gui.exe')

function Require($condition, $message) {
    if (-not $condition) { throw $message }
}

foreach ($name in $binaries) {
    $path = Join-Path $BinDir $name
    Require (Test-Path -LiteralPath $path -PathType Leaf) "missing binary: $name"

    $item = Get-Item -LiteralPath $path
    $version = $item.VersionInfo
    Require ($version.FileVersion -eq $expectedQuad) "$name has FileVersion $($version.FileVersion)"
    Require ($version.ProductVersion -eq $expectedQuad) "$name has ProductVersion $($version.ProductVersion)"
    Require ($version.OriginalFilename -eq $name) "$name has OriginalFilename $($version.OriginalFilename)"

    $bytes = [IO.File]::ReadAllBytes($path)
    Require ($bytes.Length -gt 256) "$name is too small to be a PE"
    Require ($bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a) "$name has no MZ header"
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    Require ($peOffset -gt 0 -and $peOffset + 6 -le $bytes.Length) "$name has an invalid PE offset"
    Require ([BitConverter]::ToUInt32($bytes, $peOffset) -eq 0x00004550) "$name has no PE signature"
    Require ([BitConverter]::ToUInt16($bytes, $peOffset + 4) -eq 0x8664) "$name is not x64"
    $optionalOffset = $peOffset + 24
    Require ($optionalOffset + 152 -le $bytes.Length) "$name has a truncated optional header"
    Require ([BitConverter]::ToUInt16($bytes, $optionalOffset) -eq 0x20b) "$name is not PE32+"
    Require ([BitConverter]::ToUInt32($bytes, $optionalOffset + 108) -ge 5) "$name has no security directory entry"
    $securityOffset = $optionalOffset + 144
    $certificateOffset = [BitConverter]::ToUInt32($bytes, $securityOffset)
    $certificateSize = [BitConverter]::ToUInt32($bytes, $securityOffset + 4)
    Require ($certificateOffset -eq 0 -and $certificateSize -eq 0) "$name unexpectedly contains an Authenticode certificate"
    $ascii = [Text.Encoding]::ASCII.GetString($bytes)
    Require (-not $ascii.Contains('MSVCP140.dll')) "$name depends on the Visual C++ redistributable"
    Require (-not $ascii.Contains('VCRUNTIME140.dll')) "$name depends on the Visual C++ redistributable"
    Require (-not $ascii.Contains('VCRUNTIME140_1.dll')) "$name depends on the Visual C++ redistributable"
}

$unifiedVersion = (& (Join-Path $BinDir 'horus.exe') --version) -join ''
Require ($LASTEXITCODE -eq 0 -and $unifiedVersion -eq $ExpectedVersion) 'horus.exe --version mismatch'
$cliVersion = (& (Join-Path $BinDir 'horus-cli.exe') --version) -join ''
Require ($LASTEXITCODE -eq 0 -and $cliVersion -eq $ExpectedVersion) 'horus-cli.exe --version mismatch'
