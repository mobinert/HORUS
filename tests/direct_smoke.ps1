param(
    [Parameter(Mandatory=$true)][string]$Horus,
    [Parameter(Mandatory=$true)][string]$HorusGui
)

$ErrorActionPreference = 'Stop'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $tempBase ("horus-direct-" + [guid]::NewGuid().ToString('N'))

function Require($condition, $message) {
    if (-not $condition) { throw $message }
}

try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $version = (& $Horus --version) -join ''
    Require ($version -eq '4.0.0') '--version did not report 4.0.0'
    $help = (& $Horus --help --no-color) -join "`n"
    Require ($help.Contains('--case') -and $help.Contains('--enrich') -and
             $help.Contains('--no-recurse') -and $help.Contains('--gui')) 'v4 options are missing from help'
    $sample = Join-Path $root 'sample with spaces'
    Copy-Item -LiteralPath $Horus -Destination $sample

    $peText = (& $Horus $sample --json --no-color) -join "`n"
    $peCode = $LASTEXITCODE
    $pe = $peText | ConvertFrom-Json
    Require (($peCode -eq 0) -or ($peCode -eq 1)) 'PE exit code was not 0 or 1'
    Require ($pe.analysis_status -eq 'complete') 'PE analysis did not complete'
    Require ($pe.is_pe -eq $true) 'extensionless PE was not detected from content'
    Require ($pe.md5.Length -eq 32 -and $pe.sha1.Length -eq 40 -and
             $pe.sha256.Length -eq 64) 'direct analysis did not return all cryptographic hashes'
    Require (-not [string]::IsNullOrWhiteSpace($pe.tlsh) -and
             -not [string]::IsNullOrWhiteSpace($pe.ssdeep)) 'direct PE fuzzy hashes are missing'

    $guiReport = Join-Path $root 'drag and drop report.html'
    & $HorusGui $sample --html $guiReport --no-color | Out-Null
    Require (($LASTEXITCODE -eq 0) -or ($LASTEXITCODE -eq 1)) 'GUI drag-and-drop argument failed'
    Require (Test-Path -LiteralPath $guiReport) 'GUI report was not written'
    Require ([IO.File]::ReadAllText($guiReport).Contains('v4.0.0')) 'GUI did not embed the central version'

    $plainPath = Join-Path $root 'plain file.txt'
    [IO.File]::WriteAllText($plainPath, 'plain text')
    $plainText = (& $Horus $plainPath --json --no-color) -join "`n"
    $plainCode = $LASTEXITCODE
    $plain = $plainText | ConvertFrom-Json
    Require ($plainCode -eq 3) 'non-PE input did not return 3'
    Require ($plain.analysis_status -eq 'unknown') 'non-PE input was not UNKNOWN'
    Require ($null -eq $plain.final_score) 'non-PE input received a score'
    Require ($plain.md5.Length -eq 32 -and $plain.sha1.Length -eq 40 -and
             $plain.sha256.Length -eq 64) 'non-PE inventory did not return all hashes'

    $reportPath = Join-Path $root 'offline report.html'
    & $Horus $plainPath --html $reportPath --no-color | Out-Null
    Require ($LASTEXITCODE -eq 3) 'UNKNOWN HTML export did not return 3'
    Require (Test-Path -LiteralPath $reportPath) 'HTML report was not written'
    $report = [IO.File]::ReadAllText($reportPath)
    Require (-not $report.Contains('__HORUS_REPORT_B64__')) 'HTML marker was left behind'

    $indicatorText = (& $Horus example.com --json --no-color) -join "`n"
    $indicatorCode = $LASTEXITCODE
    $indicator = $indicatorText | ConvertFrom-Json
    Require ($indicatorCode -eq 3) 'unenriched indicator did not return 3'
    Require ($indicator.analysis_status -eq 'unknown') 'unenriched indicator was not UNKNOWN'

    $ErrorActionPreference = 'Continue'
    & $Horus --max-file-mb nope $sample --no-color 2>$null | Out-Null
    Require ($LASTEXITCODE -eq 2) 'malformed number did not return 2'
    & $Horus --scan $plainPath --no-color 2>$null | Out-Null
    Require ($LASTEXITCODE -eq 2) '--scan accepted a regular file'
    & $Horus $plainPath $sample --no-color 2>$null | Out-Null
    Require ($LASTEXITCODE -eq 2) 'multiple direct targets were accepted'
    $ErrorActionPreference = 'Stop'

    $large = Join-Path $root 'large.bin'
    $stream = [IO.File]::OpenWrite($large)
    try { $stream.SetLength(2MB) } finally { $stream.Dispose() }
    $largeText = (& $Horus $large --max-file-mb 1 --json --no-color) -join "`n"
    $largeCode = $LASTEXITCODE
    $largeReport = $largeText | ConvertFrom-Json
    Require ($largeCode -eq 3) 'skipped file did not return 3'
    Require ($largeReport.analysis_status -eq 'skipped') 'large file was not skipped'
}
finally {
    $resolved = [IO.Path]::GetFullPath($root)
    if ($resolved.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolved)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
