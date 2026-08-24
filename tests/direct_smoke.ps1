param([Parameter(Mandatory=$true)][string]$Horus)

$ErrorActionPreference = 'Stop'
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$root = Join-Path $tempBase ("horus-direct-" + [guid]::NewGuid().ToString('N'))

function Require($condition, $message) {
    if (-not $condition) { throw $message }
}

try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $sample = Join-Path $root 'sample with spaces'
    Copy-Item -LiteralPath $Horus -Destination $sample

    $peText = (& $Horus $sample --json --no-color) -join "`n"
    $peCode = $LASTEXITCODE
    $pe = $peText | ConvertFrom-Json
    Require (($peCode -eq 0) -or ($peCode -eq 1)) 'PE exit code was not 0 or 1'
    Require ($pe.analysis_status -eq 'complete') 'PE analysis did not complete'
    Require ($pe.is_pe -eq $true) 'extensionless PE was not detected from content'

    $plainPath = Join-Path $root 'plain file.txt'
    [IO.File]::WriteAllText($plainPath, 'plain text')
    $plainText = (& $Horus $plainPath --json --no-color) -join "`n"
    $plainCode = $LASTEXITCODE
    $plain = $plainText | ConvertFrom-Json
    Require ($plainCode -eq 3) 'non-PE input did not return 3'
    Require ($plain.analysis_status -eq 'unknown') 'non-PE input was not UNKNOWN'
    Require ($null -eq $plain.final_score) 'non-PE input received a score'

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
