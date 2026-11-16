param(
    [string]$Python = 'python',
    [string]$FixtureRoot = '.build/ext4-ci-fixtures',
    [string]$EvidenceDirectory = '.build/ext4-ci-evidence',
    [switch]$SkipFixtureExtraction
)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
function Resolve-Ext4TestPath([string]$Value) {
    if ([IO.Path]::IsPathRooted($Value)) { return [IO.Path]::GetFullPath($Value) }
    return [IO.Path]::GetFullPath((Join-Path $project $Value))
}
$fixtures = Resolve-Ext4TestPath $FixtureRoot
$evidence = Resolve-Ext4TestPath $EvidenceDirectory
if (Test-Path -LiteralPath $evidence) { throw 'A new ext4 evidence directory is required.' }
New-Item -ItemType Directory -Path $evidence | Out-Null
Push-Location $project
try {
    if (-not $SkipFixtureExtraction) {
        & $Python tests/ext4_fixture_generator.py --extract tests/fixtures/ext4 --destination $fixtures
        if ($LASTEXITCODE -ne 0) { throw 'Ext4 fixture integrity verification failed.' }
    }
    . ./scripts/build-app.ps1
    $app = Join-Path $project '.build/app/USB-Recovery.exe'
    $appHash = (Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant()
    $manifest = Join-Path $evidence 'as-invoker.manifest'
    $xml = [Xml.XmlDocument]::new()
    $xml.PreserveWhitespace = $true
    $xml.XmlResolver = $null
    $xml.Load((Join-Path $project 'src/Recovery/app.manifest'))
    $levels = @($xml.GetElementsByTagName('requestedExecutionLevel'))
    if ($levels.Count -ne 1) { throw 'Missing execution-level manifest.' }
    $levels[0].SetAttribute('level', 'asInvoker')
    $xml.Save($manifest)
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $suites = @()
    foreach ($name in 'Ext4GroupCheckpointTests', 'Ext4InodeCheckpointTests', 'Ext4JournalCheckpointTests', 'Ext4JournalHistoryCheckpointTests', 'Ext4ReplayCheckpointTests', 'Ext4GroupMetadataTests', 'Ext4RecoveryTests', 'Ext4DirectoryEvidenceTests') {
        $exe = Join-Path $project ('.build/app/' + $name + '-Ext4CI.exe')
        & $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:" + $manifest) /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:" + $app) ("/out:" + $exe) (Join-Path $project ('tests/' + $name + '.cs')) (Join-Path $project 'tests/FrameworkTarget.cs')
        if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $name) }
        Copy-Item -LiteralPath ($app + '.config') -Destination ($exe + '.config')
        $arguments = @($project, $fixtures)
        if ($name -eq 'Ext4RecoveryTests') { $arguments = @($fixtures, (Join-Path $evidence 'legacy-results')) }
        if ($name -eq 'Ext4DirectoryEvidenceTests') { $arguments = @() }
        & $exe @arguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence ($name + '.log'))
        if ($LASTEXITCODE -ne 0) { throw ('Ext4 validation failed: ' + $name) }
        $suites += $name
    }
    if ((Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant() -ne $appHash) { throw 'Application changed during validation.' }
    @{status='passed';scope='Ext4 group, inode, journal discovery/transaction controller and legacy controls; not full-engine resume';source_sha=$env:GITHUB_SHA;app_sha256=$appHash;suites=$suites;gui_tests_run=$false;real_devices_tested=$false;network_isolation_requested=$false} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
} finally { Pop-Location }
