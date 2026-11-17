param(
    [string]$Python = 'python',
    [string]$FixtureRoot = '.build/apfs-checkpoint-fixtures',
    [string]$EvidenceDirectory = '.build/apfs-checkpoint-evidence'
)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
function Resolve-ApfsPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $project $Path))
}
$fixtures = Resolve-ApfsPath $FixtureRoot
$evidence = Resolve-ApfsPath $EvidenceDirectory
if (Test-Path -LiteralPath $evidence) { throw 'A fresh APFS evidence directory is required.' }
New-Item -ItemType Directory -Path $evidence | Out-Null
Push-Location $project
try {
    & $Python tests/apfs_salvage_fixture_generator.py --extract tests/fixtures/apfs-salvage --destination $fixtures
    if ($LASTEXITCODE -ne 0) { throw 'APFS fixture verification failed.' }
    . ./scripts/build-app.ps1
    $app = Join-Path $project '.build/app/USB-Recovery.exe'
    $appHash = (Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant()
    $manifest = Join-Path $evidence 'as-invoker.manifest'
    $xml = [Xml.XmlDocument]::new()
    $xml.PreserveWhitespace = $true
    $xml.XmlResolver = $null
    $xml.Load((Join-Path $project 'src/Recovery/app.manifest'))
    $levels = @($xml.GetElementsByTagName('requestedExecutionLevel'))
    if ($levels.Count -ne 1) { throw 'Missing execution level.' }
    $levels[0].SetAttribute('level','asInvoker')
    $xml.Save($manifest)
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $programs = @('ApfsEngineCheckpointTests','ApfsSessionCheckpointTests','ApfsOutputSafetyTests','ApfsRecoveryTests')
    foreach ($name in $programs) {
        $exe = Join-Path $project ('.build/app/' + $name + '-ApfsCI.exe')
        & $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:" + $manifest) /reference:System.Web.Extensions.dll ("/reference:" + $app) ("/out:" + $exe) (Join-Path $project ('tests/' + $name + '.cs')) (Join-Path $project 'tests/FrameworkTarget.cs')
        if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $name) }
        Copy-Item -LiteralPath ($app + '.config') -Destination ($exe + '.config')
        $arguments = @($project,$fixtures)
        if ($name -eq 'ApfsRecoveryTests') { $arguments = @($fixtures,(Join-Path $evidence 'legacy-results')) }
        & $exe @arguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence ($name + '.log'))
        if ($LASTEXITCODE -ne 0) { throw ('APFS validation failed: ' + $name) }
    }
    if ((Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant() -ne $appHash) { throw 'Application changed during validation.' }
    @{status='passed';scope='Managed APFS structural reader continuation and output safety on six authored fixtures; no new native-format compatibility or device claim';source_sha=$env:GITHUB_SHA;app_sha256=$appHash;suites=$programs;gui_tests_run=$false;real_devices_tested=$false;network_isolation_requested=$false} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
} finally { Pop-Location }
