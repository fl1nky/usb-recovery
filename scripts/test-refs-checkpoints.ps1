param(
    [string]$Python = 'python',
    [string]$FixtureRoot = '.build/refs-ci-fixtures',
    [string]$AdversarialRoot = '.build/refs-ci-adversarial',
    [string]$EvidenceDirectory = '.build/refs-ci-evidence',
    [string]$NativeImage
)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
function Resolve-RefsPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $project $Path))
}
$fixtures = Resolve-RefsPath $FixtureRoot
$adversarial = Resolve-RefsPath $AdversarialRoot
$evidence = Resolve-RefsPath $EvidenceDirectory
if (Test-Path -LiteralPath $evidence) { throw 'A new ReFS evidence directory is required.' }
New-Item -ItemType Directory -Path $evidence | Out-Null
Push-Location $project
try {
    & $Python tests/refs_fixture_generator.py --extract tests/fixtures/refs --destination $fixtures
    if ($LASTEXITCODE -ne 0) { throw 'ReFS fixture integrity verification failed.' }
    & $Python tests/adversarial_refs_generator.py --destination $adversarial
    if ($LASTEXITCODE -ne 0) { throw 'ReFS adversarial fixture generation failed.' }
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
    foreach ($name in 'RefsMetadataCheckpointTests', 'RefsOutputSafetyTests', 'RefsRecoveryTests', 'RefsChallenger1Tests') {
        $exe = Join-Path $project ('.build/app/' + $name + '-RefsCI.exe')
        & $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:" + $manifest) /reference:System.Web.Extensions.dll ("/reference:" + $app) ("/out:" + $exe) (Join-Path $project ('tests/' + $name + '.cs')) (Join-Path $project 'tests/FrameworkTarget.cs')
        if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $name) }
        Copy-Item -LiteralPath ($app + '.config') -Destination ($exe + '.config')
        $arguments = @($project, $fixtures)
        if ($name -eq 'RefsMetadataCheckpointTests' -and $NativeImage) { $arguments += @('--native-image', (Resolve-RefsPath $NativeImage)) }
        if ($name -eq 'RefsRecoveryTests') { $arguments = @($fixtures, (Join-Path $evidence 'legacy-results')) }
        if ($name -eq 'RefsChallenger1Tests') { $arguments = @($adversarial, (Join-Path $evidence 'adversarial-results')) }
        & $exe @arguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence ($name + '.log'))
        if ($LASTEXITCODE -ne 0) { throw ('ReFS validation failed: ' + $name) }
        $suites += $name
    }
    if ((Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant() -ne $appHash) { throw 'Application changed during validation.' }
    @{status='passed';scope='ReFS bounded raw metadata cursor, actual anchor/tree parsing and output collision safety; not whole-engine continuation';source_sha=$env:GITHUB_SHA;app_sha256=$appHash;suites=$suites;native_metadata_image_requested=[bool]$NativeImage;gui_tests_run=$false;real_devices_tested=$false;network_isolation_requested=$false} |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
} finally { Pop-Location }
