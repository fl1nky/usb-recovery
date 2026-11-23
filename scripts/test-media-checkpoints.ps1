param(
    [string]$Python = 'python',
    [string]$EvidenceDirectory = '.build/media-checkpoint-evidence'
)
$ErrorActionPreference = 'Stop'
$project = Split-Path $PSScriptRoot -Parent
$evidence = if ([IO.Path]::IsPathRooted($EvidenceDirectory)) { [IO.Path]::GetFullPath($EvidenceDirectory) } else { Join-Path $project $EvidenceDirectory }
if (Test-Path -LiteralPath $evidence) { throw 'A fresh media evidence directory is required.' }
New-Item -ItemType Directory -Path $evidence | Out-Null
Push-Location $project
try {
    $fixtures = Join-Path $evidence 'qtff'
    $units = Join-Path $evidence 'units'
    $aac = Join-Path $evidence 'aac'
    $hevc = Join-Path $evidence 'hevc'
    # The fMP4 preparer restricts its output to this project's .build directory.
    $fmp4 = Join-Path $project ('.build/media-fmp4-' + [Guid]::NewGuid().ToString('N'))
    & $Python tests/build_fragmented_media_fixtures.py $fixtures
    if ($LASTEXITCODE -ne 0) { throw 'QTFF fixture generation failed.' }
    & $Python tests/build_media_unit_fixtures.py --extract tests/fixtures/media-units --destination $units
    if ($LASTEXITCODE -ne 0) { throw 'Allocation-unit fixture verification failed.' }
    & $Python tests/build_aac_recovery_fixtures.py --extract tests/fixtures/aac-islands --destination $aac
    if ($LASTEXITCODE -ne 0) { throw 'AAC fixture verification failed.' }
    & $Python tests/fixture_bundle.py extract tests/fixtures/hevc-recovery $hevc
    if ($LASTEXITCODE -ne 0) { throw 'HEVC fixture verification failed.' }
    & $Python tests/prepare_fmp4_media_fixtures.py $fmp4
    if ($LASTEXITCODE -ne 0) { throw 'Native fMP4 fixture verification failed.' }
    & ./scripts/build-app.ps1 -OutputDirectory (Join-Path $evidence 'app')
    $app = Join-Path $evidence 'app/USB-Recovery.exe'
    $appHash = (Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant()
    $manifest = Join-Path $evidence 'as-invoker.manifest'
    $xml = [Xml.XmlDocument]::new(); $xml.PreserveWhitespace = $true; $xml.XmlResolver = $null
    $xml.Load((Join-Path $project 'src/Recovery/app.manifest'))
    $levels = @($xml.GetElementsByTagName('requestedExecutionLevel'))
    if ($levels.Count -ne 1) { throw 'Missing execution level.' }
    $levels[0].SetAttribute('level','asInvoker'); $xml.Save($manifest)
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    $programs = @('MappedContentCheckpointTests','FragmentedMediaCheckpointTests',
        'FragmentedMediaSessionCheckpointTests','FragmentedMediaRecoveryTests',
        'FragmentedMediaUnitRecoveryTests','FragmentedAacRecoveryTests','HevcRecoveryTests','Fmp4RecoveryTests')
    $extraImages = @((Join-Path $fmp4 'image.dd')) + @(
        Get-ChildItem -LiteralPath $units,$aac,$hevc -File -Filter '*.dd' | Sort-Object FullName | Select-Object -ExpandProperty FullName
    )
    $counts = @{}
    foreach ($name in $programs) {
        $exe = Join-Path $evidence ('app/' + $name + '-MediaCI.exe')
        & $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:" + $manifest) /reference:System.Web.Extensions.dll ("/reference:" + $app) ("/out:" + $exe) (Join-Path $project ('tests/' + $name + '.cs')) (Join-Path $project 'tests/FrameworkTarget.cs')
        if ($LASTEXITCODE -ne 0) { throw ('Compilation failed: ' + $name) }
        Copy-Item -LiteralPath ($app + '.config') -Destination ($exe + '.config')
        $arguments = @($project,$fixtures)
        if ($name -eq 'MappedContentCheckpointTests') { $arguments = @($project) }
        if ($name -eq 'FragmentedMediaCheckpointTests') { $arguments += $extraImages }
        if ($name -eq 'FragmentedMediaUnitRecoveryTests') { $arguments = @($project,$units) }
        if ($name -eq 'FragmentedAacRecoveryTests') { $arguments = @($project,$aac) }
        if ($name -eq 'HevcRecoveryTests') { $arguments = @($project,$hevc) }
        if ($name -eq 'Fmp4RecoveryTests') { $arguments = @($project,$fmp4) }
        $log = Join-Path $evidence ($name + '.log')
        & $exe @arguments 2>&1 | Tee-Object -FilePath $log
        if ($LASTEXITCODE -ne 0) { throw ('Media validation failed: ' + $name) }
        $matches = [regex]::Matches((Get-Content -LiteralPath $log -Raw),'PASS [^\r\n]+: (\d+) checks')
        if ($matches.Count -ne 1) { throw ('Missing unambiguous check count: ' + $name) }
        $counts[$name] = [int]$matches[0].Groups[1].Value
    }
    if ((Get-FileHash -LiteralPath $app).Hash.ToLowerInvariant() -ne $appHash) { throw 'Application changed during validation.' }
    @{status='passed';scope='Managed video continuation on QTFF, owned native fMP4, AVC/AAC allocation units and HEVC controls; exact hashes/maps, not authenticity or confirmed deletion';source_sha=$env:GITHUB_SHA;app_sha256=$appHash;suites=$programs;counts=$counts;checks=($counts.Values | Measure-Object -Sum).Sum;additional_continuation_images=$extraImages.Count;gui_tests_run=$false;real_devices_tested=$false;external_decode_run=$false;network_isolated=$false} |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
} finally { Pop-Location }
