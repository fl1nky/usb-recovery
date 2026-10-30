param(
    [string]$Python312 = '',
    [switch]$SkipTests,
    [switch]$SkipRebuildBundle
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskRoot = (Get-RecoveryLayout).Root
$envPython = Join-Path $taskRoot '.build\engine-env\Scripts\python.exe'
$wheelRoot = Join-Path $taskRoot 'helpers\recovery_engine\wheels'
if (-not (Test-Path -LiteralPath $envPython)) {
    if (-not $Python312) { throw 'Provide -Python312 with a Windows x64 Python 3.12 interpreter for developer rebuilding.' }
    $version = & $Python312 -c 'import sys; print("%d.%d" % sys.version_info[:2])'
    if ($version -ne '3.12') { throw 'Python 3.12 is required for rebuilding.' }
    & $Python312 -m venv (Join-Path $taskRoot '.build\engine-env')
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the build environment.' }
}
if (-not (Test-Path -LiteralPath $wheelRoot)) { throw 'Bundled wheel directory is missing.' }
$wheelManifest = Get-Content -LiteralPath (Join-Path $wheelRoot 'SHA256.json') -Raw | ConvertFrom-Json
foreach ($item in $wheelManifest) {
    $candidate = Join-Path $wheelRoot $item.name
    if ([IO.Path]::GetFileName($item.name) -ne $item.name -or -not (Test-Path -LiteralPath $candidate)) { throw 'Invalid wheel inventory.' }
    if ((Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash -ne $item.sha256) { throw 'Wheel checksum mismatch.' }
}
$storageSources=Join-Path $taskRoot 'helpers\recovery_engine\storage-dependencies.json'
if(Test-Path -LiteralPath $storageSources){foreach($item in (Get-Content -LiteralPath $storageSources -Raw|ConvertFrom-Json)){
    if([IO.Path]::GetFileName($item.source)-ne$item.source){throw 'Invalid storage source inventory.'}
    $candidate=Join-Path $taskRoot ('helpers\recovery_engine\dependency-sources\'+$item.source)
    if(-not(Test-Path -LiteralPath $candidate)-or(Get-FileHash -LiteralPath $candidate).Hash-ne$item.sha256){throw 'Storage source checksum mismatch.'}
}}
& $envPython -m pip install --no-index --find-links $wheelRoot --require-hashes -r (Join-Path $taskRoot 'helpers\recovery_engine\requirements-wheel-lock.txt')
if ($LASTEXITCODE -ne 0) { throw 'Could not install the fixed local dependencies.' }
foreach ($vendorName in @('iphone-backup-decrypt')) {
    & $envPython -m pip install --no-index --no-deps --no-build-isolation (Join-Path $taskRoot "vendor\$vendorName")
    if ($LASTEXITCODE -ne 0) { throw "Could not install pinned source: $vendorName" }
}
Push-Location $taskRoot
try {
    if (-not $SkipTests) {
        foreach ($taskTest in 'TelegramAutoTests.py','TelegramMemoryTests.py','ArchiveSearchTests.py','TelegramTlTests.py','SqliteHistoryTests.py','TelegramMediaTests.py','Oct30IndependentReviewTests.py','ApfsRecoveryTests.py','BitLockerRecoveryTests.py','StorageProbeTests.py') {
            & $envPython (Join-Path 'tests' $taskTest)
            if ($LASTEXITCODE -ne 0) { throw 'Telegram regression tests failed.' }
        }
    }
    & $envPython -m PyInstaller --noconfirm --clean --onedir --console --name recovery-helper `
        --distpath (Join-Path $taskRoot 'tools') --workpath (Join-Path $taskRoot '.build\pyinstaller-engine') `
        --specpath (Join-Path $taskRoot '.build') --collect-all Crypto --collect-all pillow_heif `
        --collect-all dissect.apfs --collect-all dissect.fve --collect-all dissect.cstruct --collect-all dissect.util --collect-all asn1crypto --collect-all regex --collect-submodules iphone_backup_decrypt `
        --exclude-module wa_crypt_tools --exclude-module Whatsapp_Chat_Exporter --exclude-module Cryptodome `
        --exclude-module tkinter --exclude-module pytest 'helpers\recovery_engine\engine.py'
    if ($LASTEXITCODE -ne 0) { throw 'Portable helper build failed.' }
    if ($SkipRebuildBundle) { & $envPython 'helpers\recovery_engine\package_runtime.py' '--skip-rebuild-bundle' }
    else { & $envPython 'helpers\recovery_engine\package_runtime.py' }
    if ($LASTEXITCODE -ne 0) { throw 'Runtime license/source packaging failed.' }
} finally { Pop-Location }
