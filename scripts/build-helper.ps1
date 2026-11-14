param(
    [string]$Python312 = '',
    [switch]$SkipTests,
    [switch]$SkipRebuildBundle
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
. (Join-Path $PSScriptRoot 'SourceTests.ps1')
$taskRoot = (Get-RecoveryLayout).Root
& (Join-Path $PSScriptRoot 'prepare-helper-env.ps1') -Python312 $Python312
$envPython = Join-Path $taskRoot '.build\engine-env\Scripts\python.exe'
Push-Location $taskRoot
try {
    if (-not $SkipTests) {
        foreach ($taskTest in (Get-RecoverySourceTests -Suite Full -Root $taskRoot)) {
            if ($env:GITHUB_ACTIONS -eq 'true') { Write-Output ('::notice title=Source check::'+$taskTest) }
            & $envPython (Join-Path $PSScriptRoot 'run-source-test.py') (Join-Path 'tests' $taskTest)
            if ($LASTEXITCODE -ne 0) {
                if ($env:GITHUB_ACTIONS -eq 'true') { Write-Output ('::error title=Source check failed::'+$taskTest+' (exit '+$LASTEXITCODE+')') }
                throw ('Source regression failed: '+$taskTest)
            }
        }
    }
    & $envPython -m PyInstaller --noconfirm --clean --onedir --console --name recovery-helper `
        --distpath (Join-Path $taskRoot 'tools') --workpath (Join-Path $taskRoot '.build\pyinstaller-engine') `
        --specpath (Join-Path $taskRoot '.build') --collect-all Crypto --collect-all pillow_heif `
        --paths vendor/ewfprobe --hidden-import recovery_io --hidden-import resumable_copy --hidden-import apfs_journal --hidden-import storage_lvm --hidden-import storage_lvm_thin --collect-all dissect.volume --hidden-import forensic_image --hidden-import ewf_reader --hidden-import ewfprobe --collect-all dissect.apfs --collect-all dissect.fve --collect-all dissect.cstruct --collect-all dissect.util --collect-all asn1crypto --collect-all regex --collect-submodules iphone_backup_decrypt --hidden-import telegram_media_cache --hidden-import telegram_platforms --hidden-import telegram_postbox --hidden-import png_fragments `
        --exclude-module wa_crypt_tools --exclude-module Whatsapp_Chat_Exporter --exclude-module Cryptodome `
        --exclude-module tkinter --exclude-module pytest 'helpers\recovery_engine\engine.py'
    if ($LASTEXITCODE -ne 0) { throw 'Portable helper build failed.' }
    if ($SkipRebuildBundle) { & $envPython 'helpers\recovery_engine\package_runtime.py' '--skip-rebuild-bundle' }
    else { & $envPython 'helpers\recovery_engine\package_runtime.py' }
    if ($LASTEXITCODE -ne 0) { throw 'Runtime license/source packaging failed.' }
} finally { Pop-Location }
