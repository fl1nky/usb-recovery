param([Parameter(Mandatory=$true)][string]$ApplicationDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'OfflineEvidence.ps1')
$taskApp = [IO.Path]::GetFullPath($ApplicationDirectory)
$taskProject = Split-Path -Parent $PSScriptRoot
$taskGroup = 'TelegramRecoverySynthetic-' + [Guid]::NewGuid().ToString('N')
$taskWorker = Join-Path $taskApp 'tools\recovery-helper\recovery-helper.exe'
$taskHarness = Join-Path $taskApp 'TelegramOfflineHarness.exe'
$taskNativeHarness = Join-Path $taskApp 'TelegramNativeOfflineHarness.exe'
$taskMediaHarness = Join-Path $taskApp 'TelegramMediaOfflineHarness.exe'
$taskDeletedHarness=Join-Path $taskApp 'TelegramDeletedOfflineHarness.exe'
$taskHarnesses = @($taskHarness, $taskNativeHarness, $taskMediaHarness, $taskDeletedHarness)
$taskDeletedFixtures=Join-Path (Split-Path -Parent $PSScriptRoot) '.build\telegram-deleted-portable-fixtures'
$taskFixtures = Join-Path $taskApp 'source\tests\TelegramNativeFixtures'
$taskMediaFixtures = Join-Path $taskApp 'source\tests\TelegramMediaFixtures'
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskOldPath = $env:PATH
$taskOldHome = $env:PYTHONHOME
$taskOldPythonPath = $env:PYTHONPATH
$taskResult=New-RecoveryOfflineEvidence $taskApp 'Synthetic Telegram exports/dumps and Android SQLite/WAL fixtures -> frozen worker -> C# archive search; no phone access.' $PSCommandPath
$taskResult.outbound_blocked=$false
$taskSourceProofs=@{}
try {
    if (-not (Test-Path -LiteralPath (Join-Path $taskFixtures 'manifest.json'))) { throw 'Packaged native Telegram fixtures missing.' }
    if (-not (Test-Path -LiteralPath (Join-Path $taskMediaFixtures 'manifest.json'))) { throw 'Packaged Telegram media fixtures missing.' }
    $taskProfiles = @(Get-NetFirewallProfile)
    if ($taskProfiles.Where({ -not $_.Enabled }).Count) { throw 'Firewall profiles must be enabled for enforced offline check.' }
    $taskSourceProofs.TelegramPortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramPortableTests.cs")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\TelegramPortableTests.cs" "$PSScriptRoot\FrameworkTarget.cs" "/win32manifest:$taskProject\src\Recovery\app.manifest"
    if ($LASTEXITCODE -ne 0) { throw 'Offline harness build failed.' }
    $taskSourceProofs.TelegramNativePortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramNativePortableTests.cs")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskNativeHarness" "$PSScriptRoot\TelegramNativePortableTests.cs" "$PSScriptRoot\FrameworkTarget.cs" "/win32manifest:$taskProject\src\Recovery\app.manifest"
    if ($LASTEXITCODE -ne 0) { throw 'Native Telegram offline harness build failed.' }
    $taskSourceProofs.TelegramMediaPortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramMediaPortableTests.cs")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskMediaHarness" "$PSScriptRoot\TelegramMediaPortableTests.cs" "$PSScriptRoot\FrameworkTarget.cs" "/win32manifest:$taskProject\src\Recovery\app.manifest"
    if ($LASTEXITCODE -ne 0) { throw 'Media Telegram offline harness build failed.' }
    $taskSourceProofs.TelegramDeletedPortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramDeletedPortableTests.cs","$PSScriptRoot\build_telegram_deleted_fixtures.py","$PSScriptRoot\TelegramDeletedTests.py","$PSScriptRoot\TelegramResidualProvenanceTests.py","$PSScriptRoot\build_telegram_native_fixtures.py")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskDeletedHarness" "$PSScriptRoot\TelegramDeletedPortableTests.cs" "$PSScriptRoot\FrameworkTarget.cs" "/win32manifest:$taskProject\src\Recovery\app.manifest"
    if($LASTEXITCODE-ne0){throw 'Deleted Telegram portable harness build failed.'}
    foreach($taskFile in $taskHarnesses){Initialize-RecoveryHarnessRuntime $taskFile $taskApp}
    $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($isAdmin){
        foreach ($taskProgram in @($taskWorker) + $taskHarnesses) {
        New-NetFirewallRule -DisplayName 'Telegram recovery temporary synthetic offline check' -Name ($taskGroup + '-' + $taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True | Out-Null
        $taskResult.outbound_rules++
    }
        $taskRules = @(Get-NetFirewallRule -Group $taskGroup)
        if ($taskRules.Count -ne ($taskHarnesses.Count+1) -or @($taskRules | Where-Object { $_.Action -ne 'Block' -or $_.Enabled -ne 'True' }).Count) { throw 'Outbound test blocks did not activate.' }
        $taskResult.outbound_blocked = $true
    }
    $env:PATH = Join-Path $env:WINDIR 'System32'
    $env:PYTHONHOME = $null; $env:PYTHONPATH = $null
    $taskResult.python_on_path = [bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if ($taskResult.python_on_path) { throw 'Python unexpectedly present on restricted PATH.' }
    $taskLog = Join-Path $PSScriptRoot 'TelegramOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult 'TelegramPortable' $taskHarness @() $taskLog $taskSourceProofs.TelegramPortable
    if ($taskNativeExit -ne 0) { Get-Content -LiteralPath $taskLog -Tail 8; throw ('Offline portable integration failed; exit '+$taskNativeExit) }
    Get-Content -LiteralPath $taskLog -Tail 1
    Add-RecoveryTestEvidence $taskResult 'TelegramPortable' $taskLog $taskHarness $taskSourceProofs.TelegramPortable $taskStartedUtc
    $taskLog = Join-Path $PSScriptRoot 'TelegramNativeOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult 'TelegramNativePortable' $taskNativeHarness @($taskFixtures) $taskLog $taskSourceProofs.TelegramNativePortable
    if ($taskNativeExit -ne 0) { Get-Content -LiteralPath $taskLog -Tail 8; throw ('Native Telegram offline portable integration failed; exit '+$taskNativeExit) }
    Get-Content -LiteralPath $taskLog -Tail 1
    Add-RecoveryTestEvidence $taskResult 'TelegramNativePortable' $taskLog $taskNativeHarness $taskSourceProofs.TelegramNativePortable $taskStartedUtc
    $taskLog = Join-Path $PSScriptRoot 'TelegramMediaOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult 'TelegramMediaPortable' $taskMediaHarness @($taskMediaFixtures) $taskLog $taskSourceProofs.TelegramMediaPortable
    if ($taskNativeExit -ne 0) { Get-Content -LiteralPath $taskLog -Tail 8; throw ('Media Telegram offline portable integration failed; exit '+$taskNativeExit) }
    Get-Content -LiteralPath $taskLog -Tail 1
    Add-RecoveryTestEvidence $taskResult 'TelegramMediaPortable' $taskLog $taskMediaHarness $taskSourceProofs.TelegramMediaPortable $taskStartedUtc
    $taskLog=Join-Path $PSScriptRoot 'TelegramDeletedOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult 'TelegramDeletedPortable' $taskDeletedHarness @($taskDeletedFixtures) $taskLog $taskSourceProofs.TelegramDeletedPortable
    if($taskNativeExit-ne0){Get-Content -LiteralPath $taskLog -Tail 8;throw ('Deleted Telegram frozen pipeline failed; exit '+$taskNativeExit)}
    Get-Content -LiteralPath $taskLog -Tail 1
    Add-RecoveryTestEvidence $taskResult 'TelegramDeletedPortable' $taskLog $taskDeletedHarness $taskSourceProofs.TelegramDeletedPortable $taskStartedUtc
    $taskResult.status='passed'
} catch {$taskResult.failure=[string]$_;$taskResult.status='failed'} finally {
    $env:PATH = $taskOldPath; $env:PYTHONHOME = $taskOldHome; $env:PYTHONPATH = $taskOldPythonPath
    Complete-RecoveryOfflineRun $taskResult $taskGroup $taskHarnesses (Join-Path $PSScriptRoot 'TelegramOffline-validation.json')
}
if($taskResult.status-ne'passed'){throw ('Packaged Telegram validation failed: '+$taskResult.failure+'; cleanup: '+($taskResult.cleanup_errors-join'; '))}
