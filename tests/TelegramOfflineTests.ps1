param([Parameter(Mandatory=$true)][string]$ApplicationDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'OfflineEvidence.ps1')
$taskApp = [IO.Path]::GetFullPath($ApplicationDirectory)
$taskGroup = 'TelegramRecoverySynthetic-' + [Guid]::NewGuid().ToString('N')
$taskWorker = Join-Path $taskApp 'tools\recovery-helper\recovery-helper.exe'
$taskHarness = Join-Path $taskApp 'TelegramOfflineHarness.exe'
$taskNativeHarness = Join-Path $taskApp 'TelegramNativeOfflineHarness.exe'
$taskMediaHarness = Join-Path $taskApp 'TelegramMediaOfflineHarness.exe'
$taskHarnesses = @($taskHarness, $taskNativeHarness, $taskMediaHarness)
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
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\TelegramPortableTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Offline harness build failed.' }
    $taskSourceProofs.TelegramNativePortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramNativePortableTests.cs")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskNativeHarness" "$PSScriptRoot\TelegramNativePortableTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Native Telegram offline harness build failed.' }
    $taskSourceProofs.TelegramMediaPortable=New-RecoveryTestSources @("$PSScriptRoot\TelegramMediaPortableTests.cs")
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskMediaHarness" "$PSScriptRoot\TelegramMediaPortableTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Media Telegram offline harness build failed.' }
    foreach ($taskProgram in @($taskWorker) + $taskHarnesses) {
        New-NetFirewallRule -DisplayName 'Telegram recovery temporary synthetic offline check' -Name ($taskGroup + '-' + $taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True | Out-Null
        $taskResult.outbound_rules++
    }
    $taskRules = @(Get-NetFirewallRule -Group $taskGroup)
    if ($taskRules.Count -ne 4 -or @($taskRules | Where-Object { $_.Action -ne 'Block' -or $_.Enabled -ne 'True' }).Count) { throw 'Outbound test blocks did not activate.' }
    $taskResult.outbound_blocked = $true
    $env:PATH = Join-Path $env:WINDIR 'System32'
    $env:PYTHONHOME = $null; $env:PYTHONPATH = $null
    $taskResult.python_on_path = [bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if ($taskResult.python_on_path) { throw 'Python unexpectedly present on restricted PATH.' }
    $taskLog = Join-Path $PSScriptRoot 'TelegramOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    & $taskHarness | Tee-Object -FilePath $taskLog
    if ($LASTEXITCODE -ne 0) { throw 'Offline portable integration failed.' }
    Add-RecoveryTestEvidence $taskResult 'TelegramPortable' $taskLog $taskHarness $taskSourceProofs.TelegramPortable $taskStartedUtc
    $taskLog = Join-Path $PSScriptRoot 'TelegramNativeOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    & $taskNativeHarness $taskFixtures | Tee-Object -FilePath $taskLog
    if ($LASTEXITCODE -ne 0) { throw 'Native Telegram offline portable integration failed.' }
    Add-RecoveryTestEvidence $taskResult 'TelegramNativePortable' $taskLog $taskNativeHarness $taskSourceProofs.TelegramNativePortable $taskStartedUtc
    $taskLog = Join-Path $PSScriptRoot 'TelegramMediaOfflineTests.result.txt'
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    & $taskMediaHarness $taskMediaFixtures | Tee-Object -FilePath $taskLog
    if ($LASTEXITCODE -ne 0) { throw 'Media Telegram offline portable integration failed.' }
    Add-RecoveryTestEvidence $taskResult 'TelegramMediaPortable' $taskLog $taskMediaHarness $taskSourceProofs.TelegramMediaPortable $taskStartedUtc
    $taskResult.status='passed'
} finally {
    $env:PATH = $taskOldPath; $env:PYTHONHOME = $taskOldHome; $env:PYTHONPATH = $taskOldPythonPath
    Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $taskResult.rules_removed = @(Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue).Count -eq 0
    Complete-RecoveryOfflineEvidence $taskResult
    foreach ($taskFile in $taskHarnesses) { if (Test-Path -LiteralPath $taskFile) { Remove-Item -LiteralPath $taskFile } }
    $taskResult | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'TelegramOffline-validation.json') -Encoding UTF8
}
if($taskResult.status-ne'passed'){throw 'Packaged evidence did not bind unchanged tested binaries.'}
