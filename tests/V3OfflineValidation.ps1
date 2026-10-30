param([Parameter(Mandatory=$true)][string]$ApplicationDirectory)
$ErrorActionPreference = 'Stop'
$taskProject = Split-Path -Parent $PSScriptRoot
$taskApp = [IO.Path]::GetFullPath($ApplicationDirectory)
$taskGroup = 'USBRecoveryV3Validation-' + [Guid]::NewGuid().ToString('N')
$taskPrograms = @('tools\recovery-helper\recovery-helper.exe','tools\signal\SignalLegacyHelper.exe','tools\signal\SignalModernHelper.exe') | ForEach-Object { Join-Path $taskApp $_ }
$taskProfiles = @(Get-NetFirewallProfile | Select-Object Name,Enabled)
if ($taskProfiles.Where({ -not $_.Enabled }).Count -gt 0) { throw 'Firewall profile disabled; enforced offline test cannot be claimed.' }
$taskHarness = Join-Path $taskApp 'V3OfflineHarness.exe'
$taskSearchHarness = Join-Path $taskApp 'ArchiveSearchOfflineHarness.exe'
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskEnvNames = @('PATH','PYTHONHOME','PYTHONPATH','VIRTUAL_ENV')
$taskOldEnv = @{}
foreach ($taskName in $taskEnvNames) { $taskOldEnv[$taskName] = [Environment]::GetEnvironmentVariable($taskName,'Process') }
$taskResult = [ordered]@{status='failed';application=$taskApp;firewall_profiles=$taskProfiles;python_on_path=$null;programs=@();rules_removed=$false}
try {
    foreach ($taskProgram in $taskPrograms) {
        if (-not (Test-Path -LiteralPath $taskProgram -PathType Leaf)) { throw 'Required portable binary missing.' }
        New-NetFirewallRule -DisplayName ([IO.Path]::GetFileName($taskProgram) + ' temporary offline check') -Name ($taskGroup + '-' + $taskResult.programs.Count) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True | Out-Null
        $taskResult.programs += [ordered]@{path=$taskProgram;sha256=(Get-FileHash -LiteralPath $taskProgram -Algorithm SHA256).Hash}
    }
    $taskRules = @(Get-NetFirewallRule -Group $taskGroup)
    if ($taskRules.Count -ne 3 -or $taskRules.Where({$_.Action -ne 'Block' -or $_.Enabled -ne 'True'}).Count -gt 0) { throw 'Offline rules not active.' }
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\V3PackagedIntegrationTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Offline harness compile failed.' }
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskSearchHarness" "$PSScriptRoot\ArchiveSearchWorkflowTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Offline archive search harness compile failed.' }
    $env:PATH = Join-Path $env:WINDIR 'System32'
    foreach ($taskName in 'PYTHONHOME','PYTHONPATH','VIRTUAL_ENV') { [Environment]::SetEnvironmentVariable($taskName,$null,'Process') }
    $taskResult.python_on_path = [bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if ($taskResult.python_on_path) { throw 'Python still available through restricted PATH.' }
    & $taskHarness $taskProject | Tee-Object -FilePath (Join-Path $PSScriptRoot 'V3OfflineIntegration.result.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Enforced offline integration failed.' }
    & $taskSearchHarness $taskProject | Tee-Object -FilePath (Join-Path $PSScriptRoot 'ArchiveSearchOffline.result.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Enforced offline archive search failed.' }
    $taskResult.status='passed'
    $taskResult.scope='C# acquisition -> bundled Python helper -> offline archive; native keyword search and Telegram/WhatsApp/Signal switching; runtime outbound blocked; no installed Python on PATH.'
} finally {
    foreach ($taskName in $taskEnvNames) { [Environment]::SetEnvironmentVariable($taskName,$taskOldEnv[$taskName],'Process') }
    Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $taskResult.rules_removed = @(Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue).Count -eq 0
    if (Test-Path -LiteralPath $taskHarness) { Remove-Item -LiteralPath $taskHarness }
    if (Test-Path -LiteralPath $taskSearchHarness) { Remove-Item -LiteralPath $taskSearchHarness }
    $taskResult | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'V3Offline-validation.json') -Encoding UTF8
}
