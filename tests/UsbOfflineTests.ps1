param([Parameter(Mandatory=$true)][string]$ApplicationDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'OfflineEvidence.ps1')
$taskApp=[IO.Path]::GetFullPath($ApplicationDirectory)
$taskProject=Split-Path -Parent $PSScriptRoot
$taskGroup='UsbDeepSynthetic-'+[Guid]::NewGuid().ToString('N')
$taskHarness=Join-Path $taskApp 'UsbOfflineHarness.exe'
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskOldPath=$env:PATH
$taskResult=New-RecoveryOfflineEvidence $taskApp 'Synthetic regular images only; actual packaged PhotoRec/TestDisk; no physical USB device tests.' $PSCommandPath
$taskSourceProof=New-RecoveryTestSources @("$PSScriptRoot\UsbPackagedTests.cs")
try {
    if(@(Get-NetFirewallProfile | Where-Object {-not $_.Enabled}).Count){throw 'Firewall profiles disabled.'}
    foreach($taskRelative in 'tools\testdisk-7.2\photorec_win.exe','tools\testdisk-7.2\testdisk_win.exe','tools\recovery-helper\recovery-helper.exe'){
        $taskProgram=Join-Path $taskApp $taskRelative
        New-NetFirewallRule -DisplayName 'USB deep recovery temporary offline test' -Name ($taskGroup+'-'+$taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True | Out-Null
        $taskResult.outbound_rules++
    }
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\UsbPackagedTests.cs"
    if($LASTEXITCODE -ne 0){throw 'Packaged test build failed.'}
    $env:PATH=Join-Path $env:WINDIR 'System32'
    $taskResult.python_on_path=[bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if($taskResult.python_on_path){throw 'Python unexpectedly on restricted PATH.'}
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    & $taskHarness $taskProject *> (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt')
    if($LASTEXITCODE -ne 0){Get-Content -LiteralPath (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt') -Tail 8;throw 'Packaged offline test failed.'}
    Get-Content -LiteralPath (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt') -Tail 1
    Add-RecoveryTestEvidence $taskResult 'UsbPackaged' (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt') $taskHarness $taskSourceProof $taskStartedUtc
    $taskResult.status='passed'
} finally {
    $env:PATH=$taskOldPath
    Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $taskResult.rules_removed=@(Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue).Count -eq 0
    Complete-RecoveryOfflineEvidence $taskResult
    if(Test-Path -LiteralPath $taskHarness){Remove-Item -LiteralPath $taskHarness}
    $taskResult|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'UsbOffline-validation.json') -Encoding UTF8
}
if($taskResult.status-ne'passed'){throw 'Packaged evidence did not bind unchanged tested binaries.'}
