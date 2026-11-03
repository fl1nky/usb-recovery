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
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\UsbPackagedTests.cs" "$PSScriptRoot\FrameworkTarget.cs" "/win32manifest:$taskProject\src\Recovery\app.manifest"
    if($LASTEXITCODE -ne 0){throw 'Packaged test build failed.'}
    Initialize-RecoveryHarnessRuntime $taskHarness $taskApp
    $env:PATH=Join-Path $env:WINDIR 'System32'
    $taskResult.python_on_path=[bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if($taskResult.python_on_path){throw 'Python unexpectedly on restricted PATH.'}
    $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
    $taskLog=Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt'
    $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult 'UsbPackaged' $taskHarness @($taskProject) $taskLog $taskSourceProof
    if($taskNativeExit -ne 0){Get-Content -LiteralPath $taskLog -Tail 8;throw ('Packaged offline test failed; exit '+$taskNativeExit)}
    Get-Content -LiteralPath (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt') -Tail 1
    Add-RecoveryTestEvidence $taskResult 'UsbPackaged' (Join-Path $PSScriptRoot 'UsbOfflineTests.result.txt') $taskHarness $taskSourceProof $taskStartedUtc
    $taskResult.status='passed'
} catch {$taskResult.failure=[string]$_;$taskResult.status='failed'} finally {
    $env:PATH=$taskOldPath
    Complete-RecoveryOfflineRun $taskResult $taskGroup @($taskHarness) (Join-Path $PSScriptRoot 'UsbOffline-validation.json')
}
if($taskResult.status-ne'passed'){throw ('Packaged USB validation failed: '+$taskResult.failure+'; cleanup: '+($taskResult.cleanup_errors-join'; '))}
