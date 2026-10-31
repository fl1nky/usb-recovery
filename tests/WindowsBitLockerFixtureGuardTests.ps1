# Pure generator guards; -CheckCurrentHome additionally runs guarded read-only
# preflight/default refusal subprocesses. No VHD/native mutation is permitted.
[CmdletBinding()]
param([switch]$CheckCurrentHome)
$ErrorActionPreference='Stop'
$taskProject=Split-Path -Parent $PSScriptRoot
$taskSource=Join-Path $PSScriptRoot 'build_windows_bitlocker_fixture.ps1'
$taskParseErrors=$null;$taskTokens=$null
$taskAst=[Management.Automation.Language.Parser]::ParseFile($taskSource,[ref]$taskTokens,[ref]$taskParseErrors)
if($taskParseErrors.Count){throw 'GENERATOR_PARSE_FAILED'}
$taskChecks=0
function Check([bool]$taskOk,[string]$taskMessage){if(-not$taskOk){throw ('FAILED: '+$taskMessage)};$script:taskChecks++}
function Reject([scriptblock]$taskAction,[string]$taskCode){
    try{&$taskAction;throw 'EXPECTED_REJECTION_MISSING'}catch{Check ($_.Exception.Message-eq$taskCode) ('rejection '+$taskCode)}
}
# Load only the selected function definitions, never the generator body.
$taskNames=@('Test-FixtureHomeSku','Get-FixturePreflight','Get-ValidatedVolumeGuidRoot','Join-FixturePayloadPath','Assert-FixtureEncryptionStatus','Close-FixtureResource','Stop-FixtureChild','Complete-FixtureReport')
foreach($taskName in $taskNames){
    $taskDefinitions=@($taskAst.FindAll({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq$taskName},$true))
    Check ($taskDefinitions.Count-eq 1) ('single function '+$taskName)
    . ([scriptblock]::Create($taskDefinitions[0].Extent.Text))
}
Check ($taskParseErrors.Count-eq 0) 'valid PowerShell source'
foreach($taskSku in 98,99,100,101){Check (Test-FixtureHomeSku $taskSku) ('Home SKU '+$taskSku)}
foreach($taskSku in 0,1,4,48,97,102,121,161){Check (-not(Test-FixtureHomeSku $taskSku)) ('not classified Home '+$taskSku)}

$taskRoot='\\?\Volume{1378c0b0-eaa5-4e66-a909-85eb681a10cb}\'
$taskOther='\\?\Volume{1378c0b0-eaa5-4e66-a909-85eb681a10cc}\'
Check ((Get-ValidatedVolumeGuidRoot $taskRoot $taskRoot)-ceq$taskRoot) 'canonical GUID root'
Check ((Get-ValidatedVolumeGuidRoot $taskRoot.ToUpperInvariant() $taskRoot)-eq$taskRoot) 'GUID case insensitive identity'
foreach($taskBad in '', 'C:\', '\\.\PhysicalDrive0', '\\server\share\', ($taskRoot+'..\'), $taskRoot.TrimEnd('\'), '\\?\Volume{00000000-0000-0000-0000-000000000000}\', '\\?\Volume{1378c0b0eaa54e66a90985eb681a10cb}\', ($taskRoot+'known-proof.bin')){
    Reject {Get-ValidatedVolumeGuidRoot $taskBad} 'VOLUME_GUID_INVALID'
}
Reject {Get-ValidatedVolumeGuidRoot $taskOther $taskRoot} 'VOLUME_GUID_CHANGED'
foreach($taskLeaf in 'known-proof.bin','deleted-proof.txt'){Check ((Join-FixturePayloadPath $taskRoot $taskLeaf $taskRoot)-ceq($taskRoot+$taskLeaf)) 'GUID-rooted payload'}
foreach($taskBad in '..\known-proof.bin','x.txt','C:\known-proof.bin','known-proof.bin:stream','deleted-proof.txt\..',''){
    Reject {Join-FixturePayloadPath $taskRoot $taskBad $taskRoot} 'PAYLOAD_NAME_INVALID'
}
Reject {Join-FixturePayloadPath $taskOther 'known-proof.bin' $taskRoot} 'VOLUME_GUID_CHANGED'

$taskFull=[pscustomobject]@{ConversionStatus=1;EncryptionPercentage=100};$taskOn=[pscustomobject]@{ProtectionStatus=1}
foreach($taskMethod in 3,6){Assert-FixtureEncryptionStatus $taskFull $taskMethod $taskMethod $taskOn;Check $true 'full requested cipher accepted'}
foreach($taskActual in 0,1,2,4,5,6,7,4294967295){if($taskActual-ne 3){Reject {Assert-FixtureEncryptionStatus $taskFull $taskActual 3 $taskOn} 'ENCRYPTION_METHOD_MISMATCH'}}
Reject {Assert-FixtureEncryptionStatus $taskFull 7 7 $taskOn} 'ENCRYPTION_METHOD_MISMATCH'
foreach($taskConversion in 0,2,3,4,5,6){Reject {Assert-FixtureEncryptionStatus ([pscustomobject]@{ConversionStatus=$taskConversion;EncryptionPercentage=100}) 6 6 $taskOn} 'ENCRYPTION_NOT_COMPLETE'}
foreach($taskPercent in 0,1,99,101){Reject {Assert-FixtureEncryptionStatus ([pscustomobject]@{ConversionStatus=1;EncryptionPercentage=$taskPercent}) 6 6 $taskOn} 'ENCRYPTION_NOT_COMPLETE'}
foreach($taskProtection in 0,2){Reject {Assert-FixtureEncryptionStatus $taskFull 6 6 ([pscustomobject]@{ProtectionStatus=$taskProtection})} 'NEW_VOLUME_PROTECTION_NOT_ON'}

$taskErrors=[Collections.Generic.List[string]]::new()
$taskBroken=[pscustomobject]@{Calls=0};$taskBroken|Add-Member ScriptMethod Dispose {$this.Calls++;throw 'SIMULATED_DISPOSE_FAILURE'}
$taskGood=[pscustomobject]@{Calls=0};$taskGood|Add-Member ScriptMethod Dispose {$this.Calls++}
Close-FixtureResource $taskBroken 'FIRST' $taskErrors
Close-FixtureResource $taskGood 'SECOND' $taskErrors
Close-FixtureResource $null 'NONE' $taskErrors
Check ($taskBroken.Calls-eq 1-and$taskGood.Calls-eq 1) 'one disposal failure does not prevent subsequent cleanup'
Check ($taskErrors.Count-eq 1-and$taskErrors[0]-eq'DISPOSE_FIRST_FAILED') 'disposal failure recorded'
$taskChild=[pscustomobject]@{HasExited=$false;Kills=0;Wait=0;Ends=$true}
$taskChild|Add-Member ScriptMethod Kill {$this.Kills++}
$taskChild|Add-Member ScriptMethod WaitForExit {param($ms)$this.Wait=$ms;return $this.Ends}
$taskErrors.Clear();Stop-FixtureChild $taskChild $taskErrors
Check ($taskChild.Kills-eq 1-and$taskChild.Wait-eq 5000-and$taskErrors.Count-eq 0) 'owned child termination bounded'
$taskChild.HasExited=$true;Stop-FixtureChild $taskChild $taskErrors
Check ($taskChild.Kills-eq 1) 'exited child not killed'
$taskChild.HasExited=$false;$taskChild.Ends=$false;Stop-FixtureChild $taskChild $taskErrors
Check ($taskErrors.Count-eq 1-and$taskErrors[0]-eq'DISKPART_CLEANUP_FAILED') 'child cleanup failure recorded'

foreach($taskCaptured in $false,$true){foreach($taskDetached in $false,$true){foreach($taskBadCleanup in $false,$true){
    $taskResult=[ordered]@{status='captured';exit_code=1;reason_code='UNSET'}
    $taskFailures=@();if($taskBadCleanup){$taskFailures=@('DISPOSE_TEST_FAILED')}
    Complete-FixtureReport $taskResult $taskCaptured $taskDetached $taskFailures
    $taskSuccess=$taskCaptured-and$taskDetached-and-not$taskBadCleanup
    Check (($taskResult.status-eq'created')-eq$taskSuccess) 'complete success requires capture/detach/clean resources'
    Check ($taskResult.windows_created_complete_fixture-eq$taskSuccess) 'completion flag follows cleanup'
    Check (($taskResult.exit_code-eq 0)-eq$taskSuccess) 'completion exit follows cleanup'
}}}
foreach($taskStatus in 'cancelled','unavailable','failed'){
    $taskCode=if($taskStatus-eq'cancelled'){3}elseif($taskStatus-eq'unavailable'){2}else{1}
    $taskResult=[ordered]@{status=$taskStatus;exit_code=$taskCode;reason_code='ORIGINAL_ERROR'}
    Complete-FixtureReport $taskResult $true $true @()
    Check ($taskResult.status-eq$taskStatus-and$taskResult.exit_code-eq$taskCode-and-not$taskResult.windows_created_complete_fixture) 'caught failure/cancellation cannot become success'
}

# These structural checks guard the routes not executed on Windows Home.
$taskText=[IO.File]::ReadAllText($taskSource)
Check (-not$taskText.Contains('$taskMount')) 'no mutable folder mount payload paths'
$taskGate=$taskText.IndexOf('$taskPreflight=Get-FixturePreflight')
$taskFirstDirectory=$taskText.IndexOf('New-Item -ItemType Directory')
Check ($taskGate-ge 0-and$taskFirstDirectory-gt$taskGate) 'preflight before first directory creation'
Check ($taskText.Contains('WaitForExit(30000)')-and-not$taskText.Contains('-WindowStyle Hidden -Wait')) 'DiskPart finite wait'
$taskPreflightAst=$taskAst.Find({param($n)$n-is[Management.Automation.Language.FunctionDefinitionAst]-and$n.Name-eq'Get-FixturePreflight'},$true)
$taskPreflightCalls=@($taskPreflightAst.FindAll({param($n)$n-is[Management.Automation.Language.CommandAst]},$true)|ForEach-Object {$_.GetCommandName()})
Check (@($taskPreflightCalls|Where-Object {$_-in@('New-Item','Mount-DiskImage','Dismount-DiskImage','Initialize-Disk','New-Partition','Format-Volume','Invoke-CimMethod','Start-Process','Add-Type')}).Count-eq 0) 'preflight contains no native mutation calls'

if($CheckCurrentHome){
    function Snapshot-FixtureTree{
        $taskTree=Join-Path $taskProject '.build\storage-bitlocker\windows-fixture'
        if(-not(Test-Path -LiteralPath $taskTree)){return 'ABSENT'}
        return (@(Get-ChildItem -LiteralPath $taskTree -Force -Recurse|Sort-Object FullName|ForEach-Object {
            if($_.PSIsContainer){'D|'+$_.FullName}else{'F|'+$_.FullName+'|'+$_.Length+'|'+$_.LastWriteTimeUtc.Ticks+'|'+(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
        })-join"`n")
    }
    function Run-GuardedGenerator([bool]$taskOnly){
        # Even a regressed gate cannot reach diskpart/mount/format during this test.
        $taskCodeText='$ErrorActionPreference=''Stop'';'
        foreach($taskCommand in 'New-Item','Mount-DiskImage','Dismount-DiskImage','Initialize-Disk','New-Partition','Format-Volume','Invoke-CimMethod','Start-Process','Add-Type'){$taskCodeText+='function '+$taskCommand+' { throw ''NATIVE_MUTATION_FORBIDDEN'' };'}
        $taskCodeText+="& '"+$taskSource.Replace("'","''")+"'";if($taskOnly){$taskCodeText+=' -PreflightOnly'};$taskCodeText+=';exit $LASTEXITCODE'
        $taskEncoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($taskCodeText))
        $taskStart=[Diagnostics.ProcessStartInfo]::new();$taskStart.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $taskStart.Arguments='-NoProfile -NonInteractive -EncodedCommand '+$taskEncoded;$taskStart.UseShellExecute=$false;$taskStart.CreateNoWindow=$true;$taskStart.RedirectStandardOutput=$true;$taskStart.RedirectStandardError=$true
        $taskProcess=[Diagnostics.Process]::Start($taskStart)
        try{
            $taskStdout=$taskProcess.StandardOutput.ReadToEndAsync();$taskStderr=$taskProcess.StandardError.ReadToEndAsync()
            if(-not$taskProcess.WaitForExit(20000)){$taskProcess.Kill();$null=$taskProcess.WaitForExit(5000);throw 'PREFLIGHT_TIMEOUT'}
            $taskOut=$taskStdout.GetAwaiter().GetResult();$taskErr=$taskStderr.GetAwaiter().GetResult()
            Check ($taskProcess.ExitCode-eq 2) 'native Home early refusal exit 2'
            Check ([string]::IsNullOrWhiteSpace($taskErr)) 'native preflight has no errors'
            return $taskOut|ConvertFrom-Json
        }finally{$taskProcess.Dispose()}
    }
    $taskBefore=Snapshot-FixtureTree
    $taskNative=Run-GuardedGenerator $true
    Check ($taskNative.status-eq'unavailable'-and$taskNative.reason_code-eq'WINDOWS_EDITION_UNSUPPORTED'-and(Test-FixtureHomeSku $taskNative.operating_system_sku)) 'actual Home preflight is unavailable'
    Check ($taskNative.mode-eq'preflight'-and$taskNative.read_only-and-not$taskNative.vhd_created-and-not$taskNative.mounted) 'native preflight read-only flags'
    $taskNativeDefault=Run-GuardedGenerator $false
    Check ($taskNativeDefault.status-eq'unavailable'-and$taskNativeDefault.reason_code-eq'WINDOWS_EDITION_UNSUPPORTED') 'default invocation refuses Home before mutation'
    Check ((Snapshot-FixtureTree)-ceq$taskBefore) 'all existing fixture directories/files/hashes unchanged'
}
[ordered]@{status='passed';assertions=$taskChecks;current_home_checks=[bool]$CheckCurrentHome;native_mutation_executed=$false;source_sha256=(Get-FileHash -LiteralPath $taskSource -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json
