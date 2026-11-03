param([string]$ProjectRoot=(Split-Path -Parent $PSScriptRoot),[switch]$Child,[string]$Work='')
$ErrorActionPreference='Stop'

function Assert-OwnControl([bool]$Condition,[string]$Message) {
    $script:checks++
    if(-not$Condition){throw $Message}
}
function Own-Hash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-OwnPath([string]$Path,[string]$Root) {
    $taskAbsolute=[IO.Path]::GetFullPath($Path)
    $taskBase=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if(-not$taskAbsolute.StartsWith($taskBase+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Synthetic path escaped its own test directory.'}
    for($taskParent=[IO.DirectoryInfo]$taskAbsolute;$null-ne$taskParent;$taskParent=$taskParent.Parent){
        if($taskParent.Exists-and($taskParent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked synthetic test path.'}
    }
    return $taskAbsolute
}

$taskProject=[IO.Path]::GetFullPath($ProjectRoot)
$taskHelper=Join-Path $PSScriptRoot 'OfflineEvidence.ps1'
$taskHelperBefore=Own-Hash $taskHelper
$taskTestBefore=Own-Hash $PSCommandPath
$script:checks=0
if(-not$Child) {
    $taskWork=Assert-OwnPath (Join-Path $taskProject ('.build\offline-evidence-tests-'+[Guid]::NewGuid().ToString('N'))) $taskProject
    if(Test-Path -LiteralPath $taskWork){throw 'Fresh synthetic test directory required.'}
    New-Item -ItemType Directory -Path $taskWork|Out-Null
    $taskShell=(Get-Process -Id $PID).Path
    if(-not$taskShell-or$taskShell-notmatch '(?i)(?:pwsh|powershell)\.exe$'){throw 'Known PowerShell child process required.'}
    $taskProcess=New-Object Diagnostics.Process
    $taskInfo=New-Object Diagnostics.ProcessStartInfo
    $taskInfo.FileName=$taskShell;$taskInfo.UseShellExecute=$false;$taskInfo.CreateNoWindow=$true
    $taskInfo.RedirectStandardOutput=$true;$taskInfo.RedirectStandardError=$true
    $taskInfo.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$PSCommandPath+'" -ProjectRoot "'+$taskProject+'" -Child -Work "'+$taskWork+'"'
    $taskProcess.StartInfo=$taskInfo
    try {
        if(-not$taskProcess.Start()){throw 'Synthetic child did not start.'}
        $taskOut=$taskProcess.StandardOutput.ReadToEndAsync();$taskErr=$taskProcess.StandardError.ReadToEndAsync()
        if(-not$taskProcess.WaitForExit(90000)){
            # This handle is the new test child created above, never a user process.
            $taskProcess.Kill();$taskProcess.WaitForExit();throw 'Own synthetic child exceeded ninety seconds.'
        }
        $taskStdout=$taskOut.GetAwaiter().GetResult();$taskStderr=$taskErr.GetAwaiter().GetResult()
        [IO.File]::WriteAllText((Join-Path $taskWork 'child.stdout.txt'),$taskStdout,(New-Object Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText((Join-Path $taskWork 'child.stderr.txt'),$taskStderr,(New-Object Text.UTF8Encoding($false)))
        if($taskStdout){Write-Output $taskStdout.TrimEnd()}
        if($taskProcess.ExitCode-ne0){throw ('Synthetic controls failed; child exit '+$taskProcess.ExitCode+'; '+$taskWork)}
        Assert-OwnControl ((Own-Hash $taskHelper)-ceq$taskHelperBefore-and(Own-Hash $PSCommandPath)-ceq$taskTestBefore) 'Test/helper source changed during child controls.'
        $taskReceipt=Get-Content -LiteralPath (Join-Path $taskWork 'synthetic-controls.json') -Raw -Encoding UTF8|ConvertFrom-Json
        Assert-OwnControl ($taskReceipt.schema-eq0-and$taskReceipt.Scope-ceq'Own synthetic controls; not portable acceptance'-and$taskReceipt.status-ceq'synthetic-controls-passed') 'Synthetic receipt must never claim accepted portable evidence.'
        Write-Output ('PASS OfflineEvidenceTests: '+($taskReceipt.checks+$script:checks)+' checks; own child/native streams/exit and mocked firewall/cleanup controls only; no real firewall/network/helper/device. '+$taskWork)
    } finally {$taskProcess.Dispose()}
    return
}

$script:work=Assert-OwnPath $Work (Join-Path $taskProject '.build')
if([IO.Path]::GetFileName($script:work)-cnotmatch '^offline-evidence-tests-[a-f0-9]{32}$'-or-not(Test-Path -LiteralPath $script:work -PathType Container)){throw 'Parent-created own test directory required.'}
. $taskHelper

# These functions exist only in this separate process. Their bodies never call
# NetSecurity, CIM, a module-qualified cmdlet, network or any actual firewall API.
$script:mockRules=@();$script:mockRemovals=@();$script:mockQueries=0;$script:mockMode='normal'
function New-OwnCimNotFound {
    # This is an isolated mock error object, never an actual CIM operation.
    # Public constructors cannot set this status. Only this synthetic object's
    # private enum field is set, then the exact public type/status are asserted.
    $taskException=New-Object Microsoft.Management.Infrastructure.CimException -ArgumentList 'OWN_SYNTHETIC_TYPED_CIM_NOT_FOUND'
    $taskField=[Microsoft.Management.Infrastructure.CimException].GetField('<NativeErrorCode>k__BackingField',[Reflection.BindingFlags]'Instance,NonPublic')
    Assert-OwnControl ($null-ne$taskField-and$taskField.FieldType.FullName-ceq'Microsoft.Management.Infrastructure.NativeErrorCode') 'The mock-only CIM status field must have its exact enum type.'
    $taskField.SetValue($taskException,[Enum]::ToObject($taskField.FieldType,6))
    Assert-OwnControl ($taskException.GetType()-eq[Microsoft.Management.Infrastructure.CimException]-and[int]$taskException.NativeErrorCode-eq6) 'Synthetic positive must be a genuine direct CimException with public NativeErrorCode6.'
    return $taskException
}
function New-OwnCmdletizationError([string]$Mode) {
    # Public constructors and an own ErrorRecord only. No CIM or NetSecurity call.
    $taskId='CmdletizationQuery_NotFound_InstanceID,Remove-NetFirewallRule'
    $taskCategory=[Management.Automation.ErrorCategory]::ObjectNotFound
    $taskType=[Microsoft.PowerShell.Cmdletization.Cim.CimJobException]
    if($Mode-ceq'adapter-wrong-id'){$taskId='CmdletizationQuery_NotFound_InstanceID,UnrelatedCommand'}
    if($Mode-ceq'adapter-wrong-category'){$taskCategory=[Management.Automation.ErrorCategory]::PermissionDenied}
    if($Mode-ceq'adapter-wrong-class'){$taskType=[InvalidOperationException]}
    $taskException=[Activator]::CreateInstance($taskType,@('OWN_SYNTHETIC_CMDLETIZATION_QUERY_CONTROL'))
    $taskRecord=[Management.Automation.ErrorRecord]::new($taskException,$taskId,$taskCategory,$null)
    Assert-OwnControl ($taskRecord.Exception.GetType()-eq$taskType-and$taskRecord.FullyQualifiedErrorId-ceq$taskId-and$taskRecord.CategoryInfo.Category-eq$taskCategory) 'Own adapter control must retain its exact exception type, category and ID without any actual cmdlet invocation.'
    return $taskRecord
}
function Get-NetFirewallRule {
    [CmdletBinding()]param()
    $script:mockQueries++
    if($script:mockMode-ceq'query-denied'-and$script:mockQueries-gt1){throw 'OWN_SYNTHETIC_QUERY_DENIED'}
    return @($script:mockRules)
}
function Remove-NetFirewallRule {
    [CmdletBinding()]param([Parameter(Mandatory=$true)][string]$Name)
    $script:mockRemovals+= $Name
    if($script:mockMode-ceq'permission-denied'){Write-Error 'OWN_SYNTHETIC_PERMISSION_DENIED' -ErrorId 'OWN_PERMISSION_DENIED' -Category PermissionDenied -ErrorAction Stop}
    if($script:mockMode-ceq'query-denied'){throw (New-OwnCimNotFound)}
    if($script:mockMode-ceq'adapter-still-present'){throw (New-OwnCmdletizationError $script:mockMode)}
    if($script:mockMode-ceq'still-present'){return}
    $script:mockRules=@($script:mockRules|Where-Object {$_.Name-cne$Name})
    if($script:mockMode-ceq'permission-absent'){Write-Error 'OWN_SYNTHETIC_PERMISSION_DENIED_AFTER_DISAPPEARANCE' -ErrorId 'OWN_PERMISSION_DENIED' -Category PermissionDenied -ErrorAction Stop}
    if($script:mockMode-ceq'forged-fqid-absent'){Write-Error 'OWN_SYNTHETIC_FORGED_NOT_FOUND_ID' -ErrorId 'MI RESULT 6' -Category ObjectNotFound -ErrorAction Stop}
    if($script:mockMode-ceq'win32-code6-absent'){throw ([ComponentModel.Win32Exception]::new(6))}
    if($script:mockMode-ceq'wrapped-cim-absent'){throw ([InvalidOperationException]::new('OWN_SYNTHETIC_WRAPPED_CIM_UNKNOWN',(New-OwnCimNotFound)))}
    if($script:mockMode-in@('adapter-absent','adapter-wrong-category','adapter-wrong-id','adapter-wrong-class')){throw (New-OwnCmdletizationError $script:mockMode)}
    if($script:mockMode-ceq'stale-absent'){throw (New-OwnCimNotFound)}
}
foreach($taskName in 'Get-NetFirewallRule','Remove-NetFirewallRule'){
    $taskCommand=Get-Command $taskName -CommandType Function
    Assert-OwnControl ($taskCommand.ScriptBlock.File-ceq$PSCommandPath) 'Only this child-process synthetic firewall function may resolve.'
}
function New-OwnReport([string]$Failure) {
    return [ordered]@{
        evidence_schema=0;Scope='Own synthetic controls; not portable acceptance';run_id=[Guid]::NewGuid().ToString('N')
        status='failed';application=$script:work;started_utc=[DateTime]::UtcNow.ToString('o');completed_utc=$null
        python_on_path=$false;outbound_rules=1;rules_removed=$false;dependencies=@();tests=@()
        runner=[ordered]@{path=[IO.Path]::GetFileName($PSCommandPath);sha256=(Own-Hash $PSCommandPath)}
        evidence_helper_sha256=(Own-Hash $taskHelper);failure=$Failure;harness_invocations=@();cleanup_errors=@();cleanup_confirmed=$false
    }
}
function Reset-OwnFirewall([string]$Group,[string]$Mode) {
    $script:mockRules=@([pscustomobject]@{Name='owned-rule';Group=$Group},[pscustomobject]@{Name='unrelated-rule';Group='UNRELATED_SYNTHETIC_GROUP'},[pscustomobject]@{Name='case-variant-rule';Group=$Group.ToLowerInvariant()})
    $script:mockRemovals=@();$script:mockQueries=0;$script:mockMode=$Mode
}
function Own-CompletionControl([string]$Mode,[bool]$ShouldClean) {
    $taskFolder=Join-Path $script:work $Mode;New-Item -ItemType Directory -Path $taskFolder|Out-Null
    # Cleanup is extension/content agnostic. Ordinary owned files isolate this
    # contract from transient locks on newly copied executable images.
    $taskExecutable=Join-Path $taskFolder 'created-harness.control';[IO.File]::WriteAllText($taskExecutable,'OWN_CREATED_HARNESS_CONTROL')
    [IO.File]::WriteAllText(($taskExecutable+'.config'),'OWN_CREATED_HARNESS_CONFIG_CONTROL')
    $taskUnrelated=Join-Path $taskFolder 'unrelated-keep.txt';[IO.File]::WriteAllText($taskUnrelated,'OWN_UNRELATED_KEEP')
    $taskGroup='OwnSynthetic-'+[Guid]::NewGuid().ToString('N');Reset-OwnFirewall $taskGroup $Mode
    $taskReport=New-OwnReport 'OWN_PRIMARY_NATIVE_FAILURE_EXIT_7'
    $taskEvidence=Join-Path $taskFolder 'mock-evidence.json'
    Complete-RecoveryOfflineRun $taskReport $taskGroup @($taskExecutable) $taskEvidence
    Assert-OwnControl (Test-Path -LiteralPath $taskEvidence -PathType Leaf) 'Cleanup must persist the original failure report.'
    $taskSaved=Get-Content -LiteralPath $taskEvidence -Raw -Encoding UTF8|ConvertFrom-Json
    Assert-OwnControl ($taskSaved.evidence_schema-eq0-and$taskSaved.Scope-ceq'Own synthetic controls; not portable acceptance'-and$taskSaved.status-ceq'failed'-and$taskSaved.failure-ceq'OWN_PRIMARY_NATIVE_FAILURE_EXIT_7') 'Cleanup cannot erase the primary failure or emit accepted portable metadata.'
    Assert-OwnControl (-not(Test-Path -LiteralPath $taskExecutable)-and-not(Test-Path -LiteralPath ($taskExecutable+'.config'))-and(Test-Path -LiteralPath $taskUnrelated)) 'Completion removes its own harness/config even on failure and preserves unrelated files.'
    Assert-OwnControl ($script:mockRemovals.Count-eq1-and$script:mockRemovals[0]-ceq'owned-rule'-and@($script:mockRules|Where-Object {$_.Name-in@('unrelated-rule','case-variant-rule')}).Count-eq2) 'Cleanup removes only the exact synthetic group, retaining unrelated and case-variant groups.'
    if($Mode-in@('forged-fqid-absent','win32-code6-absent','wrapped-cim-absent','adapter-wrong-category','adapter-wrong-id','adapter-wrong-class')){
        Assert-OwnControl (@($script:mockRules|Where-Object {$_.Name-ceq'owned-rule'}).Count-eq0) 'Forged, wrong-native-type and wrapped-error negatives have an actually absent synthetic rule; absence alone cannot excuse the wrong exception type.'
    }
    if($ShouldClean){
        Assert-OwnControl ($taskSaved.rules_removed-eq$true-and$taskSaved.cleanup_confirmed-eq$true-and@($taskSaved.cleanup_errors).Count-eq0-and$script:mockQueries-ge3) 'Stale removal is accepted only after a fresh named-rule absence and final group query.'
    } else {
        Assert-OwnControl ($taskSaved.rules_removed-eq$false-and$taskSaved.cleanup_confirmed-eq$false-and@($taskSaved.cleanup_errors).Count-ge1-and($taskSaved.cleanup_errors-join' ')-match'firewall:') 'Permission, failed verification or still-present rule must produce a cleanup failure without masking the primary failure.'
    }
}
function Own-InvocationIoControls($Sources) {
    $taskReport=New-OwnReport 'OWN_LOG_WRITE_FAILURE_AFTER_EXIT_7'
    $taskLog=Join-Path $script:work 'never-created-log-parent\own.log';$taskCaught=$null
    Assert-OwnControl (-not(Test-Path -LiteralPath (Split-Path -Parent $taskLog))) 'Missing-log-parent control must not depend on ACL or system changes.'
    try {Invoke-RecoveryOfflineHarness $taskReport 'OwnLogWriteFailure' $script:program @('argument with spaces') $taskLog $Sources|Out-Null}
    catch {$taskCaught=[string]$_;$taskReport.failure=$taskCaught}
    Assert-OwnControl ($null-ne$taskCaught-and$taskCaught-match'\bexit 7\b'-and$taskReport.harness_invocations.Count-eq1) 'Log-write failure must retain known native exit7 in its thrown diagnostic and one invocation row.'
    $taskRow=$taskReport.harness_invocations[0]
    Assert-OwnControl ($taskRow.exit_code-eq7-and-not[String]::IsNullOrWhiteSpace($taskRow.invocation_error)-and$null-eq$taskRow.log_sha256-and-not(Test-Path -LiteralPath $taskLog)) 'Invocation records native7 and its log-write failure even when the log could not be created.'
    Assert-OwnControl ($taskRow.harness_sha256-ceq(Own-Hash $script:program)-and$taskRow.harness_config_sha256-ceq(Own-Hash ($script:program+'.config'))) 'Failed log recording does not discard independently available executable/config identities.'
    $taskReport|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work 'mock-log-write-failure.json') -Encoding UTF8
    $taskOriginalHash=(Get-Command Get-RecoveryEvidenceHash -CommandType Function).ScriptBlock
    try {
        # This local function shadows the helper only during these child controls.
        # The failure is injected after the real native output was fully logged.
        function Get-RecoveryEvidenceHash([string]$Path) {
            if($Path-ceq$script:hashMockProgram){
                $taskLogged=Get-Content -LiteralPath $script:hashMockLog -Raw -Encoding UTF8
                Assert-OwnControl ($taskLogged.Contains('OWN_STDOUT_END')-and$taskLogged.Contains('OWN_STDERR_END')) 'Metadata failure must occur after both complete real native streams, never before process start.'
                $script:hashMockHits++
                throw ('OWN_SYNTHETIC_METADATA_HASH_FAILURE_EXIT_'+$script:hashMockExit)
            }
            & $taskOriginalHash $Path
        }
        foreach($taskKnownExit in @(7,0)){
            $script:hashMockProgram=$script:program;$script:hashMockExit=$taskKnownExit;$script:hashMockHits=0
            $script:hashMockLog=Join-Path $script:work ('native-metadata-failure-'+$taskKnownExit+'.log')
            $taskReport=New-OwnReport ('OWN_METADATA_FAILURE_AFTER_EXIT_'+$taskKnownExit);$taskCaught=$null
            $taskArguments=if($taskKnownExit-eq0){@('return-zero')}else{@('argument with spaces')}
            try {Invoke-RecoveryOfflineHarness $taskReport ('OwnHashFailure'+$taskKnownExit) $script:program $taskArguments $script:hashMockLog $Sources|Out-Null}
            catch {$taskCaught=[string]$_;$taskReport.failure=$taskCaught}
            Assert-OwnControl ($null-ne$taskCaught-and$taskCaught-match('\bexit '+$taskKnownExit+'\b')-and$script:hashMockHits-eq1-and$taskReport.harness_invocations.Count-eq1) 'Metadata recording failure must throw with the exact known native exit, including exit0; neither can be accepted.'
            $taskRow=$taskReport.harness_invocations[0]
            Assert-OwnControl ($taskRow.exit_code-eq$taskKnownExit-and$null-eq$taskRow.harness_sha256-and$null-eq$taskRow.invocation_error-and@($taskRow.metadata_errors).Count-eq1-and$taskRow.metadata_errors[0].Contains('OWN_SYNTHETIC_METADATA_HASH_FAILURE_EXIT_'+$taskKnownExit)) 'Per-file hash failure records null hash and a separate metadata error while preserving the real native exit.'
            Assert-OwnControl ($taskRow.log_sha256-ceq(Own-Hash $script:hashMockLog)-and$taskRow.harness_config_sha256-ceq(Own-Hash ($script:program+'.config'))-and$taskReport.status-ceq'failed') 'A failed metadata field cannot discard other hashes or turn a zero-exit invocation into successful evidence.'
            $taskReport|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work ('mock-metadata-failure-'+$taskKnownExit+'.json')) -Encoding UTF8
        }
    } finally {Set-Item -LiteralPath Function:\Get-RecoveryEvidenceHash -Value $taskOriginalHash}
    Assert-OwnControl ((Get-RecoveryEvidenceHash $script:program)-ceq(Own-Hash $script:program)) 'Own metadata hash mock is restored in finally before other evidence controls.'
}

try {
    $taskNativeSource=Join-Path $script:work 'own-native-control.cs'
    $taskNativeCode=@'
using System;
public static class OwnNativeControl {
    public static int Main(string[] args) {
        Console.Out.WriteLine("OWN_STDOUT_BEGIN");
        Console.Error.WriteLine("OWN_STDERR_BEGIN");
        for(int i=0;i<1024;i++) { Console.Out.WriteLine(new string('O',80)); Console.Error.WriteLine(new string('E',80)); }
        Console.Out.WriteLine("OWN_ARG:"+(args.Length==1?args[0]:"WRONG_ARGUMENT_COUNT"));
        Console.Error.WriteLine("OWN_STDERR_END");
        Console.Out.WriteLine("OWN_STDOUT_END");
        return args.Length==1 && args[0]=="return-zero" ? 0 : 7;
    }
}
'@
    [IO.File]::WriteAllText($taskNativeSource,$taskNativeCode,(New-Object Text.UTF8Encoding($false)))
    $script:program=Join-Path $script:work 'own-native-control.exe'
    $taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ('/out:'+$script:program) $taskNativeSource > (Join-Path $script:work 'compile.txt') 2>&1
    if($LASTEXITCODE-ne0){throw 'Own minimal native-control compilation failed.'}
    [IO.File]::WriteAllText(($script:program+'.config'),'<?xml version="1.0"?><configuration><startup><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" /></startup></configuration>')
    $taskSources=@([ordered]@{path=[IO.Path]::GetFileName($taskNativeSource);sha256=(Own-Hash $taskNativeSource)})
    $taskLog=Join-Path $script:work 'native-exit7.log';$taskReport=New-OwnReport 'OWN_NATIVE_EXIT_7'
    $taskExit=Invoke-RecoveryOfflineHarness $taskReport 'OwnNativeExit7' $script:program @('argument with spaces') $taskLog $taskSources
    Assert-OwnControl ($taskExit-is[int]-and$taskExit-eq7) 'Native stdout/stderr must retain the exact exit code 7.'
    $taskText=Get-Content -LiteralPath $taskLog -Raw -Encoding UTF8
    Assert-OwnControl ($taskText.Contains('[stderr]')-and$taskText.Contains('OWN_STDERR_BEGIN')-and$taskText.Contains('OWN_STDERR_END')-and$taskText.Contains('OWN_STDOUT_BEGIN')-and$taskText.Contains('OWN_STDOUT_END')-and$taskText.Contains('OWN_ARG:argument with spaces')) 'Both complete streams and quoted argument must survive native failure.'
    Assert-OwnControl ($taskText.Length-gt160000) 'Both streams exceed a pipe buffer and are drained without truncation or deadlock.'
    Assert-OwnControl ($taskReport.harness_invocations.Count-eq1) 'Exactly one real invocation row is recorded.'
    $taskInvocation=$taskReport.harness_invocations[0]
    Assert-OwnControl ($taskInvocation.exit_code-eq7-and$taskInvocation.harness_sha256-ceq(Own-Hash $script:program)-and$taskInvocation.harness_config_sha256-ceq(Own-Hash ($script:program+'.config'))-and$taskInvocation.log_sha256-ceq(Own-Hash $taskLog)-and$taskInvocation.sources[0].sha256-ceq(Own-Hash $taskNativeSource)) 'Invocation binds actual executable/config/log/source hashes despite nonzero exit.'
    Assert-OwnControl ([DateTime]::Parse($taskInvocation.completed_utc)-ge[DateTime]::Parse($taskInvocation.started_utc)) 'Native invocation has ordered start/completion timestamps.'
    $taskMissing=New-OwnReport 'OWN_NOT_STARTED';$taskCaught=$false
    try {Invoke-RecoveryOfflineHarness $taskMissing 'OwnMissingProgram' (Join-Path $script:work 'never-created.exe') @() (Join-Path $script:work 'never-created.log') $taskSources|Out-Null}
    catch {$taskCaught=$true;$taskMissing.failure='OWN_START_FAILURE: '+$_.Exception.GetType().FullName}
    Assert-OwnControl ($taskCaught-and$taskMissing.harness_invocations.Count-eq1-and$null-eq$taskMissing.harness_invocations[0].exit_code-and$null-eq$taskMissing.harness_invocations[0].harness_sha256-and$taskMissing.failure.StartsWith('OWN_START_FAILURE:')) 'Start failure records a null exit, missing executable and an explicit caller primary failure; it cannot become exit zero.'
    $taskMissing|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work 'mock-start-failure.json') -Encoding UTF8
    $taskReport|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work 'mock-native-failure.json') -Encoding UTF8
    Own-InvocationIoControls $taskSources
    Own-CompletionControl 'stale-absent' $true
    Own-CompletionControl 'permission-denied' $false
    Own-CompletionControl 'permission-absent' $false
    Own-CompletionControl 'forged-fqid-absent' $false
    Own-CompletionControl 'win32-code6-absent' $false
    Own-CompletionControl 'wrapped-cim-absent' $false
    Own-CompletionControl 'adapter-absent' $true
    Own-CompletionControl 'adapter-still-present' $false
    Own-CompletionControl 'adapter-wrong-category' $false
    Own-CompletionControl 'adapter-wrong-id' $false
    Own-CompletionControl 'adapter-wrong-class' $false
    Own-CompletionControl 'still-present' $false
    Own-CompletionControl 'query-denied' $false
    $taskEmptyGroup='OwnAbsent-'+[Guid]::NewGuid().ToString('N');Reset-OwnFirewall $taskEmptyGroup 'normal';$script:mockRules=@($script:mockRules|Where-Object {$_.Group-cne$taskEmptyGroup})
    $taskEmptyResult=Remove-RecoveryOfflineRules $taskEmptyGroup
    Assert-OwnControl ($taskEmptyResult-eq$true-and$script:mockRemovals.Count-eq0-and$script:mockRules.Count-eq2) 'An absent group succeeds without any Remove call or change to unrelated rules.'
    Assert-OwnControl ((Own-Hash $taskHelper)-ceq$taskHelperBefore-and(Own-Hash $PSCommandPath)-ceq$taskTestBefore) 'Actual helper/test source remains unchanged throughout all controls.'
    $taskReceipt=[ordered]@{schema=0;Scope='Own synthetic controls; not portable acceptance';status='synthetic-controls-passed';checks=$script:checks;helper_sha256=$taskHelperBefore;test_sha256=$taskTestBefore;real_firewall_called=$false;network_called=$false;recovery_helper_called=$false;devices_opened=$false;mock_process_only=$true;child_pid=$PID}
    $taskReceipt|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work 'synthetic-controls.json') -Encoding UTF8
    Write-Output ('Synthetic controls: '+$script:checks+' checks; exact exit7, complete stdout/stderr and isolated firewall cleanup failures preserved.')
    exit 0
} catch {
    [ordered]@{schema=0;Scope='Own synthetic controls; not portable acceptance';status='synthetic-controls-failed';checks=$script:checks;error=[string]$_;helper_sha256=$taskHelperBefore;test_sha256=$taskTestBefore;real_firewall_called=$false;network_called=$false;recovery_helper_called=$false}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $script:work 'synthetic-controls-failed.json') -Encoding UTF8
    [Console]::Error.WriteLine([string]$_);exit 1
}
