# Shared evidence for synthetic packaged tests. No source medium is opened here.
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
function Get-RecoveryEvidenceHash([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Initialize-RecoveryHarnessRuntime([string]$Harness,[string]$ApplicationDirectory) {
    Copy-Item -LiteralPath (Join-Path $ApplicationDirectory 'USB-Recovery.exe.config') -Destination ($Harness+'.config')
}
function New-RecoveryOfflineEvidence([string]$ApplicationDirectory,[string]$Scope,[string]$Runner) {
    $taskEvidenceDependencies=@()
    # Bind the executable entry points AND their transitive dependency sets.
    # Final verification hashes every file listed by these two inventories;
    # replacing a DLL/PYD and regenerating an inventory invalidates this run.
    foreach($taskRelative in 'USB-Recovery.exe','USB-Recovery.exe.config','tools\recovery-helper\recovery-helper.exe','tools\testdisk-7.2\photorec_win.exe','tools\testdisk-7.2\testdisk_win.exe','package-sha256.json','tools\recovery-helper\runtime-SHA256.json') {
        $taskCandidate=Join-Path $ApplicationDirectory $taskRelative
        if(Test-Path -LiteralPath $taskCandidate -PathType Leaf) {
            $taskEvidenceDependencies+= [ordered]@{path=$taskRelative.Replace('\','/');sha256_before=(Get-RecoveryEvidenceHash $taskCandidate);sha256_after=$null}
        } else {throw ('Missing runtime evidence dependency: '+$taskRelative)}
    }
    return [ordered]@{
        evidence_schema=2;run_id=[Guid]::NewGuid().ToString('N');status='failed';application=$ApplicationDirectory
        started_utc=[DateTime]::UtcNow.ToString('o');completed_utc=$null
        python_on_path=$null;outbound_rules=0;rules_removed=$false
        dependencies=$taskEvidenceDependencies
        runner=[ordered]@{path=[IO.Path]::GetFileName($Runner);sha256=(Get-RecoveryEvidenceHash $Runner)}
        evidence_helper_sha256=(Get-RecoveryEvidenceHash (Join-Path $PSScriptRoot 'OfflineEvidence.ps1'))
        tests=@();scope=$Scope;failure=$null;harness_invocations=@();cleanup_errors=@();cleanup_confirmed=$false
    }
}
function New-RecoveryTestSources([string[]]$Paths) {
    $taskPaths=@($Paths);$taskTarget=Join-Path $PSScriptRoot 'FrameworkTarget.cs'
    if($taskPaths-notcontains$taskTarget){$taskPaths+=$taskTarget}
    return @($taskPaths | ForEach-Object { [ordered]@{path=[IO.Path]::GetFileName($_);sha256=(Get-RecoveryEvidenceHash $_)} })
}
function Add-RecoveryTestEvidence($Report,[string]$Name,[string]$Log,[string]$Harness,$Sources,[string]$StartedUtc) {
    $taskConfigHash=Get-RecoveryEvidenceHash ($Harness+'.config')
    if($taskConfigHash-ne(Get-RecoveryEvidenceHash (Join-Path $Report.application 'USB-Recovery.exe.config'))){throw ('Harness runtime configuration changed: '+$Name)}
    $taskSummary=[string](Get-Content -LiteralPath $Log -Tail 1)
    $taskMatch=[regex]::Match($taskSummary,'(?i)\b(\d+)\s+(?:[A-Za-z-]+\s+){0,4}(?:assertions|checks)\b')
    if(-not $taskMatch.Success -or [int]$taskMatch.Groups[1].Value -le 0){throw ('Missing actual assertion count: '+$Name)}
    foreach($taskSource in $Sources) {
        if((Get-RecoveryEvidenceHash (Join-Path $PSScriptRoot $taskSource.path))-ne $taskSource.sha256){throw ('Test source changed during execution: '+$Name)}
    }
    $Report.tests+= [ordered]@{
        name=$Name;status='passed';assertions=[int]$taskMatch.Groups[1].Value;summary=$taskSummary
        log=[IO.Path]::GetFileName($Log);log_sha256=(Get-RecoveryEvidenceHash $Log)
        harness_sha256=(Get-RecoveryEvidenceHash $Harness);harness_config_sha256=$taskConfigHash;sources=@($Sources)
        started_utc=$StartedUtc;completed_utc=[DateTime]::UtcNow.ToString('o')
    }
}
function Complete-RecoveryOfflineEvidence($Report) {
    $Report.completed_utc=[DateTime]::UtcNow.ToString('o')
    foreach($taskDependency in $Report.dependencies) {
        try{$taskDependency.sha256_after=Get-RecoveryEvidenceHash (Join-Path $Report.application $taskDependency.path)}catch{$taskDependency.sha256_after=$null}
        if($taskDependency.sha256_before-ne $taskDependency.sha256_after){$Report.status='failed'}
    }
    if((Get-RecoveryEvidenceHash (Join-Path $PSScriptRoot $Report.runner.path))-ne $Report.runner.sha256){$Report.status='failed'}
    if((Get-RecoveryEvidenceHash (Join-Path $PSScriptRoot 'OfflineEvidence.ps1'))-ne $Report.evidence_helper_sha256){$Report.status='failed'}
    $taskIsAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(-not $Report.rules_removed -or $Report.python_on_path-ne $false -or ($taskIsAdmin -and $Report.outbound_rules-le 0)){$Report.status='failed'}
}

function Invoke-RecoveryOfflineHarness($Report,[string]$Name,[string]$Program,[string[]]$Arguments,[string]$Log,$Sources) {
    # Capture both streams before testing the exit code. Windows PowerShell can
    # turn redirected native stderr into a terminating error and lose the log.
    $taskProcess=New-Object Diagnostics.Process
    $taskStarted=[DateTime]::UtcNow.ToString('o')
    $taskExit=$null
    $taskInvocationFailure=$null
    $taskRecordingErrors=@()
    $taskReportRow=$null
    try {
        if(@($Arguments|Where-Object {$_-match '["\r\n]' -or $_.EndsWith('\')}).Count){throw 'Unsupported offline harness argument.'}
        $taskInfo=New-Object Diagnostics.ProcessStartInfo
        $taskInfo.FileName=$Program;$taskInfo.UseShellExecute=$false;$taskInfo.CreateNoWindow=$true
        $taskInfo.RedirectStandardOutput=$true;$taskInfo.RedirectStandardError=$true
        $taskInfo.Arguments=(@($Arguments|ForEach-Object {'"'+$_+'"'})-join' ')
        $taskInfo.WorkingDirectory=Split-Path -Parent $Program
        $taskInfo.EnvironmentVariables['__COMPAT_LAYER']='RunAsInvoker'
        $taskProcess.StartInfo=$taskInfo
        if(-not$taskProcess.Start()){throw 'Offline harness did not start.'}
        $taskOut=$taskProcess.StandardOutput.ReadToEndAsync();$taskErr=$taskProcess.StandardError.ReadToEndAsync()
        $taskProcess.WaitForExit()
        $taskExit=$taskProcess.ExitCode
        $taskStdout=$taskOut.GetAwaiter().GetResult();$taskStderr=$taskErr.GetAwaiter().GetResult()
        $taskText=if($taskStderr){"[stderr]`r`n"+$taskStderr+"`r`n"}else{''}
        if($taskStdout){$taskText+=$taskStdout;if(-not$taskStdout.EndsWith("`n")){$taskText+="`r`n"}}
        [IO.File]::WriteAllText($Log,$taskText,(New-Object Text.UTF8Encoding($false)))
        return $taskExit
    } catch {
        $taskInvocationFailure=[string]$_
        if($null-ne$taskExit-and$taskExit-ne 0){throw ('Offline harness '+$Name+' failed; exit '+$taskExit+'; diagnostic recording: '+$taskInvocationFailure)}
        throw
    } finally {
        try {
            $taskReportRow=[ordered]@{name=$Name;exit_code=$taskExit;started_utc=$taskStarted;completed_utc=[DateTime]::UtcNow.ToString('o');sources=@($Sources);invocation_error=$taskInvocationFailure;metadata_errors=@()}
            foreach($taskPair in @(@('harness_sha256',$Program),@('harness_config_sha256',($Program+'.config')),@('log_sha256',$Log))){
                try {$taskReportRow[$taskPair[0]]=if(Test-Path -LiteralPath $taskPair[1] -PathType Leaf){Get-RecoveryEvidenceHash $taskPair[1]}else{$null}}
                catch {$taskReportRow[$taskPair[0]]=$null;$taskRecordingErrors+=($taskPair[0]+': '+[string]$_)}
            }
            $taskReportRow.log=[IO.Path]::GetFileName($Log)
            $Report.harness_invocations+= $taskReportRow
        } finally {
            try {$taskProcess.Dispose()}catch{$taskRecordingErrors+=('process disposal: '+[string]$_)}
            if($null-ne$taskReportRow){$taskReportRow.metadata_errors=$taskRecordingErrors}
        }
        if($taskRecordingErrors.Count-and$null-eq$taskInvocationFailure){
            throw ('Offline harness '+$Name+' diagnostics failed; exit '+$taskExit+'; '+($taskRecordingErrors-join'; '))
        }
    }
}

function Remove-RecoveryOfflineRules([string]$Group) {
    # Only the exact random group created by this run may be removed.
    foreach($taskRule in @(Get-NetFirewallRule -ErrorAction Stop|Where-Object {$_.Group-ceq$Group})){
        try {Remove-NetFirewallRule -Name $taskRule.Name -ErrorAction Stop}
        catch {
            # A stale CIM object is harmless only if a fresh query confirms the
            # same named rule is already absent; permission failures stay errors.
            $taskCimMissing=$_.Exception-is[Microsoft.Management.Infrastructure.CimException]-and[int]$_.Exception.NativeErrorCode-eq 6
            $taskQueryMissing=$_.Exception-is[Microsoft.PowerShell.Cmdletization.Cim.CimJobException]-and
                $_.CategoryInfo.Category-eq[Management.Automation.ErrorCategory]::ObjectNotFound-and
                $_.FullyQualifiedErrorId-ceq'CmdletizationQuery_NotFound_InstanceID,Remove-NetFirewallRule'
            if(-not($taskCimMissing-or$taskQueryMissing)){throw}
            if(@(Get-NetFirewallRule -ErrorAction Stop|Where-Object {$_.Name-ceq$taskRule.Name}).Count){throw}
        }
    }
    if(@(Get-NetFirewallRule -ErrorAction Stop|Where-Object {$_.Group-ceq$Group}).Count){throw 'Offline firewall cleanup incomplete.'}
    return $true
}

function Complete-RecoveryOfflineRun($Report,[string]$Group,[string[]]$Harnesses,[string]$EvidencePath) {
    $taskErrors=@()
    try {$Report.rules_removed=Remove-RecoveryOfflineRules $Group}
    catch {$Report.rules_removed=$false;$Report.status='failed';$taskErrors+=('firewall: '+[string]$_)}
    try {Complete-RecoveryOfflineEvidence $Report}
    catch {$Report.status='failed';$taskErrors+=('evidence: '+[string]$_)}
    foreach($taskHarness in $Harnesses){foreach($taskFile in @($taskHarness,($taskHarness+'.config'))){
        try {if(Test-Path -LiteralPath $taskFile){Remove-Item -LiteralPath $taskFile -ErrorAction Stop}}
        catch {$Report.status='failed';$taskErrors+=('created harness: '+[string]$_)}
    }}
    $Report.cleanup_errors=$taskErrors
    $Report.cleanup_confirmed=($taskErrors.Count-eq 0-and$Report.rules_removed-eq $true)
    $Report|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $EvidencePath -Encoding UTF8
}
