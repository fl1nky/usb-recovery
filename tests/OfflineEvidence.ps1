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
        tests=@();scope=$Scope
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
    if(-not $Report.rules_removed -or $Report.python_on_path-ne $false -or $Report.outbound_rules-le 0){$Report.status='failed'}
}
