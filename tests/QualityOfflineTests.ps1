param([Parameter(Mandatory=$true)][string]$ApplicationDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'OfflineEvidence.ps1')
$taskApp=[IO.Path]::GetFullPath($ApplicationDirectory)
$taskProject=Split-Path -Parent $PSScriptRoot
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskGroup='RecoveryQualityOffline-'+[Guid]::NewGuid().ToString('N')
$taskOldPath=$env:PATH
$taskHarnesses=@()
$taskSourceProofs=@{}
$taskResult=New-RecoveryOfflineEvidence $taskApp 'Synthetic regular image files only; actual packaged managed recovery modules. No user profiles or physical devices.' $PSCommandPath
try {
    if(@(Get-NetFirewallProfile|Where-Object {-not $_.Enabled}).Count){throw 'Firewall profiles disabled.'}
    $taskNames=@('ContentQualityTests','ArchiveSalvageTests','MetadataRescueTests','NewEngineIntegrationTests','ResumableCaptureTests','RecoverySessionTests','FolderProvenanceTests','FolderExportTests','FragmentedZipRecoveryTests','ApplicationPathsTests','FragmentedMediaRecoveryTests','MediaWorkflowTests','FragmentedPhotoPortableTests','ProgressivePhotoPortableTests','AndroidHeapPortableTests','Ext4RecoveryTests','Ext4WorkflowTests','RaidMetadataProbeTests','RaidMetadataAuditTests','RaidMetadataUiAuditTests','Ext4IntegrationAuditTests','PhotoCheckpointSessionTests','CandidateIntegrityPreservationTests','HelperCheckpointProtocolTests','RecoveryRunLockTests','AacLcValidatorTests','AacSyntaxAuditTests','FragmentedAacRecoveryTests','HevcSampleValidatorTests','HevcRecoveryTests','PhotoCheckpointPortableTests','PhotoCheckpointParentAuditTests','TelegramRecoveryProvenanceUiTests','TelegramRecoveryPortableTests','FragmentedMediaUnitRecoveryTests')
    foreach($taskOptional in 'UserSignatureRecoveryTests','SignatureUiIntegrationTests','RecoveryMotionTests','RecoveryResultsVisualTests','RecoveryStageProgressTests','RaidRecoveryTests','StorageUiTests','StoragePipelineTests','HelperMemoryTests','AtomicJsonSaveTests','ExportTempCollisionTests','StorageWorkflowTests','CaptureProvenanceTests'){if(Test-Path -LiteralPath (Join-Path $PSScriptRoot ($taskOptional+'.cs'))){$taskNames+=$taskOptional}}
    foreach($taskName in $taskNames) {
        $taskHarness=Join-Path $taskApp ($taskName+'-OfflineHarness.exe')
        $taskSources=@((Join-Path $PSScriptRoot ($taskName+'.cs')))
        if($taskName-eq'ContentQualityTests'){$taskSources+=Join-Path $PSScriptRoot 'FilesystemRecoveryTests.cs'}
        $taskSourceProofs[$taskName]=New-RecoveryTestSources $taskSources
        & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:"$taskApp\USB-Recovery.exe" "/main:$taskName" "/out:$taskHarness" @taskSources
        if($LASTEXITCODE-ne 0){throw ('Packaged quality test build failed: '+$taskName)}
        $taskHarnesses+=$taskHarness
    }
    $taskPrograms=@($taskHarnesses)+@(Join-Path $taskApp 'USB-Recovery.exe')+@(Join-Path $taskApp 'tools\recovery-helper\recovery-helper.exe')
    foreach($taskProgram in $taskPrograms){New-NetFirewallRule -DisplayName 'Recovery quality temporary offline test' -Name ($taskGroup+'-'+$taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True|Out-Null;$taskResult.outbound_rules++}
    $env:PATH=Join-Path $env:WINDIR 'System32'
    $taskResult.python_on_path=[bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if($taskResult.python_on_path){throw 'Python unexpectedly on restricted PATH.'}
    foreach($taskHarness in $taskHarnesses){
        $taskName=[IO.Path]::GetFileName($taskHarness).Replace('-OfflineHarness.exe','')
        $taskLog=Join-Path $PSScriptRoot ($taskName+'.packaged.result.txt')
        $taskInput=if($taskName-eq'ArchiveSalvageTests'){Join-Path $taskProject '.build\archive-salvage-tests'}else{$taskProject}
        if($taskName-eq'FragmentedZipRecoveryTests'){$taskInput=Join-Path $taskProject '.build\fragmented-zip-tests'}
        if($taskName-eq'HevcSampleValidatorTests'){$taskInput=Join-Path $taskProject '.build\hevc-validation-fixtures-current'}
        $taskExtraArguments=@()
        if($taskName-eq'Ext4RecoveryTests'){$taskInput=Join-Path $taskProject '.build\ext4-fixtures-current';$taskExtraArguments=@((Join-Path $taskProject ('.build\ext4-offline-'+[Guid]::NewGuid().ToString('N'))))}
        $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
        & $taskHarness $taskInput @taskExtraArguments *> $taskLog
        if($LASTEXITCODE-ne 0){Get-Content -LiteralPath $taskLog -Tail 8;throw ('Packaged quality test failed: '+$taskName)}
        $taskSummary=Get-Content -LiteralPath $taskLog -Tail 1
        Write-Output $taskSummary
        Add-RecoveryTestEvidence $taskResult $taskName $taskLog $taskHarness $taskSourceProofs[$taskName] $taskStartedUtc
    }
    $taskResult.status='passed'
} finally {
    $env:PATH=$taskOldPath
    Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue|Remove-NetFirewallRule
    $taskResult.rules_removed=@(Get-NetFirewallRule -Group $taskGroup -ErrorAction SilentlyContinue).Count-eq 0
    Complete-RecoveryOfflineEvidence $taskResult
    foreach($taskHarness in $taskHarnesses){if(Test-Path -LiteralPath $taskHarness){Remove-Item -LiteralPath $taskHarness}}
    $taskResult|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'QualityOffline-validation.json') -Encoding UTF8
}
if($taskResult.status-ne'passed'){throw 'Packaged evidence did not bind unchanged tested binaries.'}
