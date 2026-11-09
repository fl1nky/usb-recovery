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
    $taskNames=@('LongPathRecoveryTests','ContentQualityTests','ArchiveSalvageTests','MetadataRescueTests','NewEngineIntegrationTests','ResumableCaptureTests','RecoverySessionTests','FolderProvenanceTests','FolderExportTests','FragmentedZipRecoveryTests','ApplicationPathsTests','FragmentedMediaRecoveryTests','Stz2MediaRecoveryTests','Fmp4RecoveryTests','MediaWorkflowTests','FragmentedPhotoPortableTests','JpegTwoGapPortableTests','PngIdatGapPortableTests','PngTwoGapPortableTests','PngStreamingPortableTests','PhotoSourceAliasTests','PhotoCatalogTests','ProgressivePhotoPortableTests','AndroidHeapPortableTests','Ext4RecoveryTests','RefsRecoveryTests','RaidControllerRecoveryTests','ApfsRecoveryTests','Ext4WorkflowTests','RaidMetadataProbeTests','RaidMetadataAuditTests','RaidMetadataUiAuditTests','Ext4IntegrationAuditTests','PhotoCheckpointSessionTests','CandidateIntegrityPreservationTests','HelperCheckpointProtocolTests','RecoveryRunLockTests','AacLcValidatorTests','AacSyntaxAuditTests','FragmentedAacRecoveryTests','HevcSampleValidatorTests','HevcRecoveryTests','PhotoCheckpointPortableTests','PhotoCheckpointParentAuditTests','TelegramRecoveryProvenanceUiTests','TelegramRecoveryPortableTests','TelegramRollbackPortableTests','TelegramMediaCachePortableTests','TelegramMediaCacheProfilePortableTests','TelegramDocumentEmptyPortableTests','TelegramDocumentDescriptorPortableTests','TelegramDocumentAttributesPortableTests','TelegramMediaOnlyPortableTests','ArchiveTextPortableTests','FragmentedMediaUnitRecoveryTests','FragmentedMediaScaleTests')
    foreach($taskOptional in 'UserSignatureRecoveryTests','SignatureUiIntegrationTests','RecoveryMotionTests','RecoveryResultsVisualTests','RecoveryStageProgressTests','RaidRecoveryTests','StorageUiTests','StoragePipelineTests','HelperMemoryTests','AtomicJsonSaveTests','ExportTempCollisionTests','StorageWorkflowTests','CaptureProvenanceTests'){if(Test-Path -LiteralPath (Join-Path $PSScriptRoot ($taskOptional+'.cs'))){$taskNames+=$taskOptional}}
    $taskNames+=@('RecoveryContinuityTests','DocumentMediaPreviewTests','TelegramPlatformPortableTests','JpegVideoExpansionPortableTests','CommandLineTests','LocalizationTests','DdrescueMapTests','LocalWebServerTests','OfficeXmlSalvageTests','E01ImageReaderTests')
    foreach($taskName in $taskNames) {
        $taskHarness=Join-Path $taskApp ($taskName+'-OfflineHarness.exe')
        $taskSources=@((Join-Path $PSScriptRoot ($taskName+'.cs')),(Join-Path $PSScriptRoot 'FrameworkTarget.cs'))
        if($taskName-in'ContentQualityTests','LongPathRecoveryTests'){$taskSources+=Join-Path $PSScriptRoot 'FilesystemRecoveryTests.cs'}
        $taskSourceProofs[$taskName]=New-RecoveryTestSources $taskSources
        & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 "/win32manifest:$taskProject\src\Recovery\app.manifest" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.IO.Compression.dll /reference:"$taskApp\USB-Recovery.exe" "/main:$taskName" "/out:$taskHarness" @taskSources
        if($LASTEXITCODE-ne 0){throw ('Packaged quality test build failed: '+$taskName)}
        $taskHarnesses+=$taskHarness
        Initialize-RecoveryHarnessRuntime $taskHarness $taskApp
    }
    $taskPrograms=@($taskHarnesses)+@(Join-Path $taskApp 'USB-Recovery.exe')+@(Join-Path $taskApp 'tools\recovery-helper\recovery-helper.exe')
    $isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if($isAdmin){foreach($taskProgram in $taskPrograms){New-NetFirewallRule -DisplayName 'Recovery quality temporary offline test' -Name ($taskGroup+'-'+$taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True|Out-Null;$taskResult.outbound_rules++}}
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
        if($taskName-eq'DocumentMediaPreviewTests'){$taskExtraArguments=@((Join-Path $PSScriptRoot 'fixtures\document-media-preview\avc-aac.mp4'))}
        if($taskName-eq'Ext4RecoveryTests'){$taskInput=Join-Path $taskProject '.build\ext4-fixtures-current';$taskExtraArguments=@((Join-Path $taskProject ('.build\ext4-offline-'+[Guid]::NewGuid().ToString('N'))))}
        if($taskName-eq'RefsRecoveryTests'){$taskInput=Join-Path $taskProject '.build\refs-fixtures-current';$taskExtraArguments=@((Join-Path $taskProject ('.build\refs-offline-'+[Guid]::NewGuid().ToString('N'))))}
        if($taskName-eq'RaidControllerRecoveryTests'){$taskInput=$taskProject;$taskExtraArguments=@((Join-Path $taskProject '.build\raid-controller-fixtures-current'),(Join-Path $taskProject ('.build\raid-ctrl-'+[Guid]::NewGuid().ToString('N'))))}
        if($taskName-eq'ApfsRecoveryTests'){$taskInput=Join-Path $taskProject '.build\apfs-fixtures-current';$taskExtraArguments=@((Join-Path $taskProject ('.build\apfs-offline-'+[Guid]::NewGuid().ToString('N'))))}
        $taskStartedUtc=[DateTime]::UtcNow.ToString('o')
        $taskNativeExit=Invoke-RecoveryOfflineHarness $taskResult $taskName $taskHarness (@($taskInput)+$taskExtraArguments) $taskLog $taskSourceProofs[$taskName]
        if($taskNativeExit-ne 0){Get-Content -LiteralPath $taskLog -Tail 8;throw ('Packaged quality test failed: '+$taskName+'; exit '+$taskNativeExit)}
        $taskSummary=Get-Content -LiteralPath $taskLog -Tail 1
        Write-Output $taskSummary
        Add-RecoveryTestEvidence $taskResult $taskName $taskLog $taskHarness $taskSourceProofs[$taskName] $taskStartedUtc
    }
    $taskResult.status='passed'
} catch {$taskResult.failure=[string]$_;$taskResult.status='failed'} finally {
    $env:PATH=$taskOldPath
    Complete-RecoveryOfflineRun $taskResult $taskGroup $taskHarnesses (Join-Path $PSScriptRoot 'QualityOffline-validation.json')
}
if($taskResult.status-ne'passed'){throw ('Packaged quality validation failed: '+$taskResult.failure+'; cleanup: '+($taskResult.cleanup_errors-join'; '))}
