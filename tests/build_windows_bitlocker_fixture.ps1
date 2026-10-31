# Creates and encrypts ONE NEW disposable virtual disk, never an existing disk.
# TEST ONLY PUBLIC PASSPHRASE: Recovery-Test-Only-2026!Fixture#42
# No policy edits, TPM changes, auto-unlock, AD/cloud backups or driver installs.
# Microsoft API references:
# https://learn.microsoft.com/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
# https://learn.microsoft.com/windows/win32/secprov/encrypt-win32-encryptablevolume
# -PreflightOnly performs read-only checks and writes JSON to stdout, never files.
# Exit codes: 0 ready/created, 2 unavailable, 1 failed, 3 cancelled.
# Home/Core SKU definitions: https://learn.microsoft.com/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
[CmdletBinding()]
param([ValidateSet(3,6)][uint32]$EncryptionMethod=6,[switch]$PreflightOnly)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

function Test-FixtureHomeSku([uint32]$taskSku){return $taskSku-in@(98,99,100,101)}
function Get-FixturePreflight{
    $taskCheck=[ordered]@{status='unavailable';mode='preflight';exit_code=2;reason_code='';eligible=$false;read_only=$true;native_encryption_verified=$false;vhd_created=$false;mounted=$false;requested_encryption_method=$EncryptionMethod;checked_utc=[DateTime]::UtcNow.ToString('o')}
    if([Environment]::OSVersion.Platform-ne[PlatformID]::Win32NT){$taskCheck.reason_code='WINDOWS_REQUIRED';return $taskCheck}
    try{
        $taskOs=Get-CimInstance -ClassName Win32_OperatingSystem -Property OperatingSystemSKU,ProductType,Version,BuildNumber -OperationTimeoutSec 10 -ErrorAction Stop
        if($null-eq$taskOs.OperatingSystemSKU){throw 'OS_SKU_UNAVAILABLE'}
        $taskCheck['operating_system_sku']=[uint32]$taskOs.OperatingSystemSKU;$taskCheck['product_type']=[uint32]$taskOs.ProductType
        $taskCheck['windows_version']=[string]$taskOs.Version;$taskCheck['windows_build']=[string]$taskOs.BuildNumber
        # Command/provider presence on Home does not confer the BitLocker feature license.
        if(Test-FixtureHomeSku $taskCheck.operating_system_sku){$taskCheck.reason_code='WINDOWS_EDITION_UNSUPPORTED';return $taskCheck}
        if(-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){$taskCheck.reason_code='ADMIN_REQUIRED';return $taskCheck}
        foreach($taskCommand in 'Get-DiskImage','Mount-DiskImage','Dismount-DiskImage','Get-Disk','Get-Partition','Get-Volume','Initialize-Disk','New-Partition','Format-Volume','Get-CimClass','Get-CimInstance','Invoke-CimMethod'){
            if(-not(Get-Command $taskCommand -ErrorAction SilentlyContinue)){$taskCheck.reason_code='WINDOWS_STORAGE_UNAVAILABLE';$taskCheck['missing_command']=$taskCommand;return $taskCheck}
        }
        if(-not[IO.File]::Exists((Join-Path $env:WINDIR 'System32\diskpart.exe'))){$taskCheck.reason_code='DISKPART_UNAVAILABLE';return $taskCheck}
        $taskClass=Get-CimClass -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -OperationTimeoutSec 10 -ErrorAction Stop
        foreach($taskMethod in 'ProtectKeyWithPassPhrase','Encrypt','GetConversionStatus','GetProtectionStatus','GetEncryptionMethod'){
            if(-not$taskClass.CimClassMethods[$taskMethod]){$taskCheck.reason_code='WINDOWS_FVE_PROVIDER_UNAVAILABLE';return $taskCheck}
        }
        $taskCheck.status='preflight_ready';$taskCheck.exit_code=0;$taskCheck.reason_code='READ_ONLY_CHECKS_PASSED';$taskCheck.eligible=$true
    }catch{$taskCheck.status='failed';$taskCheck.exit_code=1;$taskCheck.reason_code='PREFLIGHT_QUERY_FAILED';$taskCheck['exception_type']=$_.Exception.GetType().FullName}
    return $taskCheck
}
function Get-ValidatedVolumeGuidRoot([string]$taskRoot,[string]$taskExpectedRoot=''){
    $taskPrefix='\\?\Volume{';$taskSuffix='}\'
    if(-not$taskRoot.StartsWith($taskPrefix,[StringComparison]::OrdinalIgnoreCase)-or-not$taskRoot.EndsWith($taskSuffix,[StringComparison]::Ordinal)){throw 'VOLUME_GUID_INVALID'}
    $taskInner=$taskRoot.Substring($taskPrefix.Length,$taskRoot.Length-$taskPrefix.Length-$taskSuffix.Length);$taskGuid=[Guid]::Empty
    if(-not[Guid]::TryParse($taskInner,[ref]$taskGuid)-or$taskGuid-eq[Guid]::Empty-or$taskInner-ne$taskGuid.ToString('D')){throw 'VOLUME_GUID_INVALID'}
    if($taskExpectedRoot-and-not[string]::Equals($taskRoot,$taskExpectedRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'VOLUME_GUID_CHANGED'}
    return $taskRoot
}
function Join-FixturePayloadPath([string]$taskRoot,[string]$taskLeaf,[string]$taskExpectedRoot){
    if($taskLeaf-notin@('known-proof.bin','deleted-proof.txt')){throw 'PAYLOAD_NAME_INVALID'}
    return (Get-ValidatedVolumeGuidRoot $taskRoot $taskExpectedRoot)+$taskLeaf
}
function Assert-FixtureEncryptionStatus($taskStatus,[uint32]$taskActualMethod,[uint32]$taskExpectedMethod,$taskProtection){
    if($taskExpectedMethod-notin@(3,6)-or$taskActualMethod-ne$taskExpectedMethod){throw 'ENCRYPTION_METHOD_MISMATCH'}
    if($taskStatus.ConversionStatus-ne 1-or$taskStatus.EncryptionPercentage-ne 100){throw 'ENCRYPTION_NOT_COMPLETE'}
    if($taskProtection.ProtectionStatus-ne 1){throw 'NEW_VOLUME_PROTECTION_NOT_ON'}
}
function Close-FixtureResource($taskResource,[string]$taskName,[Collections.Generic.List[string]]$taskErrors){
    if($null-ne$taskResource){try{$taskResource.Dispose()}catch{$taskErrors.Add('DISPOSE_'+$taskName+'_FAILED')}}
}
function Stop-FixtureChild($taskChild,[Collections.Generic.List[string]]$taskErrors){
    if($null-ne$taskChild){try{if(-not$taskChild.HasExited){$taskChild.Kill();if(-not$taskChild.WaitForExit(5000)){throw 'CHILD_STILL_RUNNING'}}}catch{$taskErrors.Add('DISKPART_CLEANUP_FAILED')}}
}
function Complete-FixtureReport([Collections.IDictionary]$taskResult,[bool]$taskCaptured,[bool]$taskDetached,[string[]]$taskErrors){
    $taskResult['detached']=$taskDetached;$taskResult['cleanup_errors']=@($taskErrors);$taskResult['windows_created_complete_fixture']=$false
    if($taskErrors.Count-gt 0-or($taskCaptured-and-not$taskDetached)){$taskResult['status']='failed';$taskResult['exit_code']=1;$taskResult['reason_code']='OWN_RESOURCE_CLEANUP_FAILED'}
    elseif($taskCaptured-and$taskDetached-and$taskResult['status']-eq'captured'){$taskResult['status']='created';$taskResult['exit_code']=0;$taskResult['reason_code']='FIXTURE_CREATED';$taskResult['windows_created_complete_fixture']=$true}
    elseif($taskResult['status']-in@('created','captured')){$taskResult['status']='failed';$taskResult['exit_code']=1;$taskResult['reason_code']='FIXTURE_NOT_CAPTURED'}
}

$taskPreflight=Get-FixturePreflight
if($PreflightOnly-or-not$taskPreflight.eligible){$taskPreflight|ConvertTo-Json -Depth 6;exit ([int]$taskPreflight.exit_code)}
# No directory creation, VHD creation or mutable Windows API precedes this gate.
$taskProject=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$taskFixtureRoot=[IO.Path]::GetFullPath((Join-Path $taskProject '.build\storage-bitlocker\windows-fixture'))
if(-not $taskFixtureRoot.StartsWith((Join-Path $taskProject '.build\storage-bitlocker\'),[StringComparison]::OrdinalIgnoreCase)){throw 'WORKSPACE_BOUNDARY_INVALID'}
$taskCase=Join-Path $taskFixtureRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[Guid]::NewGuid().ToString('N'))
$taskVhd=Join-Path $taskCase 'NEW-TEST-ONLY.vhd'
$taskExpectedSize=[uint64](128MB)
$taskPublicTestPassphrase='Recovery-Test-Only-2026!Fixture#42'
$taskStage='setup';$taskCreated=$false;$taskCaseCreated=$false;$taskCaptured=$false;$taskVolumeStream=$null;$taskRawStream=$null;$taskHandle=$null;$taskProcess=$null;$taskOwnedVolumeRoot=''
$taskCleanupErrors=[Collections.Generic.List[string]]::new()
$taskReport=[ordered]@{status='failed';mode='generate';exit_code=1;reason_code='FIXTURE_NOT_CAPTURED';created_utc=[DateTime]::UtcNow.ToString('o');case=$taskCase;vhd=$taskVhd;expected_disk_bytes=$taskExpectedSize;only_new_virtual_disk=$true;real_user_devices_used=$false;policy_modified=$false;cloud_or_ad_backup=$false;secret_source='Public TEST ONLY constant in this fixture generator';requested_encryption_method=$EncryptionMethod;windows_created_complete_fixture=$false;detached=$false;preflight=$taskPreflight}

function Assert-FixturePath([string]$taskPath){
    $taskAbsolute=[IO.Path]::GetFullPath($taskPath)
    if(-not $taskAbsolute.StartsWith($taskCase+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'FIXTURE_PATH_INVALID'}
    if((Test-Path -LiteralPath $taskAbsolute)-and((Get-Item -LiteralPath $taskAbsolute -Force).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'FIXTURE_LEAF_REPARSE'}
    $taskDirectory=[IO.DirectoryInfo]([IO.Path]::GetDirectoryName($taskAbsolute))
    while($taskDirectory){if($taskDirectory.Exists-and($taskDirectory.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'FIXTURE_PARENT_REPARSE'};$taskDirectory=$taskDirectory.Parent}
    return $taskAbsolute
}
function Normalize-ImagePath([string]$taskPath){
    if($taskPath.StartsWith('\\?\')-and$taskPath.Length-gt 6-and$taskPath[5]-eq':'){$taskPath=$taskPath.Substring(4)}
    return [IO.Path]::GetFullPath($taskPath)
}
function Get-OwnedDisk{
    if(-not $taskCreated){throw 'VHD_NOT_CREATED_BY_THIS_RUN'}
    $null=Assert-FixturePath $taskVhd
    $taskImage=Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop
    if((Normalize-ImagePath $taskImage.ImagePath)-ne$taskVhd-or-not$taskImage.Attached){throw 'IMAGE_IDENTITY_INVALID'}
    $taskDisks=@($taskImage|Get-Disk -ErrorAction Stop)
    if($taskDisks.Count-ne 1){throw 'IMAGE_DISK_AMBIGUOUS'}
    $taskDisk=$taskDisks[0]
    if($taskDisk.IsBoot-or$taskDisk.IsSystem-or$taskDisk.Size-ne$taskExpectedSize){throw 'DISK_IDENTITY_INVALID'}
    $taskExpectedDevice=([string][char]92)*2+'.'+[char]92+'PhysicalDrive'+$taskDisk.Number
    if($taskImage.DevicePath-ne$taskExpectedDevice){throw 'DISK_DEVICE_IDENTITY_INVALID'}
    return $taskDisk
}
function Get-OwnedPartition{
    $taskDisk=Get-OwnedDisk
    $taskPartitions=@(Get-Partition -DiskNumber $taskDisk.Number -ErrorAction Stop)
    if($taskPartitions.Count-ne 1){throw 'PARTITION_IDENTITY_AMBIGUOUS'}
    $taskPartition=$taskPartitions[0]
    if($taskPartition.DiskNumber-ne$taskDisk.Number-or$taskPartition.IsBoot-or$taskPartition.IsSystem-or$taskPartition.Offset-ne 1MB-or$taskPartition.Size-ne($taskExpectedSize-2MB)){throw 'PARTITION_IDENTITY_INVALID'}
    return $taskPartition
}
function Get-OwnedVolume{
    $taskPartition=Get-OwnedPartition
    $taskVolumes=@($taskPartition|Get-Volume -ErrorAction Stop)
    if($taskVolumes.Count-ne 1-or$taskVolumes[0].FileSystemLabel-ne'RECOVERY_TEST_ONLY'){throw 'VOLUME_IDENTITY_INVALID'}
    return $taskVolumes[0]
}
function Get-OwnedVolumeRoot{
    $taskVolume=Get-OwnedVolume;$taskDevice=[string]$taskVolume.UniqueId
    if(-not$taskDevice){$taskDevice=[string]$taskVolume.Path}
    return Get-ValidatedVolumeGuidRoot $taskDevice $taskOwnedVolumeRoot
}
function Get-OwnedPayloadPath([string]$taskLeaf){return Join-FixturePayloadPath (Get-OwnedVolumeRoot) $taskLeaf $taskOwnedVolumeRoot}
function Write-OwnedPayload([string]$taskLeaf,[byte[]]$taskBytes){
    $taskPath=Get-OwnedPayloadPath $taskLeaf
    $taskOutput=[IO.FileStream]::new($taskPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$taskOutput.Write($taskBytes,0,$taskBytes.Length);$taskOutput.Flush($true)}finally{$taskOutput.Dispose()}
    return $taskPath
}
function Get-OwnedFve{
    $taskDevice=Get-OwnedVolumeRoot
    $taskEscaped=$taskDevice.Replace('\','\\')
    $taskFve=@(Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter ("DeviceID='"+$taskEscaped+"'") -OperationTimeoutSec 10 -ErrorAction Stop)
    if($taskFve.Count-ne 1-or$taskFve[0].DeviceID-ne$taskDevice-or$taskFve[0].VolumeType-notin@(1,2)){throw 'FVE_VOLUME_IDENTITY_INVALID'}
    return $taskFve[0]
}
function Assert-CimSuccess($taskResult,[string]$taskMethod){
    if([uint32]$taskResult.ReturnValue-ne 0){$taskReport['windows_return_code']=[uint32]$taskResult.ReturnValue;$taskReport['windows_method']=$taskMethod;throw 'WINDOWS_METHOD_REFUSED'}
}
function Copy-OwnedStream([IO.Stream]$taskInput,[uint64]$taskBytes,[string]$taskOutput){
    $taskOutput=Assert-FixturePath $taskOutput
    if(Test-Path -LiteralPath $taskOutput){throw 'OUTPUT_ALREADY_EXISTS'}
    $taskPartial=$taskOutput+'.partial'
    $taskWriter=$null;$taskDigest=$null;$taskErrorsBefore=$taskCleanupErrors.Count
    try{
        $taskWriter=[IO.FileStream]::new($taskPartial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $taskDigest=[Security.Cryptography.SHA256]::Create()
        $taskInput.Seek(0,[IO.SeekOrigin]::Begin)|Out-Null
        $taskBuffer=New-Object byte[] (1MB);[uint64]$taskDone=0
        while($taskDone-lt$taskBytes){$taskCount=[int][Math]::Min([uint64]$taskBuffer.Length,$taskBytes-$taskDone);$taskRead=$taskInput.Read($taskBuffer,0,$taskCount);if($taskRead-le 0){throw 'VIRTUAL_IMAGE_SHORT_READ'};$taskWriter.Write($taskBuffer,0,$taskRead);$taskDigest.TransformBlock($taskBuffer,0,$taskRead,$null,0)|Out-Null;$taskDone+=[uint64]$taskRead}
        $taskWriter.Flush($true);$taskDigest.TransformFinalBlock((New-Object byte[] 0),0,0)|Out-Null
        $taskHash=[BitConverter]::ToString($taskDigest.Hash).Replace('-','').ToLowerInvariant()
    }finally{Close-FixtureResource $taskWriter 'OUTPUT_STREAM' $taskCleanupErrors;Close-FixtureResource $taskDigest 'OUTPUT_DIGEST' $taskCleanupErrors}
    if($taskCleanupErrors.Count-ne$taskErrorsBefore){throw 'OUTPUT_CLOSE_FAILED'}
    [IO.File]::Move($taskPartial,$taskOutput)
    return [ordered]@{path=$taskOutput;bytes=$taskBytes;sha256=$taskHash}
}

try{
    $null=Assert-FixturePath $taskVhd
    New-Item -ItemType Directory -Path $taskFixtureRoot -Force|Out-Null
    New-Item -ItemType Directory -Path $taskCase|Out-Null;$taskCaseCreated=$true
    if(Test-Path -LiteralPath $taskVhd){throw 'NEW_VHD_PATH_ALREADY_EXISTS'}
    $null=Assert-FixturePath $taskVhd
    $taskStage='create_new_vhd'
    $taskDiskpart=Join-Path $taskCase 'create-only.txt'
    [IO.File]::WriteAllText($taskDiskpart,('create vdisk file="'+$taskVhd+'" maximum=128 type=fixed'+"`r`nexit`r`n"),[Text.Encoding]::ASCII)
    $taskProcess=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\diskpart.exe') -ArgumentList @('/s',('"'+$taskDiskpart+'"')) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $taskCase 'diskpart-create.log') -RedirectStandardError (Join-Path $taskCase 'diskpart-create.error.log')
    if(-not$taskProcess.WaitForExit(30000)){throw 'DISKPART_TIMEOUT'}
    if($taskProcess.ExitCode-ne 0-or-not(Test-Path -LiteralPath $taskVhd)){throw 'CREATE_VHD_UNAVAILABLE'}
    $taskCreated=$true
    $taskStage='attach_own_vhd';Mount-DiskImage -ImagePath $taskVhd -Access ReadWrite -NoDriveLetter -ErrorAction Stop|Out-Null
    $taskDisk=Get-OwnedDisk
    if($taskDisk.PartitionStyle-ne'RAW'){throw 'NEW_DISK_NOT_RAW'}
    $taskStage='initialize_own_disk';$taskDisk=Get-OwnedDisk;Initialize-Disk -InputObject $taskDisk -PartitionStyle MBR -ErrorAction Stop|Out-Null
    $taskStage='partition_own_disk';$taskDisk=Get-OwnedDisk;New-Partition -InputObject $taskDisk -Offset 1MB -Size ($taskExpectedSize-2MB) -ErrorAction Stop|Out-Null
    $taskStage='format_own_partition';$taskPartition=Get-OwnedPartition;Format-Volume -Partition $taskPartition -FileSystem NTFS -NewFileSystemLabel 'RECOVERY_TEST_ONLY' -Force -Confirm:$false -ErrorAction Stop|Out-Null
    $taskOwnedVolumeRoot=Get-OwnedVolumeRoot
    $taskReport['owned_volume_guid']=$taskOwnedVolumeRoot
    $taskStage='write_test_payloads'
    $taskLive=[Text.Encoding]::UTF8.GetBytes(('PUBLIC TEST ONLY '+[Guid]::NewGuid().ToString()+' '+('Known recovery content '+[char]0x03A9+' ')*180))
    $taskDeleted=[Text.Encoding]::UTF8.GetBytes('PUBLIC TEST ONLY deleted resident NTFS record: 2026 recovery fixture; not user data; verify SHA256 after undelete')
    $taskLivePath=Write-OwnedPayload 'known-proof.bin' $taskLive
    $taskDeletedPath=Write-OwnedPayload 'deleted-proof.txt' $taskDeleted
    [IO.File]::WriteAllBytes((Join-Path $taskCase 'expected-live.bin'),$taskLive);[IO.File]::WriteAllBytes((Join-Path $taskCase 'expected-deleted.txt'),$taskDeleted)
    $taskReport['expected_live_sha256']=(Get-FileHash -LiteralPath $taskLivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskReport['expected_deleted_sha256']=(Get-FileHash -LiteralPath $taskDeletedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskStage='add_test_passphrase';$taskFve=Get-OwnedFve
    $taskProtector=Invoke-CimMethod -InputObject $taskFve -MethodName ProtectKeyWithPassPhrase -Arguments @{FriendlyName='PUBLIC TEST ONLY';PassPhrase=$taskPublicTestPassphrase} -OperationTimeoutSec 10 -ErrorAction Stop
    Assert-CimSuccess $taskProtector 'ProtectKeyWithPassPhrase'
    $taskStage='encrypt_own_volume';$taskFve=Get-OwnedFve
    $taskEncrypt=Invoke-CimMethod -InputObject $taskFve -MethodName Encrypt -Arguments @{EncryptionMethod=$EncryptionMethod;EncryptionFlags=[uint32]0} -OperationTimeoutSec 10 -ErrorAction Stop
    Assert-CimSuccess $taskEncrypt 'Encrypt'
    $taskDeadline=[DateTime]::UtcNow.AddSeconds(60)
    do{
        $taskFve=Get-OwnedFve;$taskStatus=Invoke-CimMethod -InputObject $taskFve -MethodName GetConversionStatus -Arguments @{PrecisionFactor=[uint32]0} -OperationTimeoutSec 10 -ErrorAction Stop
        Assert-CimSuccess $taskStatus 'GetConversionStatus'
        if($taskStatus.ConversionStatus-eq 1){if($taskStatus.EncryptionPercentage-ne 100){throw 'ENCRYPTION_NOT_COMPLETE'};break}
        if([DateTime]::UtcNow-ge$taskDeadline){throw 'ENCRYPTION_NOT_COMPLETE_WITHIN_TEST_BUDGET'}
        Start-Sleep -Milliseconds 500
    }while($true)
    $taskReport['windows_encryption_percentage']=$taskStatus.EncryptionPercentage
    $taskReport['windows_conversion_status']=$taskStatus.ConversionStatus
    $taskFve=Get-OwnedFve;$taskProtection=Invoke-CimMethod -InputObject $taskFve -MethodName GetProtectionStatus -OperationTimeoutSec 10 -ErrorAction Stop
    Assert-CimSuccess $taskProtection 'GetProtectionStatus'
    $taskFve=Get-OwnedFve;$taskMethod=Invoke-CimMethod -InputObject $taskFve -MethodName GetEncryptionMethod -OperationTimeoutSec 10 -ErrorAction Stop
    Assert-CimSuccess $taskMethod 'GetEncryptionMethod'
    Assert-FixtureEncryptionStatus $taskStatus ([uint32]$taskMethod.EncryptionMethod) $EncryptionMethod $taskProtection
    $taskReport['actual_encryption_method']=[uint32]$taskMethod.EncryptionMethod;$taskReport['windows_protection_status']=[uint32]$taskProtection.ProtectionStatus
    $taskStage='delete_own_test_file';$taskLivePath=Get-OwnedPayloadPath 'known-proof.bin';$taskDeletedPath=Get-OwnedPayloadPath 'deleted-proof.txt'
    if((Get-FileHash -LiteralPath $taskLivePath -Algorithm SHA256).Hash.ToLowerInvariant()-ne$taskReport.expected_live_sha256){throw 'WINDOWS_LIVE_PAYLOAD_CHANGED'}
    [IO.File]::Delete($taskDeletedPath)
    if(Test-Path -LiteralPath $taskDeletedPath){throw 'TEST_FILE_NOT_DELETED'}
    $taskReport['test_file_deleted_after_full_encryption']=$true

    if(-not('RecoveryWindowsFixtureNative'-as[type])){Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class RecoveryWindowsFixtureNative{
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]public static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern bool DeviceIoControl(SafeFileHandle handle,uint code,IntPtr input,uint inputSize,IntPtr output,uint outputSize,out uint bytes,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)]public static extern bool FlushFileBuffers(SafeFileHandle handle);
}
'@}
    $taskStage='lock_owned_logical_volume';$taskVolumeDevice=(Get-OwnedVolumeRoot).TrimEnd('\')
    $taskHandle=[RecoveryWindowsFixtureNative]::CreateFile($taskVolumeDevice,[uint32]3221225472,[uint32]3,[IntPtr]::Zero,[uint32]3,[uint32]0,[IntPtr]::Zero)
    if($taskHandle.IsInvalid){throw 'NEW_VOLUME_HANDLE_UNAVAILABLE'}
    $taskVolumeStream=[IO.FileStream]::new($taskHandle,[IO.FileAccess]::Read,1MB,$false)
    $null=Get-OwnedVolume
    if(-not[RecoveryWindowsFixtureNative]::FlushFileBuffers($taskHandle)){throw 'NEW_VOLUME_FLUSH_UNAVAILABLE'}
    [uint32]$taskReturned=0
    if(-not[RecoveryWindowsFixtureNative]::DeviceIoControl($taskHandle,[uint32]0x90018,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$taskReturned,[IntPtr]::Zero)){throw 'NEW_VOLUME_LOCK_UNAVAILABLE'}
    $null=Get-OwnedVolume
    if(-not[RecoveryWindowsFixtureNative]::DeviceIoControl($taskHandle,[uint32]0x90083,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$taskReturned,[IntPtr]::Zero)){throw 'EXTENDED_DASD_UNAVAILABLE'}
    $taskStage='capture_windows_plaintext_oracle';$taskPartition=Get-OwnedPartition
    $taskReport['plaintext_oracle']=Copy-OwnedStream $taskVolumeStream $taskPartition.Size (Join-Path $taskCase 'windows-plaintext-partition.dd')
    $taskStage='capture_owned_encrypted_disk';$taskDisk=Get-OwnedDisk;$taskImage=Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop
    $taskRawStream=[IO.FileStream]::new($taskImage.DevicePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite,1MB,[IO.FileOptions]::SequentialScan)
    $taskReport['encrypted_raw']=Copy-OwnedStream $taskRawStream $taskDisk.Size (Join-Path $taskCase 'windows-encrypted-disk.raw')
    $taskReport['partition_offset_bytes']=$taskPartition.Offset;$taskReport['partition_length_bytes']=$taskPartition.Size
    $taskCaptured=$true;$taskReport.status='captured'
}catch{
    $taskReport['status']='failed';$taskReport['exit_code']=1;$taskReport['stage']=$taskStage
    $taskReport['reason_code']=if($_.Exception.Message-match'^[A-Z0-9_]+$'){$_.Exception.Message}else{'WINDOWS_OPERATION_UNAVAILABLE'}
    $taskReport['exception_hresult']=$_.Exception.HResult
    $taskReport['exception_type']=$_.Exception.GetType().FullName
    if($_.Exception-is[System.Management.Automation.PipelineStoppedException]-or$_.Exception-is[OperationCanceledException]){$taskReport['status']='cancelled';$taskReport['exit_code']=3;$taskReport['reason_code']='CANCELLED'}
    elseif($taskReport.Contains('windows_return_code')-and$taskReport.windows_return_code-eq[uint32]2150695002){$taskReport['status']='unavailable';$taskReport['exit_code']=2;$taskReport['reason_code']='WINDOWS_EDITION_UNSUPPORTED'}
}finally{
    Stop-FixtureChild $taskProcess $taskCleanupErrors
    Close-FixtureResource $taskRawStream 'RAW_STREAM' $taskCleanupErrors
    Close-FixtureResource $taskVolumeStream 'VOLUME_STREAM' $taskCleanupErrors
    Close-FixtureResource $taskHandle 'VOLUME_HANDLE' $taskCleanupErrors
    Close-FixtureResource $taskProcess 'DISKPART_PROCESS' $taskCleanupErrors
    $taskDetached=$false
    if($taskCreated){
        try{
            $null=Assert-FixturePath $taskVhd;$taskImage=Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop
            if((Normalize-ImagePath $taskImage.ImagePath)-ne$taskVhd){throw 'DETACH_IDENTITY_INVALID'}
            if($taskImage.Attached){Dismount-DiskImage -ImagePath $taskVhd -ErrorAction Stop|Out-Null}
            $taskDetached=-not(Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop).Attached
            if(-not$taskDetached){throw 'OWN_VHD_STILL_ATTACHED'}
        }catch{$taskCleanupErrors.Add('OWN_VHD_DETACH_FAILED')}
    }
    Complete-FixtureReport $taskReport $taskCaptured $taskDetached $taskCleanupErrors.ToArray()
    $taskReport['vhd_created']=$taskCreated
    $taskReport['completed_utc']=[DateTime]::UtcNow.ToString('o')
    if($taskCaseCreated){
        try{
            $taskReportPath=Assert-FixturePath (Join-Path $taskCase 'windows-fixture-report.json')
            $taskJsonBytes=[Text.UTF8Encoding]::new($false).GetBytes(($taskReport|ConvertTo-Json -Depth 8))
            $taskReportWriter=[IO.FileStream]::new($taskReportPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try{$taskReportWriter.Write($taskJsonBytes,0,$taskJsonBytes.Length);$taskReportWriter.Flush($true)}finally{$taskReportWriter.Dispose()}
        }catch{$taskReport.status='failed';$taskReport.exit_code=1;$taskReport.reason_code='FIXTURE_REPORT_WRITE_FAILED';$taskReport.windows_created_complete_fixture=$false}
    }
    $taskReport|ConvertTo-Json -Depth 8
}
exit ([int]$taskReport.exit_code)
