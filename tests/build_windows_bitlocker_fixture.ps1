# Creates and encrypts ONE NEW disposable virtual disk, never an existing disk.
# TEST ONLY PUBLIC PASSPHRASE: Recovery-Test-Only-2026!Fixture#42
# No policy edits, TPM changes, auto-unlock, AD/cloud backups or driver installs.
# Microsoft API references:
# https://learn.microsoft.com/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
# https://learn.microsoft.com/windows/win32/secprov/encrypt-win32-encryptablevolume
[CmdletBinding()]
param([ValidateSet(3,6)][uint32]$EncryptionMethod=6)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$taskProject=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$taskFixtureRoot=[IO.Path]::GetFullPath((Join-Path $taskProject '.build\storage-bitlocker\windows-fixture'))
if(-not $taskFixtureRoot.StartsWith((Join-Path $taskProject '.build\storage-bitlocker\'),[StringComparison]::OrdinalIgnoreCase)){throw 'WORKSPACE_BOUNDARY_INVALID'}
New-Item -ItemType Directory -Path $taskFixtureRoot -Force|Out-Null
$taskCase=Join-Path $taskFixtureRoot ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskCase|Out-Null
$taskVhd=Join-Path $taskCase 'NEW-TEST-ONLY.vhd'
$taskMount=Join-Path $taskCase 'mount'
$taskExpectedSize=[uint64](128MB)
$taskPublicTestPassphrase='Recovery-Test-Only-2026!Fixture#42'
$taskStage='preflight';$taskCreated=$false;$taskVolumeStream=$null;$taskRawStream=$null
$taskReport=[ordered]@{status='started';created_utc=[DateTime]::UtcNow.ToString('o');case=$taskCase;vhd=$taskVhd;expected_disk_bytes=$taskExpectedSize;only_new_virtual_disk=$true;real_user_devices_used=$false;policy_modified=$false;cloud_or_ad_backup=$false;secret_source='Public TEST ONLY constant in this fixture generator';requested_encryption_method=$EncryptionMethod;detached=$false}

function Assert-FixturePath([string]$taskPath){
    $taskAbsolute=[IO.Path]::GetFullPath($taskPath)
    if(-not $taskAbsolute.StartsWith($taskCase+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'FIXTURE_PATH_INVALID'}
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
function Get-OwnedFve{
    $taskVolume=Get-OwnedVolume
    $taskDevice=$taskVolume.UniqueId
    if(-not $taskDevice){$taskDevice=$taskVolume.Path}
    $taskGuidPrefix=([string][char]92)*2+'?'+[char]92+'Volume{'
    $taskGuidSuffix='}'+[char]92
    if(-not$taskDevice.StartsWith($taskGuidPrefix)-or-not$taskDevice.EndsWith($taskGuidSuffix)){throw 'VOLUME_GUID_INVALID'}
    $taskGuid=[Guid]::Empty;if(-not[Guid]::TryParse($taskDevice.Substring($taskGuidPrefix.Length,$taskDevice.Length-$taskGuidPrefix.Length-$taskGuidSuffix.Length),[ref]$taskGuid)){throw 'VOLUME_GUID_INVALID'}
    $taskEscaped=$taskDevice.Replace('\','\\')
    $taskFve=@(Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter ("DeviceID='"+$taskEscaped+"'") -ErrorAction Stop)
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
    $taskWriter=[IO.FileStream]::new($taskPartial,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    $taskDigest=[Security.Cryptography.SHA256]::Create()
    try{
        $taskInput.Seek(0,[IO.SeekOrigin]::Begin)|Out-Null
        $taskBuffer=New-Object byte[] (1MB);[uint64]$taskDone=0
        while($taskDone-lt$taskBytes){$taskCount=[int][Math]::Min([uint64]$taskBuffer.Length,$taskBytes-$taskDone);$taskRead=$taskInput.Read($taskBuffer,0,$taskCount);if($taskRead-le 0){throw 'VIRTUAL_IMAGE_SHORT_READ'};$taskWriter.Write($taskBuffer,0,$taskRead);$taskDigest.TransformBlock($taskBuffer,0,$taskRead,$null,0)|Out-Null;$taskDone+=[uint64]$taskRead}
        $taskWriter.Flush($true);$taskDigest.TransformFinalBlock((New-Object byte[] 0),0,0)|Out-Null
        $taskHash=[BitConverter]::ToString($taskDigest.Hash).Replace('-','').ToLowerInvariant()
    }finally{$taskWriter.Dispose();$taskDigest.Dispose()}
    [IO.File]::Move($taskPartial,$taskOutput)
    return [ordered]@{path=$taskOutput;bytes=$taskBytes;sha256=$taskHash}
}

try{
    if(-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'ADMIN_REQUIRED'}
    foreach($taskCommand in 'Get-DiskImage','Mount-DiskImage','Initialize-Disk','New-Partition','Format-Volume','Add-PartitionAccessPath'){if(-not(Get-Command $taskCommand -ErrorAction SilentlyContinue)){throw 'WINDOWS_STORAGE_UNAVAILABLE'}}
    if(Test-Path -LiteralPath $taskVhd){throw 'NEW_VHD_PATH_ALREADY_EXISTS'}
    $null=Assert-FixturePath $taskVhd
    $taskStage='create_new_vhd'
    $taskDiskpart=Join-Path $taskCase 'create-only.txt'
    [IO.File]::WriteAllText($taskDiskpart,('create vdisk file="'+$taskVhd+'" maximum=128 type=fixed'+"`r`nexit`r`n"),[Text.Encoding]::ASCII)
    $taskProcess=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\diskpart.exe') -ArgumentList @('/s',('"'+$taskDiskpart+'"')) -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $taskCase 'diskpart-create.log') -RedirectStandardError (Join-Path $taskCase 'diskpart-create.error.log')
    if($taskProcess.ExitCode-ne 0-or-not(Test-Path -LiteralPath $taskVhd)){throw 'CREATE_VHD_UNAVAILABLE'}
    $taskCreated=$true
    $taskStage='attach_own_vhd';Mount-DiskImage -ImagePath $taskVhd -Access ReadWrite -NoDriveLetter -ErrorAction Stop|Out-Null
    $taskDisk=Get-OwnedDisk
    if($taskDisk.PartitionStyle-ne'RAW'){throw 'NEW_DISK_NOT_RAW'}
    $taskStage='initialize_own_disk';$taskDisk=Get-OwnedDisk;Initialize-Disk -InputObject $taskDisk -PartitionStyle MBR -ErrorAction Stop|Out-Null
    $taskStage='partition_own_disk';$taskDisk=Get-OwnedDisk;New-Partition -InputObject $taskDisk -Offset 1MB -Size ($taskExpectedSize-2MB) -ErrorAction Stop|Out-Null
    $taskStage='format_own_partition';$taskPartition=Get-OwnedPartition;Format-Volume -Partition $taskPartition -FileSystem NTFS -NewFileSystemLabel 'RECOVERY_TEST_ONLY' -Force -Confirm:$false -ErrorAction Stop|Out-Null
    New-Item -ItemType Directory -Path $taskMount|Out-Null
    $taskStage='mount_own_partition';$taskPartition=Get-OwnedPartition;Add-PartitionAccessPath -InputObject $taskPartition -AccessPath ($taskMount+'\') -ErrorAction Stop
    $taskVolume=Get-OwnedVolume
    $taskStage='write_test_payloads'
    $taskLive=[Text.Encoding]::UTF8.GetBytes(('PUBLIC TEST ONLY '+[Guid]::NewGuid().ToString()+' '+('Known recovery content '+[char]0x03A9+' ')*180))
    $taskDeleted=[Text.Encoding]::UTF8.GetBytes('PUBLIC TEST ONLY deleted resident NTFS record: 2026 recovery fixture; not user data; verify SHA256 after undelete')
    $taskLivePath=Join-Path $taskMount 'known-proof.bin';$taskDeletedPath=Join-Path $taskMount 'deleted-proof.txt'
    $null=Get-OwnedVolume;[IO.File]::WriteAllBytes($taskLivePath,$taskLive);[IO.File]::WriteAllBytes($taskDeletedPath,$taskDeleted)
    [IO.File]::WriteAllBytes((Join-Path $taskCase 'expected-live.bin'),$taskLive);[IO.File]::WriteAllBytes((Join-Path $taskCase 'expected-deleted.txt'),$taskDeleted)
    $taskReport['expected_live_sha256']=(Get-FileHash -LiteralPath $taskLivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskReport['expected_deleted_sha256']=(Get-FileHash -LiteralPath $taskDeletedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $taskStage='add_test_passphrase';$taskFve=Get-OwnedFve
    $taskProtector=Invoke-CimMethod -InputObject $taskFve -MethodName ProtectKeyWithPassPhrase -Arguments @{FriendlyName='PUBLIC TEST ONLY';PassPhrase=$taskPublicTestPassphrase} -ErrorAction Stop
    Assert-CimSuccess $taskProtector 'ProtectKeyWithPassPhrase'
    $taskStage='encrypt_own_volume';$taskFve=Get-OwnedFve
    $taskEncrypt=Invoke-CimMethod -InputObject $taskFve -MethodName Encrypt -Arguments @{EncryptionMethod=$EncryptionMethod;EncryptionFlags=[uint32]0} -ErrorAction Stop
    Assert-CimSuccess $taskEncrypt 'Encrypt'
    $taskDeadline=[DateTime]::UtcNow.AddSeconds(60)
    do{
        $taskFve=Get-OwnedFve;$taskStatus=Invoke-CimMethod -InputObject $taskFve -MethodName GetConversionStatus -Arguments @{PrecisionFactor=[uint32]0} -ErrorAction Stop
        Assert-CimSuccess $taskStatus 'GetConversionStatus'
        if($taskStatus.ConversionStatus-eq 1){break}
        if([DateTime]::UtcNow-ge$taskDeadline){throw 'ENCRYPTION_NOT_COMPLETE_WITHIN_TEST_BUDGET'}
        Start-Sleep -Milliseconds 500
    }while($true)
    $taskReport['windows_encryption_percentage']=$taskStatus.EncryptionPercentage
    $taskReport['windows_conversion_status']=$taskStatus.ConversionStatus
    $taskFve=Get-OwnedFve;$taskProtection=Invoke-CimMethod -InputObject $taskFve -MethodName GetProtectionStatus -ErrorAction Stop
    Assert-CimSuccess $taskProtection 'GetProtectionStatus'
    if($taskProtection.ProtectionStatus-ne 1){throw 'NEW_VOLUME_PROTECTION_NOT_ON'}
    $taskStage='delete_own_test_file';$null=Get-OwnedVolume
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
    $taskStage='lock_owned_logical_volume';$taskVolume=Get-OwnedVolume;$taskVolumeDevice=$taskVolume.UniqueId.TrimEnd('\')
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
    $taskReport['status']='created';$taskReport['windows_created_complete_fixture']=$true
}catch{
    $taskReport['status']='skipped';$taskReport['stage']=$taskStage
    $taskReport['reason_code']=if($_.Exception.Message-match'^[A-Z0-9_]+$'){$_.Exception.Message}else{'WINDOWS_OPERATION_UNAVAILABLE'}
    $taskReport['exception_hresult']=$_.Exception.HResult
    $taskReport['exception_type']=$_.Exception.GetType().FullName
}finally{
    if($taskRawStream){$taskRawStream.Dispose()};if($taskVolumeStream){$taskVolumeStream.Dispose()}
    if($taskCreated){
        try{
            $null=Assert-FixturePath $taskVhd;$taskImage=Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop
            if((Normalize-ImagePath $taskImage.ImagePath)-ne$taskVhd){throw 'DETACH_IDENTITY_INVALID'}
            if($taskImage.Attached){Dismount-DiskImage -ImagePath $taskVhd -ErrorAction Stop|Out-Null}
            $taskReport['detached']=-not(Get-DiskImage -ImagePath $taskVhd -ErrorAction Stop).Attached
        }catch{$taskReport['detached']=$false;$taskReport['detach_reason']='OWN_VHD_DETACH_FAILED'}
    }
    $taskReport['completed_utc']=[DateTime]::UtcNow.ToString('o')
    $taskReport|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $taskCase 'windows-fixture-report.json') -Encoding UTF8
    Write-Output ('Windows BitLocker fixture '+$taskReport.status+': '+$taskCase)
    if($taskReport.status-ne'created'){Write-Output ('Stage '+$taskStage+'; '+$taskReport.reason_code)}
}
