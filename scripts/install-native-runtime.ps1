param(
    [Parameter(Mandatory=$true)][string]$RuntimeDirectory,
    [string]$Destination='tools/native-recovery',
    [switch]$VerifyOnly
)
$ErrorActionPreference='Stop'
$project=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
function Native-Path([string]$Value){
    $path=if([IO.Path]::IsPathRooted($Value)){[IO.Path]::GetFullPath($Value)}else{[IO.Path]::GetFullPath((Join-Path $project $Value))}
    if(-not $path.StartsWith($project.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Native runtime path outside project.'}
    for($parent=[IO.DirectoryInfo]$path;$null-ne$parent;$parent=$parent.Parent){if($parent.Exists-and($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked native runtime path.'}}
    if((Test-Path -LiteralPath $path)-and((Get-Item -LiteralPath $path).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked native runtime file.'}
    return $path
}
function Native-Json([string]$Root,[string]$Relative,[long]$Maximum=4MB){
    $file=Native-Path (Join-Path $Root $Relative)
    if(-not(Test-Path -LiteralPath $file -PathType Leaf)-or(Get-Item -LiteralPath $file).Length-gt$Maximum){throw ('Missing or oversized native metadata: '+$Relative)}
    return Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
}
function Native-Verify([string]$Root){
    $Root=Native-Path $Root
    if(-not(Test-Path -LiteralPath $Root -PathType Container)){throw 'Native runtime directory missing.'}
    if(@(Get-ChildItem -LiteralPath $Root -Recurse -Force|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count){throw 'Native runtime contains a link.'}
    $manifest=Native-Json $Root 'runtime.json' 64KB
    $receipt=Native-Json $Root 'build-receipt.json'
    $names=@('ntfs_worker.exe','cygwin1.dll','cygz.dll','cygiconv-2.dll','cygcharset-1.dll')
    if($manifest.Schema-ne 1-or$manifest.Profile-ne'ntfs-plan-v1'-or@($manifest.Files).Count-ne$names.Count-or
        $receipt.status-ne'native_ntfs_worker_built_from_pinned_sources'-or$receipt.profile-ne'ntfs-plan-v1'){throw 'Unknown native runtime profile.'}
    $seen=@{}
    foreach($row in $manifest.Files){
        if($row.Name-cnotin$names-or$seen.ContainsKey($row.Name)-or$row.Sha256-cnotmatch'^[0-9a-f]{64}$'){throw 'Invalid native tool binding.'}
        $file=Native-Path (Join-Path $Root $row.Name)
        if(-not(Test-Path -LiteralPath $file -PathType Leaf)-or(Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()-cne$row.Sha256){throw ('Native binary changed: '+$row.Name)}
        $bound=@($receipt.files|Where-Object {$_.Name-ceq$row.Name})
        if($bound.Count-ne 1-or$bound[0].Sha256-cne$row.Sha256){throw 'Native build receipt disagrees with runtime manifest.'}
        $seen[$row.Name]=$true
    }
    foreach($name in @('TestDisk-COPYING.txt','NTFS-3G-COPYING.txt','NTFS-3G-COPYING.LIB.txt','USB-Recovery-AGPL-3.0.txt',
        'Cygwin-CYGWIN_LICENSE.txt','Cygwin-GPL-3.0.txt','Cygwin-LGPL-3.0.txt','libiconv-libcharset-LGPL.txt','zlib-LICENSE.txt')){
        $file=Native-Path (Join-Path $Root ('licenses/'+$name));if(-not(Test-Path -LiteralPath $file -PathType Leaf)-or(Get-Item -LiteralPath $file).Length-lt 1){throw ('Missing native license: '+$name)}
    }
    $archives=@{
        'testdisk-7.2-source.tar.bz2'='f8343be20cb4001c5d91a2e3bcd918398f00ae6d8310894a5a9f2feb813c283f'
        'ntfs-3g_ntfsprogs-2026.9.28.tgz'='350d9415c59f7c3fa74e23985ad2d56423c6a168337368f672e2e362d8f295c8'
    }
    foreach($name in $archives.Keys){$file=Native-Path (Join-Path $Root ('sources/'+$name));if((Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()-cne$archives[$name]){throw 'Native upstream source changed.'}}
    $lock=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'native-recovery-packages.json') -Raw|ConvertFrom-Json
    foreach($row in $lock.runtime_sources.PSObject.Properties.Value){
        $file=Native-Path (Join-Path $Root ('sources/'+[IO.Path]::GetFileName($row.path)))
        if((Get-Item -LiteralPath $file).Length-ne$row.bytes-or(Get-FileHash -LiteralPath $file -Algorithm SHA512).Hash.ToLowerInvariant()-cne$row.sha512){throw 'Native runtime corresponding source changed.'}
    }
    foreach($row in $receipt.owned_sources.PSObject.Properties){
        if([IO.Path]::IsPathRooted($row.Name)-or$row.Name.Contains('..')-or$row.Name.Contains('\')-or$row.Name.Contains(':')){throw 'Invalid native owned source path.'}
        $file=Native-Path (Join-Path $Root ('sources/Recovery.Native/'+$row.Name))
        $current=Native-Path (Join-Path $project ('src/Recovery.Native/'+$row.Name))
        if((Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()-cne$row.Value-or(Get-FileHash -LiteralPath $current).Hash.ToLowerInvariant()-cne$row.Value){throw 'Native runtime differs from current maintained source.'}
    }
    if(@($receipt.owned_sources.PSObject.Properties).Count-lt 8){throw 'Native corresponding source inventory missing.'}
    $inventory=@{}
    foreach($file in Get-ChildItem -LiteralPath $Root -Recurse -File){$inventory[$file.FullName.Substring($Root.Length+1).Replace('\','/')]=(Get-FileHash -LiteralPath $file.FullName).Hash.ToLowerInvariant()}
    return $inventory
}
$source=Native-Path $RuntimeDirectory
$inventory=Native-Verify $source
if($VerifyOnly){Write-Output ('Verified native runtime files: '+$inventory.Count);exit 0}
$target=Native-Path $Destination
if($target-eq$source-or$source.StartsWith($target+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)-or$target.StartsWith($source+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Native runtime source and destination overlap.'}
$stage=Native-Path ('.build/native-runtime-staging/'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage|Out-Null
& (Join-Path $env:WINDIR 'System32/robocopy.exe') $source $stage /E /XJ /R:1 /W:1 /NFL /NDL /NJH /NJS /NP|Out-Null
if($LASTEXITCODE-ge 8){throw 'Native runtime staging failed.'}
$copied=Native-Verify $stage
if($copied.Count-ne$inventory.Count){throw 'Native runtime inventory changed during copying.'}
foreach($name in $inventory.Keys){if($copied[$name]-cne$inventory[$name]){throw 'Native runtime changed during copying.'}}
$previous=$null
if(Test-Path -LiteralPath $target){$previous=Native-Path ('.build/previous-native-runtimes/'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Force -Path (Split-Path $previous -Parent)|Out-Null;Move-Item -LiteralPath $target -Destination $previous}
try{New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent)|Out-Null;Move-Item -LiteralPath $stage -Destination $target}
catch{if($previous-and-not(Test-Path -LiteralPath $target)){Move-Item -LiteralPath $previous -Destination $target};throw}
Write-Output ('Installed verified native runtime: '+$target)
exit 0
