param(
    [string]$CacheDirectory='.build/native-archives',
    [switch]$Offline
)
$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
$cache=if([IO.Path]::IsPathRooted($CacheDirectory)){[IO.Path]::GetFullPath($CacheDirectory)}else{[IO.Path]::GetFullPath((Join-Path $project $CacheDirectory))}
$buildRoot=[IO.Path]::GetFullPath((Join-Path $project '.build')).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
if(-not $cache.StartsWith($buildRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Native input cache must be under project .build.'}
$lock=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'native-recovery-packages.json') -Raw|ConvertFrom-Json
if($lock.schema-ne 1){throw 'Unknown native package lock.'}
$rows=@()
# Official HTTPS mirrors. Size and SHA512 from the package lock still identify each archive.
$cygwinMirrors = @('https://cygwin.osuosl.org/', 'https://mirror.csclub.uwaterloo.ca/cygwin/', 'https://mirrors.kernel.org/sourceware/cygwin/')
$preferredMirror = 0
foreach($entry in @($lock.packages.PSObject.Properties.Value)+@($lock.runtime_sources.PSObject.Properties.Value)){
    $rows+=@{path=$entry.path;cygwin=$true;algorithm='SHA512';sha=$entry.sha512;bytes=[long]$entry.bytes}
}
$rows+=@(
    @{path='upstream/testdisk-7.2-source.tar.bz2';uri='https://www.cgsecurity.org/testdisk-7.2.tar.bz2';algorithm='SHA256';sha='f8343be20cb4001c5d91a2e3bcd918398f00ae6d8310894a5a9f2feb813c283f';bytes=0L},
    @{path='upstream/ntfs-3g_ntfsprogs-2026.9.28.tgz';uri='https://download.tuxera.com/opensource/ntfs-3g_ntfsprogs-2026.9.28.tgz';algorithm='SHA256';sha='350d9415c59f7c3fa74e23985ad2d56423c6a168337368f672e2e362d8f295c8';bytes=1343029L},
    @{path='fixtures/ntfs.bin.gz';uri='https://media.githubusercontent.com/media/fox-it/dissect.ntfs/83f71a87e173613580eb31f64c600789f4259c20/tests/_data/ntfs.bin.gz';algorithm='SHA256';sha='cc1b5c665a80befed008b3db817325aac1555e1efe511de63203f421c2250080';bytes=908628L}
)
foreach($row in $rows){
    if([IO.Path]::IsPathRooted($row.path)-or $row.path.Contains('\')-or $row.path.Contains(':')-or ($row.path.Split('/')|Where-Object {$_-eq '..'-or $_-eq '.'-or $_-eq ''})){throw 'Unsafe native archive path.'}
    $target=[IO.Path]::GetFullPath((Join-Path $cache $row.path))
    if(-not $target.StartsWith($cache.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Native archive escaped cache.'}
    if(-not(Test-Path -LiteralPath $target)){
        if($Offline){throw ('Missing pinned input: '+$row.path)}
        New-Item -ItemType Directory -Force -Path (Split-Path $target -Parent)|Out-Null
        for($attempt=1;$attempt-le3;$attempt++){
            $pending=$target+'.'+[Guid]::NewGuid().ToString('N')+'.partial'
            $mirror = ($preferredMirror + $attempt - 1) % $cygwinMirrors.Count
            $uri = if ($row.cygwin) { $cygwinMirrors[$mirror] + $row.path } else { $row.uri }
            try{
                Write-Output ('Downloading pinned native input: '+$row.path+' (attempt '+$attempt+')')
                # Certificate verification stays enabled. Failed partials remain
                # separate; a retry cannot publish unverified or stale bytes.
                Invoke-WebRequest -Uri $uri -OutFile $pending -TimeoutSec 120 -MaximumRedirection 5
                $size=(Get-Item -LiteralPath $pending).Length
                if($size-lt 1-or $size-gt 256MB-or $row.bytes-gt 0-and $size-ne $row.bytes-or
                    (Get-FileHash -LiteralPath $pending -Algorithm $row.algorithm).Hash.ToLowerInvariant()-ne $row.sha){throw ('Native archive validation failed: '+$row.path)}
                Move-Item -LiteralPath $pending -Destination $target
                if ($row.cygwin) { $preferredMirror = $mirror }
                break
            }catch{
                $detail='Native input '+$row.path+': '+$_.Exception.Message
                if($attempt-eq3){
                    if($env:GITHUB_ACTIONS-eq'true') {Write-Output ('::error title=Native dependency restore::'+$detail.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A'))}
                    throw $detail
                }
                Write-Warning $detail
                Start-Sleep -Seconds (2*$attempt)
            }
        }
    }
    $size=(Get-Item -LiteralPath $target).Length
    if($size-lt 1-or $size-gt 256MB-or $row.bytes-gt 0-and $size-ne $row.bytes-or
        (Get-FileHash -LiteralPath $target -Algorithm $row.algorithm).Hash.ToLowerInvariant()-ne $row.sha){throw ('Cached native archive changed: '+$row.path)}
}
@{schema=1;status='native_build_inputs_verified';archives=$rows.Count;offline=[bool]$Offline;installers_run=$false;certificate_checks_disabled=$false}|
    ConvertTo-Json|Set-Content -LiteralPath (Join-Path $cache 'restore-receipt.json') -Encoding UTF8
Write-Output ('Verified native build inputs: '+$rows.Count)
exit 0
