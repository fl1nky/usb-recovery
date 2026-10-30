$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
$taskRoot=$taskLayout.Root
$taskReady=$taskLayout.Portable
$taskStage=Join-Path $taskRoot ('.build\packages\stage-'+[Guid]::NewGuid().ToString('N')+'\USB-Recovery')
function Assert-RecoveryPath([string]$Path){
 $full=[IO.Path]::GetFullPath($Path)
 if(-not $full.StartsWith($taskRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Package path outside repository.'}
 for($parent=[IO.DirectoryInfo]$full;$null-ne$parent;$parent=$parent.Parent){if($parent.Exists-and($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Package path contains a link.'}}
 return $full
}
function Copy-RecoveryTree([string]$Source,[string]$Target){
 $Source=Assert-RecoveryPath $Source;$Target=Assert-RecoveryPath $Target
 if(-not(Test-Path -LiteralPath $Source -PathType Container)){throw ('Missing package source: '+$Source)}
 if(@(Get-ChildItem -LiteralPath $Source -Recurse -Force|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count){throw 'Linked package source is not allowed.'}
 New-Item -ItemType Directory -Path $Target -Force|Out-Null
 & (Join-Path $env:WINDIR 'System32\robocopy.exe') $Source $Target /E /XJ /R:1 /W:1 /MT:16 /NFL /NDL /NJH /NJS /NP /XD .git __pycache__ .pytest_cache bin obj|Out-Null
 if($LASTEXITCODE-ge8){throw 'Package copying failed.'}
}
foreach($relative in '.build\app\USB-Recovery.exe','tools\recovery-helper\recovery-helper.exe','tools\platform-tools\adb.exe','tools\testdisk-7.2\photorec_win.exe'){
 if(-not(Test-Path -LiteralPath (Join-Path $taskRoot $relative) -PathType Leaf)){throw ('Missing dependency: '+$relative)}
}
$null=Assert-RecoveryPath $taskStage
New-Item -ItemType Directory -Path $taskStage -Force|Out-Null
Copy-Item -LiteralPath (Join-Path $taskLayout.App 'USB-Recovery.exe') -Destination (Join-Path $taskStage 'USB-Recovery.exe')
Copy-Item -LiteralPath (Join-Path $taskRoot 'README.md') -Destination (Join-Path $taskStage 'README.md')
Copy-RecoveryTree (Join-Path $taskRoot 'docs') (Join-Path $taskStage 'docs')
$taskSource=Join-Path $taskStage 'source'
foreach($relative in 'src','scripts','helpers\recovery_engine','vendor\iphone-backup-decrypt','docs'){
 Copy-RecoveryTree (Join-Path $taskRoot $relative) (Join-Path $taskSource $relative)
}
Copy-Item -LiteralPath (Join-Path $taskRoot 'build.ps1') -Destination (Join-Path $taskSource 'build.ps1')
Copy-Item -LiteralPath (Join-Path $taskRoot 'README.md') -Destination (Join-Path $taskSource 'README.md')
New-Item -ItemType Directory -Path (Join-Path $taskSource 'tests') -Force|Out-Null
foreach($file in (Get-ChildItem -LiteralPath $taskLayout.Tests -File)){
 if($file.Extension-in'.cs','.py','.ps1'-or$file.Name-match'(result\.txt|-validation\.json)$'-or$file.Name-in'CommercialComparison-after.json','CommercialComparison-baseline.json','October30-package-audit.json'){
  Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $taskSource ('tests\'+$file.Name))
 }
}
foreach($relative in 'fixtures\ext4','fixtures\raid-md','benchmarks','TelegramNativeFixtures','TelegramMediaFixtures','StorageFixtures','photorec-20261011T231546120952Z\fixtures'){
 Copy-RecoveryTree (Join-Path $taskLayout.Tests $relative) (Join-Path $taskSource ('tests\'+$relative))
}
foreach($name in 'recovery-helper','testdisk-7.2'){Copy-RecoveryTree (Join-Path $taskLayout.Tools $name) (Join-Path $taskStage ('tools\'+$name))}
$taskAdb=Join-Path $taskStage 'tools\platform-tools';New-Item -ItemType Directory -Path $taskAdb -Force|Out-Null
foreach($name in 'adb.exe','AdbWinApi.dll','AdbWinUsbApi.dll','NOTICE.txt','source.properties'){Copy-Item -LiteralPath (Join-Path $taskLayout.Tools ('platform-tools\'+$name)) -Destination (Join-Path $taskAdb $name)}
$taskHashes=Get-ChildItem -LiteralPath $taskStage -Recurse -File|Where-Object {$_.Extension-in'.exe','.dll','.pyd'}|ForEach-Object{[pscustomobject]@{path=$_.FullName.Substring($taskStage.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant();bytes=$_.Length}}
$taskHashes|ConvertTo-Json -Depth 3|Set-Content -LiteralPath (Join-Path $taskStage 'package-sha256.json') -Encoding UTF8
$null=Assert-RecoveryPath $taskReady
New-Item -ItemType Directory -Path (Split-Path -Parent $taskReady) -Force|Out-Null
if(Test-Path -LiteralPath $taskReady){
 $taskPrevious=Join-Path $taskRoot ('.build\previous-packages\'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N').Substring(0,8))
 $null=Assert-RecoveryPath $taskPrevious;New-Item -ItemType Directory -Path (Split-Path -Parent $taskPrevious) -Force|Out-Null
 Move-Item -LiteralPath $taskReady -Destination $taskPrevious
}
Move-Item -LiteralPath $taskStage -Destination $taskReady
Write-Output ('Packaged: '+$taskReady)
Write-Output ('Runtime files hashed: '+@($taskHashes).Count)