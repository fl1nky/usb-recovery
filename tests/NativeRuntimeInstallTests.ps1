param([Parameter(Mandatory=$true)][string]$RuntimeDirectory,[string]$EvidenceDirectory='.build/native-install-tests')
$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
$source=[IO.Path]::GetFullPath($RuntimeDirectory)
$evidence=[IO.Path]::GetFullPath((Join-Path $project $EvidenceDirectory))
if(-not$evidence.StartsWith([IO.Path]::GetFullPath((Join-Path $project '.build'))+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)-or(Test-Path -LiteralPath $evidence)){throw 'Fresh .build evidence directory required.'}
New-Item -ItemType Directory -Path $evidence|Out-Null
$installer=Join-Path $project 'scripts/install-native-runtime.ps1'
$checks=0
function Check-NativeInstall([bool]$Value,[string]$Why){if(-not$Value){throw $Why};$script:checks++}
function Reject-NativeInstall([scriptblock]$Action){$rejected=$false;try{& $Action|Out-Null}catch{$rejected=$true};Check-NativeInstall $rejected 'Modified runtime was accepted.'}
$installed=Join-Path $evidence 'installed'
& $installer -RuntimeDirectory $source -Destination $installed|Out-Null
Check-NativeInstall ($LASTEXITCODE-eq 0) 'Successful installation propagated a robocopy nonzero success code.'
$expected=(Get-FileHash -LiteralPath (Join-Path $source 'ntfs_worker.exe')).Hash
Check-NativeInstall ((Get-FileHash -LiteralPath (Join-Path $installed 'ntfs_worker.exe')).Hash-eq$expected) 'Installed executable differs.'
$changed=Join-Path $evidence 'changed';Copy-Item -LiteralPath $source -Destination $changed -Recurse
$dll=Join-Path $changed 'cygz.dll';$original=[IO.File]::ReadAllBytes($dll);$damaged=[byte[]]$original.Clone();$damaged[0]=$damaged[0]-bxor 1;[IO.File]::WriteAllBytes($dll,$damaged)
Reject-NativeInstall {& $installer -RuntimeDirectory $changed -Destination $installed}
Check-NativeInstall ((Get-FileHash -LiteralPath (Join-Path $installed 'ntfs_worker.exe')).Hash-eq$expected) 'Rejected runtime replaced current executable.'
[IO.File]::WriteAllBytes($dll,$original)
$owned=Join-Path $changed 'sources/Recovery.Native/Ntfs/main.c';$originalSource=[IO.File]::ReadAllText($owned);[IO.File]::AppendAllText($owned,'changed')
Reject-NativeInstall {& $installer -RuntimeDirectory $changed -VerifyOnly}
[IO.File]::WriteAllText($owned,$originalSource,[Text.UTF8Encoding]::new($false))
$license=Join-Path $changed 'licenses/zlib-LICENSE.txt';Move-Item -LiteralPath $license -Destination ($license+'.saved')
Reject-NativeInstall {& $installer -RuntimeDirectory $changed -VerifyOnly}
Move-Item -LiteralPath ($license+'.saved') -Destination $license
$manifest=Join-Path $changed 'runtime.json';$originalManifest=[IO.File]::ReadAllText($manifest)
[IO.File]::WriteAllText($manifest,$originalManifest.Replace('ntfs_worker.exe','../ntfs_worker.exe'),[Text.UTF8Encoding]::new($false))
Reject-NativeInstall {& $installer -RuntimeDirectory $changed -VerifyOnly}
[IO.File]::WriteAllText($manifest,$originalManifest,[Text.UTF8Encoding]::new($false))
& $installer -RuntimeDirectory $changed -VerifyOnly|Out-Null
Check-NativeInstall ($LASTEXITCODE-eq 0) 'Restored candidate failed verification.'
@{status='passed';checks=$checks;scope='Actual runtime installer, binary/source/license/traversal refusal and current-install preservation';gui_tests_run=$false;real_devices_tested=$false}|
    ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
Write-Output ('PASS NativeRuntimeInstall: '+$checks+' checks')
exit 0
