param([string]$Python312='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
$ApplicationDirectory=$taskLayout.Portable
if(-not $Python312){$Python312=Join-Path $taskLayout.Root '.build\engine-env\Scripts\python.exe'}
if(-not(Test-Path -LiteralPath $Python312)){throw 'Provide -Python312 for source and evidence checks.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_fragmented_media_fixtures.py') (Join-Path $taskLayout.Root '.build\fragmented-media-tests')
if($LASTEXITCODE-ne0){throw 'Independent media fixture generation failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_fragmented_photo_fixtures.py') (Join-Path $taskLayout.Root '.build\photo-portable-fixtures')
if($LASTEXITCODE-ne0){throw 'Independent photo fixture generation failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_telegram_deleted_fixtures.py') (Join-Path $taskLayout.Root '.build\telegram-deleted-portable-fixtures')
if($LASTEXITCODE-ne0){throw 'Independent Telegram DELETE fixture generation failed.'}
foreach($taskTelegramKind in 'wal_tail','overflow'){
 $taskTelegramTarget=Join-Path $taskLayout.Root ('.build\telegram-'+$taskTelegramKind.Replace('_','-')+'-fixtures-current')
 if(-not(Test-Path -LiteralPath (Join-Path $taskTelegramTarget 'manifest.json'))){
  & $Python312 (Join-Path $taskLayout.Tests ('build_telegram_'+$taskTelegramKind+'_fixtures.py')) $taskTelegramTarget
  if($LASTEXITCODE-ne0){throw 'Independent Telegram recovery fixture generation failed.'}
 }
}
& $Python312 (Join-Path $taskLayout.Tests 'build_progressive_jpeg_fixtures.py') (Join-Path $taskLayout.Root '.build\progressive-jpeg-fixtures')
if($LASTEXITCODE-ne0){throw 'Progressive fixture generation failed.'}
$taskMdFixtures=Join-Path $taskLayout.Root '.build\raid-metadata-fixtures'
if(-not(Test-Path -LiteralPath (Join-Path $taskMdFixtures 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'build_raid_md_fixtures.py') --destination $taskMdFixtures
 if($LASTEXITCODE-ne0){throw 'Pinned MD fixture preparation failed.'}
}
$taskExt4Fixtures=Join-Path $taskLayout.Root '.build\ext4-fixtures-current'
if(-not(Test-Path -LiteralPath (Join-Path $taskExt4Fixtures 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'ext4_fixture_generator.py') --extract (Join-Path $taskLayout.Tests 'fixtures\ext4') --destination $taskExt4Fixtures
 if($LASTEXITCODE-ne0){throw 'Offline ext4 fixture extraction failed.'}
}
$taskHeapFixtures=Join-Path $taskLayout.Root '.build\telegram-heap-portable-fixtures'
if(-not(Test-Path -LiteralPath (Join-Path $taskHeapFixtures 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'build_telegram_heap_fixtures.py') $taskHeapFixtures
 if($LASTEXITCODE-ne0){throw 'Owned JVM fixture generation failed; developer JDK required for this control only.'}
}
& $Python312 (Join-Path $taskLayout.Tests 'FixtureBundleTests.py')
if($LASTEXITCODE-ne0){throw 'Offline fixture safety checks failed.'}
foreach($taskHevcKind in 'validation','recovery'){
 $taskHevcTarget=Join-Path $taskLayout.Root ('.build\hevc-'+$taskHevcKind+'-fixtures-current')
 if(-not(Test-Path -LiteralPath (Join-Path $taskHevcTarget 'manifest.json'))){
  & $Python312 (Join-Path $taskLayout.Tests 'fixture_bundle.py') extract (Join-Path $taskLayout.Tests ('fixtures\hevc-'+$taskHevcKind)) $taskHevcTarget
  if($LASTEXITCODE-ne0){throw 'HEVC offline fixture extraction failed.'}
 }
}
$taskAacTarget=Join-Path $taskLayout.Root '.build\aac-recovery-fixtures-current'
if(-not(Test-Path -LiteralPath (Join-Path $taskAacTarget 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'build_aac_recovery_fixtures.py') --extract (Join-Path $taskLayout.Tests 'fixtures\aac-islands') --destination $taskAacTarget
 if($LASTEXITCODE-ne0){throw 'AAC offline fixture extraction failed.'}
}
$taskUnitFixtures=Join-Path $taskLayout.Root '.build\media-unit-fixtures-current'
if(-not(Test-Path -LiteralPath (Join-Path $taskUnitFixtures 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'build_media_unit_fixtures.py') --extract (Join-Path $taskLayout.Tests 'fixtures\media-units') --destination $taskUnitFixtures
 if($LASTEXITCODE-ne0){throw 'Offline media-unit fixture extraction failed.'}
}
$taskScaleFixtures=Join-Path $taskLayout.Root '.build\media-scale-fixtures-01'
if(-not(Test-Path -LiteralPath (Join-Path $taskScaleFixtures 'manifest.json'))){
 $taskFfmpegRoot=Join-Path $taskLayout.Tools 'benchmarks\ffmpeg'
 $taskScaleEncoder=if(Test-Path -LiteralPath $taskFfmpegRoot){@(Get-ChildItem -LiteralPath $taskFfmpegRoot -Recurse -File -Filter ffmpeg.exe)}else{@()}
 if($taskScaleEncoder.Count-ne1){throw 'Prepare large-video fixtures with tests/build_media_scale_fixtures.py and the documented pinned developer FFmpeg.'}
 & $Python312 (Join-Path $taskLayout.Tests 'build_media_scale_fixtures.py') --destination $taskScaleFixtures --ffmpeg $taskScaleEncoder[0].FullName
 if($LASTEXITCODE-ne0){throw 'Large-video fixture generation failed.'}
}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskBaseline=Join-Path $taskLayout.App 'CommercialComparisonHarness.exe'
try {
 & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:"+(Join-Path $taskLayout.App 'USB-Recovery.exe')) ("/out:"+$taskBaseline) (Join-Path $taskLayout.Tests 'CommercialComparisonBaseline.cs')
 if($LASTEXITCODE-ne0){throw 'Comparison regression build failed.'}
 & $taskBaseline $taskLayout.Root 'CommercialComparison-after.json'
 if($LASTEXITCODE-ne0){throw 'Comparison regression failed.'}
} finally {if(Test-Path -LiteralPath $taskBaseline){Remove-Item -LiteralPath $taskBaseline}}
foreach($name in 'QualityOfflineTests.ps1','TelegramOfflineTests.ps1','UsbOfflineTests.ps1'){
 & (Join-Path $taskLayout.Tests $name) -ApplicationDirectory $ApplicationDirectory
}
& (Join-Path $taskLayout.Tests 'ArchiveTextUiTests.ps1')
& (Join-Path $taskLayout.Tests 'ArchiveTextProtocolAuditTests.ps1')
& (Join-Path $taskLayout.Tests 'MediaRangeAnchorAuditTests.ps1')
& $Python312 (Join-Path $taskLayout.Tests 'UpgradeEvidenceTests.py')
if($LASTEXITCODE-ne0){throw 'Evidence regression failed.'}
foreach($name in 'verify_upgrade_package.py','audit_oct30_package.py'){
 & $Python312 (Join-Path $taskLayout.Tests $name)
 if($LASTEXITCODE-ne0){throw ('Package verification failed: '+$name)}
}
# Refresh evidence copies only; do not rebuild or change tested runtimes.
$taskEvidenceTarget=Join-Path $ApplicationDirectory 'source\tests'
foreach($file in (Get-ChildItem -LiteralPath $taskLayout.Tests -File)){
 if($file.Name-match'(result\.txt|-validation\.json)$'-or$file.Name-in'CommercialComparison-after.json','CommercialComparison-baseline.json','October30-package-audit.json'){
  Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $taskEvidenceTarget $file.Name)
 }
}
