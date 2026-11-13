param([string]$Python312='')
$ErrorActionPreference='Stop'
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
. (Join-Path $PSScriptRoot 'FixtureCache.ps1')
$taskLayout=Get-RecoveryLayout
$ApplicationDirectory=$taskLayout.Portable
if(-not $Python312){$Python312=Join-Path $taskLayout.Root '.build\engine-env\Scripts\python.exe'}
if(-not(Test-Path -LiteralPath $Python312)){throw 'Provide -Python312 for source and evidence checks.'}
& (Join-Path $taskLayout.Tests 'FixtureCacheTests.ps1') -Python312 $Python312
& (Join-Path $taskLayout.Tests 'OfflineEvidenceTests.ps1') -ProjectRoot $taskLayout.Root
foreach($taskBaseFixture in @(
 @('QualityFixtures\cases.json','ContentQualityFixtures.py'),
 @('DeepRecoveryWork\containers-expected.json','DeepRecoveryFixtures.py')
)){
 if(-not(Test-Path -LiteralPath (Join-Path $taskLayout.Tests $taskBaseFixture[0]) -PathType Leaf)){
  $taskBaseDirectory=Split-Path -Parent (Join-Path $taskLayout.Tests $taskBaseFixture[0])
  if(Test-Path -LiteralPath $taskBaseDirectory){throw 'Incomplete base fixture cache exists; preserve it and prepare a fresh destination before testing.'}
  & $Python312 (Join-Path $taskLayout.Tests $taskBaseFixture[1])
  if($LASTEXITCODE-ne0){throw ('Independent base fixture preparation failed: '+$taskBaseFixture[1])}
 }
}
& $Python312 (Join-Path $taskLayout.Tests 'prepare_archive_regression_fixtures.py')
if($LASTEXITCODE-ne0){throw 'Owned archive and fragmented ZIP fixture preparation failed.'}
$taskRaid10=Join-Path $taskLayout.Root '.build\raid10-layout-fixtures'
if(Test-Path -LiteralPath $taskRaid10){
 & $Python312 (Join-Path $taskLayout.Tests 'build_raid10_fixtures.py') --verify $taskRaid10
}else{
 & $Python312 (Join-Path $taskLayout.Tests 'build_raid10_fixtures.py') --destination $taskRaid10
}
if($LASTEXITCODE-ne0){throw 'RAID10 pinned fixture preparation or verification failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_fragmented_media_fixtures.py') (Join-Path $taskLayout.Root '.build\fragmented-media-tests')
if($LASTEXITCODE-ne0){throw 'Independent media fixture generation failed.'}
$taskForensicSource=Join-Path $taskLayout.Tests 'fixtures\forensic-images'
$taskForensicDestination=Join-Path $taskLayout.Root '.build\forensic-image-fixtures'
Expand-RecoveryFixtureCache -BuildRoot (Join-Path $taskLayout.Root '.build') -Python $Python312 -Generator (Join-Path $taskLayout.Tests 'prepare_forensic_image_fixtures.py') -Source $taskForensicSource -Destination $taskForensicDestination -GeneratorArguments @('--extract',$taskForensicSource,'--destination',$taskForensicDestination)
$taskCompactGenerator=Join-Path $taskLayout.Tests 'prepare_stz2_media_fixtures.py'
$taskCompactTarget=Join-Path $taskLayout.Root '.build\video-stz2-fixtures-current'
if(Test-Path -LiteralPath $taskCompactTarget){$taskCompactArguments=@('--verify',$taskCompactTarget)}else{$taskCompactArguments=@($taskCompactTarget)}
& $Python312 $taskCompactGenerator @taskCompactArguments
if($LASTEXITCODE-ne0){throw 'Compact sample-size video fixtures or independent oracle SHA binding failed.'}
$taskFmp4Generator=Join-Path $taskLayout.Tests 'prepare_fmp4_media_fixtures.py'
$taskFmp4Target=Join-Path $taskLayout.Root '.build\fmp4-fixtures-current'
if(Test-Path -LiteralPath $taskFmp4Target){$taskFmp4Arguments=@('--verify',$taskFmp4Target)}else{$taskFmp4Arguments=@($taskFmp4Target)}
& $Python312 $taskFmp4Generator @taskFmp4Arguments
if($LASTEXITCODE-ne0){throw 'Indexed native fMP4 fixture or source/oracle SHA binding failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_jpeg_two_gap_portable_fixtures.py') (Join-Path $taskLayout.Root '.build\jpeg-two-gap-portable-fixtures')
if($LASTEXITCODE-ne0){throw 'Independent two-gap JPEG fixture generation failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_fragmented_photo_fixtures.py') (Join-Path $taskLayout.Root '.build\photo-portable-fixtures')
if($LASTEXITCODE-ne0){throw 'Independent photo fixture generation failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'prepare_photo_telegram_fixtures.py')
if($LASTEXITCODE-ne0){throw 'Independent PNG/Telegram profile fixture preparation or SHA binding failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'prepare_png_two_gap_fixtures.py')
if($LASTEXITCODE-ne0){throw 'Independent PNG two-gap fixture preparation or SHA binding failed.'}
$taskDocumentGenerator=Join-Path $taskLayout.Tests 'build_telegram_document_portable_fixtures.py'
$taskDocumentTarget=Join-Path $taskLayout.Root '.build\telegram-document-fixtures-current'
if(Test-Path -LiteralPath (Join-Path $taskDocumentTarget 'manifest.json') -PathType Leaf){
 & $Python312 $taskDocumentGenerator --verify $taskDocumentTarget
}else{
 if(Test-Path -LiteralPath $taskDocumentTarget){throw 'Incomplete Telegram document fixtures exist; preserve that directory and prepare a fresh destination. No existing files were changed.'}
 & $Python312 $taskDocumentGenerator $taskDocumentTarget
}
if($LASTEXITCODE-ne0){throw 'Independent Telegram document fixtures or source/oracle SHA binding failed.'}
& $Python312 (Join-Path $taskLayout.Tests 'build_telegram_deleted_fixtures.py') (Join-Path $taskLayout.Root '.build\telegram-deleted-portable-fixtures')
if($LASTEXITCODE-ne0){throw 'Independent Telegram DELETE fixture generation failed.'}
$taskMediaCacheGenerator=Join-Path $taskLayout.Tests 'build_telegram_media_cache_fixtures.py'
$taskMediaCacheGeneratorHash=(Get-FileHash -LiteralPath $taskMediaCacheGenerator -Algorithm SHA256).Hash.ToLowerInvariant()
$taskMediaCacheBuild=[IO.Path]::GetFullPath((Join-Path $taskLayout.Root '.build')).TrimEnd('\')
$taskMediaCacheTarget=[IO.Path]::GetFullPath((Join-Path $taskMediaCacheBuild 'telegram-media-cache-fixtures-current'))
if(-not $taskMediaCacheTarget.StartsWith($taskMediaCacheBuild+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Telegram media cache fixtures must stay inside .build.'}
for($taskMediaCacheParent=[IO.DirectoryInfo]$taskMediaCacheTarget;$null-ne$taskMediaCacheParent;$taskMediaCacheParent=$taskMediaCacheParent.Parent){
 if($taskMediaCacheParent.Exists-and($taskMediaCacheParent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked Telegram media cache fixture paths are forbidden.'}
}
$taskMediaCacheManifest=Join-Path $taskMediaCacheTarget 'manifest.json'
if(-not(Test-Path -LiteralPath $taskMediaCacheManifest -PathType Leaf)){
 if(Test-Path -LiteralPath $taskMediaCacheTarget){throw 'Incomplete Telegram media cache fixtures exist at .build\telegram-media-cache-fixtures-current; preserve that directory under a distinct .build path and prepare a fresh current destination before testing. No files were moved or deleted.'}
 & $Python312 $taskMediaCacheGenerator $taskMediaCacheTarget
 if($LASTEXITCODE-ne0){throw 'Independent Telegram media cache SQLite/WAL fixture generation failed.'}
}
if((Get-FileHash -LiteralPath $taskMediaCacheGenerator -Algorithm SHA256).Hash.ToLowerInvariant()-ne$taskMediaCacheGeneratorHash){throw 'Telegram media cache generator changed during fixture preparation.'}
if(-not(Test-Path -LiteralPath $taskMediaCacheManifest -PathType Leaf)){throw 'Telegram media cache generation did not publish its manifest.'}
if((Get-Item -LiteralPath $taskMediaCacheManifest).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'Linked Telegram media cache fixture manifests are forbidden.'}
$taskMediaCacheReceipt=Get-Content -LiteralPath $taskMediaCacheManifest -Raw -Encoding UTF8|ConvertFrom-Json
if($taskMediaCacheReceipt.generator_sha256-cne$taskMediaCacheGeneratorHash){throw 'Telegram media cache fixtures at .build\telegram-media-cache-fixtures-current belong to another or unrecorded generator; preserve that directory under a distinct .build path and prepare a fresh current destination before testing. No files were moved or deleted.'}
$taskMediaCacheNames=@('current','history','missing-preimage','corrupt-wal','wrong-schema','wrong-type','mid-mismatch','uid-mismatch','date-mismatch','unknown-flags','missing-media','secret-uid','primary-current','primary-historical','primary-different','repeated-history','metadata-only-edit')
$taskMediaCacheCases=@($taskMediaCacheReceipt.cases)
if($taskMediaCacheReceipt.schema-ne1-or$taskMediaCacheReceipt.source_commit-cne'4de548e79fed27f1a66fbdff84223321838fe925'-or-not($taskMediaCacheReceipt.independent_sqlite_writer-is[bool])-or$taskMediaCacheReceipt.independent_sqlite_writer-ne$true-or$taskMediaCacheCases.Count-ne17-or@($taskMediaCacheCases.variant|Select-Object -Unique).Count-ne17-or@(Compare-Object $taskMediaCacheNames @($taskMediaCacheCases.variant)).Count){throw 'Telegram media cache fixture manifest must contain exactly the seventeen current independent controls.'}
foreach($taskMediaCacheCase in $taskMediaCacheCases){
 if($taskMediaCacheCase.database-cne($taskMediaCacheCase.variant+'/cache4.db')){throw 'Unexpected Telegram media cache database path.'}
 $taskMediaCacheFolder=Join-Path $taskMediaCacheTarget $taskMediaCacheCase.variant
 if(-not(Test-Path -LiteralPath $taskMediaCacheFolder -PathType Container)-or((Get-Item -LiteralPath $taskMediaCacheFolder).Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Missing or linked Telegram media cache fixture directory.'}
 $taskMediaCacheSourceFiles=@($taskMediaCacheCase.source_files.PSObject.Properties)
 if(-not($taskMediaCacheSourceFiles.Name-ccontains'cache4.db')){throw 'Telegram media cache fixture has no declared source database hash.'}
 foreach($taskMediaCacheSourceFile in $taskMediaCacheSourceFiles){
  if($taskMediaCacheSourceFile.Name-cnotin'cache4.db','cache4.db-wal','cache4.db-shm'-or$taskMediaCacheSourceFile.Value-cnotmatch'\A[a-f0-9]{64}\z'){throw 'Unexpected Telegram media cache source hash entry.'}
  $taskMediaCacheSourcePath=Join-Path $taskMediaCacheFolder $taskMediaCacheSourceFile.Name
  if(-not(Test-Path -LiteralPath $taskMediaCacheSourcePath -PathType Leaf)-or((Get-Item -LiteralPath $taskMediaCacheSourcePath).Attributes-band[IO.FileAttributes]::ReparsePoint)-or(Get-FileHash -LiteralPath $taskMediaCacheSourcePath -Algorithm SHA256).Hash.ToLowerInvariant()-cne$taskMediaCacheSourceFile.Value){throw 'Telegram media cache fixture DB/WAL/SHM is missing, linked or changed; preserve existing evidence and prepare a fresh corpus.'}
 }
}
foreach($taskTelegramKind in 'wal_tail','overflow'){
 $taskTelegramTarget=Join-Path $taskLayout.Root ('.build\telegram-'+$taskTelegramKind.Replace('_','-')+'-fixtures-current')
 if(-not(Test-Path -LiteralPath (Join-Path $taskTelegramTarget 'manifest.json'))){
  & $Python312 (Join-Path $taskLayout.Tests ('build_telegram_'+$taskTelegramKind+'_fixtures.py')) $taskTelegramTarget
  if($LASTEXITCODE-ne0){throw 'Independent Telegram recovery fixture generation failed.'}
 }
}
$taskRollbackContextGenerator=Join-Path $taskLayout.Tests 'build_telegram_rollback_context_fixtures.py'
$taskRollbackContextTarget=Join-Path $taskLayout.Root '.build\telegram-rollback-context-fixtures-current'
$taskRollbackContextManifest=Join-Path $taskRollbackContextTarget 'manifest.json'
if(-not(Test-Path -LiteralPath $taskRollbackContextManifest)){
 if(Test-Path -LiteralPath $taskRollbackContextTarget){throw 'Incomplete rollback context fixture cache exists; preserve it and prepare a fresh destination before testing.'}
 & $Python312 $taskRollbackContextGenerator $taskRollbackContextTarget
 if($LASTEXITCODE-ne0){throw 'Native SQLite copied-phone/ZIP/generic rollback context fixture generation failed.'}
}
$taskRollbackContextReceipt=Get-Content -LiteralPath $taskRollbackContextManifest -Raw -Encoding UTF8|ConvertFrom-Json
if($taskRollbackContextReceipt.generator_sha256-ne(Get-FileHash -LiteralPath $taskRollbackContextGenerator -Algorithm SHA256).Hash.ToLowerInvariant()){
 throw 'Rollback context fixture cache belongs to another generator; preserve old fixtures and prepare the current corpus before testing.'
}
$taskRollbackGenerator=Join-Path $taskLayout.Tests 'build_telegram_rollback_fixtures.py'
$taskRollbackGeneratorHash=(Get-FileHash -LiteralPath $taskRollbackGenerator -Algorithm SHA256).Hash.ToLowerInvariant()
foreach($taskRollbackKind in 'normal','overflow'){
 $taskRollbackName=if($taskRollbackKind-eq'overflow'){'telegram-rollback-overflow-fixtures-current'}else{'telegram-rollback-fixtures-current'}
 $taskRollbackTarget=Join-Path $taskLayout.Root ('.build\'+$taskRollbackName)
 $taskRollbackManifest=Join-Path $taskRollbackTarget 'manifest.json'
 if(-not(Test-Path -LiteralPath $taskRollbackManifest)){
  if(Test-Path -LiteralPath $taskRollbackTarget){throw 'Incomplete rollback fixture cache exists; preserve it and prepare a fresh destination before testing.'}
  $taskRollbackArguments=@($taskRollbackGenerator,$taskRollbackTarget)
  if($taskRollbackKind-eq'overflow'){$taskRollbackArguments+='--overflow'}
  & $Python312 @taskRollbackArguments
  if($LASTEXITCODE-ne0){throw 'Native SQLite rollback fixture generation failed.'}
 }
 $taskRollbackReceipt=Get-Content -LiteralPath $taskRollbackManifest -Raw -Encoding UTF8|ConvertFrom-Json
 if($taskRollbackReceipt.generator_sha256-ne$taskRollbackGeneratorHash){throw 'Rollback fixture cache belongs to another generator; preserve old fixtures and prepare the current corpus before testing.'}
 & $Python312 (Join-Path $taskLayout.Tests 'audit_telegram_rollback_fixtures.py') --corpus $taskRollbackTarget
 if($LASTEXITCODE-ne0){throw 'Independent rollback before-image/coverage verification failed.'}
 if($taskRollbackKind-eq'overflow'){
  $taskRollbackChainReceipt=Join-Path $taskLayout.Root ('.build\telegram-rollback-overflow-proof-'+[Guid]::NewGuid().ToString('N')+'.json')
  & $Python312 (Join-Path $taskLayout.Tests 'audit_telegram_rollback_overflow.py') --corpus $taskRollbackTarget --out $taskRollbackChainReceipt
  if($LASTEXITCODE-ne0){throw 'Independent native rollback overflow-chain verification failed.'}
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
$taskExt4Source=Join-Path $taskLayout.Tests 'fixtures\ext4'
Expand-RecoveryFixtureCache -BuildRoot (Join-Path $taskLayout.Root '.build') -Python $Python312 -Generator (Join-Path $taskLayout.Tests 'ext4_fixture_generator.py') -Source $taskExt4Source -Destination $taskExt4Fixtures -GeneratorArguments @('--extract',$taskExt4Source,'--destination',$taskExt4Fixtures)
$taskRefsFixtures=Join-Path $taskLayout.Root '.build\refs-fixtures-current'
$taskRefsSource=Join-Path $taskLayout.Tests 'fixtures\refs'
Expand-RecoveryFixtureCache -BuildRoot (Join-Path $taskLayout.Root '.build') -Python $Python312 -Generator (Join-Path $taskLayout.Tests 'refs_fixture_generator.py') -Source $taskRefsSource -Destination $taskRefsFixtures -GeneratorArguments @('--extract',$taskRefsSource,'--destination',$taskRefsFixtures)
$taskRaidCtrlFixtures=Join-Path $taskLayout.Root '.build\raid-controller-fixtures-current'
$taskRaidCtrlSource=Join-Path $taskLayout.Tests 'fixtures\raid-controller'
Expand-RecoveryFixtureCache -BuildRoot (Join-Path $taskLayout.Root '.build') -Python $Python312 -Generator (Join-Path $taskLayout.Tests 'raid_controller_fixture_generator.py') -Source $taskRaidCtrlSource -Destination $taskRaidCtrlFixtures -GeneratorArguments @('--extract',$taskRaidCtrlSource,$taskRaidCtrlFixtures)
$taskApfsFixtures=Join-Path $taskLayout.Root '.build\apfs-fixtures-current'
$taskApfsSource=Join-Path $taskLayout.Tests 'fixtures\apfs-salvage'
Expand-RecoveryFixtureCache -BuildRoot (Join-Path $taskLayout.Root '.build') -Python $Python312 -Generator (Join-Path $taskLayout.Tests 'apfs_salvage_fixture_generator.py') -Source $taskApfsSource -Destination $taskApfsFixtures -GeneratorArguments @('--extract',$taskApfsSource,'--destination',$taskApfsFixtures)
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
$taskLargeJpegTarget=Join-Path $taskLayout.Root '.build\jpeg-large-portable-fixtures'
if(-not(Test-Path -LiteralPath (Join-Path $taskLargeJpegTarget 'manifest.json'))){
 & $Python312 (Join-Path $taskLayout.Tests 'build_large_jpeg_fixtures.py') $taskLargeJpegTarget
 if($LASTEXITCODE-ne0){throw 'Independent large JPEG fixture preparation failed.'}
}
$taskBframeTarget=Join-Path $taskLayout.Root '.build\video-bframes-fixtures'
if(Test-Path -LiteralPath $taskBframeTarget){$taskBframeArguments=@('--verify',$taskBframeTarget)}else{$taskBframeArguments=@($taskBframeTarget)}
& $Python312 (Join-Path $taskLayout.Tests 'prepare_bframe_media_fixtures.py') @taskBframeArguments
if($LASTEXITCODE-ne0){throw 'Native B-frame fixture preparation or pinned hashes failed.'}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskBaseline=Join-Path $taskLayout.App 'CommercialComparisonHarness.exe'
try {
 & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ ("/win32manifest:"+(Join-Path $taskLayout.Source 'app.manifest')) /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:"+(Join-Path $taskLayout.App 'USB-Recovery.exe')) ("/out:"+$taskBaseline) (Join-Path $taskLayout.Tests 'CommercialComparisonBaseline.cs') (Join-Path $taskLayout.Tests 'FrameworkTarget.cs')
 if($LASTEXITCODE-ne0){throw 'Comparison regression build failed.'}
 Copy-Item -LiteralPath (Join-Path $taskLayout.App 'USB-Recovery.exe.config') -Destination ($taskBaseline+'.config')
 $taskPreviousCompatLayer=$env:__COMPAT_LAYER
 try {
  $env:__COMPAT_LAYER='RunAsInvoker'
  & $taskBaseline $taskLayout.Root 'CommercialComparison-after.json'
  if($LASTEXITCODE-ne0){throw 'Comparison regression failed.'}
 } finally {
  $env:__COMPAT_LAYER=$taskPreviousCompatLayer
 }
} finally {foreach($taskFile in @($taskBaseline,($taskBaseline+'.config'))){if(Test-Path -LiteralPath $taskFile){Remove-Item -LiteralPath $taskFile}}}
foreach($name in 'QualityOfflineTests.ps1','TelegramOfflineTests.ps1','UsbOfflineTests.ps1'){
 & (Join-Path $taskLayout.Tests $name) -ApplicationDirectory $ApplicationDirectory
}
& $Python312 (Join-Path $taskLayout.Tests 'prepare_archive_regression_fixtures.py') --verify
if($LASTEXITCODE-ne0){throw 'Immutable archive fixture inputs changed during packaged recovery tests.'}
& (Join-Path $taskLayout.Tests 'ArchiveTextUiTests.ps1')
& (Join-Path $taskLayout.Tests 'ArchiveTextProtocolAuditTests.ps1')
& (Join-Path $taskLayout.Tests 'TelegramRollbackUiTests.ps1')
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
