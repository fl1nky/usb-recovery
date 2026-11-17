param(
    [Parameter(Mandatory=$true)][string]$Worker,
    [Parameter(Mandatory=$true)][string]$Fixture,
    [Parameter(Mandatory=$true)][string]$LargeFixture,
    [Parameter(Mandatory=$true)][string]$ExpectedPayload,
    [Parameter(Mandatory=$true)][string]$PipelineFixture,
    [ValidateSet('All','Integration')][string]$CaseGroup='All',
    [string]$EvidenceDirectory='.build/native-ntfs-checkpoint-evidence'
)
$ErrorActionPreference='Stop'
$project=Split-Path $PSScriptRoot -Parent
$workerPath=[IO.Path]::GetFullPath($Worker)
$fixturePath=[IO.Path]::GetFullPath($Fixture)
$largePath=[IO.Path]::GetFullPath($LargeFixture)
$expectedPath=[IO.Path]::GetFullPath($ExpectedPayload)
$pipelinePath=[IO.Path]::GetFullPath($PipelineFixture)
$evidence=if([IO.Path]::IsPathRooted($EvidenceDirectory)){[IO.Path]::GetFullPath($EvidenceDirectory)}else{Join-Path $project $EvidenceDirectory}
if(Test-Path -LiteralPath $evidence){throw 'A fresh evidence directory is required.'}
if(-not(Test-Path -LiteralPath $workerPath -PathType Leaf)-or -not(Test-Path -LiteralPath $fixturePath -PathType Leaf)){throw 'Prepared native worker and authored deletion fixture are required.'}
New-Item -ItemType Directory -Path $evidence|Out-Null
$compiler=Join-Path $env:WINDIR 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
$framework=Split-Path $compiler -Parent
$sources=@(Get-ChildItem -LiteralPath (Join-Path $project 'src/Recovery') -File -Recurse -Filter '*.cs'|Sort-Object FullName|Select-Object -ExpandProperty FullName)
$test=Join-Path $project 'tests/NativeNtfsCheckpointTests.cs'
$manifest=Join-Path $evidence 'as-invoker.manifest'
$xml=[Xml.XmlDocument]::new();$xml.PreserveWhitespace=$true;$xml.XmlResolver=$null
$xml.Load((Join-Path $project 'src/Recovery/app.manifest'))
$levels=@($xml.GetElementsByTagName('requestedExecutionLevel'))
if($levels.Count-ne 1){throw 'Missing execution level.'}
$levels[0].SetAttribute('level','asInvoker');$xml.Save($manifest)
$exe=Join-Path $evidence 'NativeNtfsCheckpointTests.exe'
$arguments=@('/nologo','/target:exe','/main:NativeNtfsCheckpointTests','/platform:x64','/optimize+','/warnaserror+','/codepage:65001',('/win32manifest:'+$manifest),('/out:'+$exe),'/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/reference:System.Runtime.WindowsRuntime.dll','/reference:System.Xaml.dll')
foreach($name in @('PresentationCore','PresentationFramework','WindowsBase','WindowsFormsIntegration')){$arguments+=('/reference:'+(Join-Path $framework ('WPF/'+$name+'.dll')))}
$inputs=@($sources)+@($test)+@(Get-ChildItem -LiteralPath (Join-Path $project 'src/Recovery.Native') -Recurse -File|Select-Object -ExpandProperty FullName)+@($PSCommandPath,(Join-Path $project 'tests/build_native_ntfs_checkpoint_fixture.py'),(Join-Path $project 'helpers/recovery_engine/ntfs_volume.py'),(Join-Path $project 'src/Recovery/app.manifest'),(Join-Path $project 'src/Recovery/app.config'))
$frozen=Join-Path $evidence 'frozen';New-Item -ItemType Directory -Path $frozen|Out-Null
$sourceManifest=@()
foreach($inputPath in $inputs){
    $relative=$inputPath.Substring($project.Length+1).Replace('\','/')
    $destination=Join-Path $frozen $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent)|Out-Null
    Copy-Item -LiteralPath $inputPath -Destination $destination
    $sha=(Get-FileHash -LiteralPath $inputPath).Hash.ToLowerInvariant()
    if((Get-FileHash -LiteralPath $destination).Hash.ToLowerInvariant()-ne $sha){throw 'Source freeze mismatch.'}
    $sourceManifest+=@{path=$relative;sha256=$sha}
}
$sourceManifest|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $evidence 'source-manifest.json') -Encoding UTF8
$bound=@($workerPath,$fixturePath,$largePath,$expectedPath,$pipelinePath)+@(Get-ChildItem -LiteralPath (Split-Path $workerPath -Parent) -File -Filter '*.dll'|Select-Object -ExpandProperty FullName)
$hashes=@{};foreach($path in $bound){$hashes[$path]=(Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()}
$compileLog=Join-Path $evidence 'compile.log';[IO.File]::WriteAllText($compileLog,'')
& $compiler @arguments @sources $test 2>&1|Tee-Object -FilePath $compileLog
if($LASTEXITCODE-ne 0){throw 'Native NTFS test compilation failed.'}
Copy-Item -LiteralPath (Join-Path $project 'src/Recovery/app.config') -Destination ($exe+'.config')
$log=Join-Path $evidence 'test.log'
& $exe (Join-Path $evidence 'cases') $workerPath $fixturePath $largePath $expectedPath $pipelinePath $CaseGroup 2>&1|Tee-Object -FilePath $log
if($LASTEXITCODE-ne 0){throw 'Native NTFS checkpoint validation failed.'}
$counts=[regex]::Matches((Get-Content -LiteralPath $log -Raw),'PASS NativeNtfsCheckpoint: (\d+) checks')
if($counts.Count-ne 1){throw 'Missing check count.'}
foreach($path in $bound){if((Get-FileHash -LiteralPath $path).Hash.ToLowerInvariant()-ne $hashes[$path]){throw 'Bound worker, dependency or fixture changed.'}}
foreach($entry in $sourceManifest){if((Get-FileHash -LiteralPath (Join-Path $project $entry.path)).Hash.ToLowerInvariant()-ne $entry.sha256){throw 'Source changed during validation.'}}
@{status='passed';scope='Native NTFS controller and real pipeline/session/catalog; not packaged acceptance';case_group=$CaseGroup;checks=[int]$counts[0].Groups[1].Value;inputs=$hashes;test_exe_sha256=(Get-FileHash -LiteralPath $exe).Hash.ToLowerInvariant();source_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $evidence 'source-manifest.json')).Hash.ToLowerInvariant();gui_tests_run=$false;real_devices_tested=$false;network_isolated=$false}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $evidence 'receipt.json') -Encoding UTF8
