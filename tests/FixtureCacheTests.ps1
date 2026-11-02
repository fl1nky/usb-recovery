param([string]$Python312='')
$ErrorActionPreference='Stop'
$taskProject=Split-Path -Parent $PSScriptRoot
if(-not $Python312){$Python312=Join-Path $taskProject '.build\engine-env\Scripts\python.exe'}
. (Join-Path $taskProject 'scripts\FixtureCache.ps1')
$taskRoot=Join-Path $taskProject ('.build\fixture-cache-tests-'+[Guid]::NewGuid().ToString('N'))
$taskSource=Join-Path $taskRoot 'source';$taskCache=Join-Path $taskRoot 'cache'
New-Item -ItemType Directory -Path $taskSource -Force|Out-Null
$taskManifest=Join-Path $taskSource 'manifest.json';$taskGenerator=Join-Path $taskRoot 'extract.py'
$taskUtf8=New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($taskManifest,'{"version":1}',$taskUtf8)
$taskCode=@'
from pathlib import Path
import shutil, sys
source, dest = map(Path, sys.argv[1:])
dest.mkdir(parents=True)
shutil.copyfile(source / "manifest.json", dest / "manifest.json")
with (source / "runs.txt").open("a") as out:
    out.write("run\n")
'@
[IO.File]::WriteAllText($taskGenerator,$taskCode,$taskUtf8)
function Invoke-TestExtraction {
 Expand-RecoveryFixtureCache -BuildRoot $taskRoot -Python $Python312 -Generator $taskGenerator -Source $taskSource -Destination $taskCache -GeneratorArguments @($taskSource,$taskCache)
}
Invoke-TestExtraction
if(-not(Test-Path -LiteralPath (Join-Path $taskCache '.fixture-source.sha256'))){throw 'Missing cache fingerprint.'}
Invoke-TestExtraction
if(@(Get-Content -LiteralPath (Join-Path $taskSource 'runs.txt')).Count-ne1){throw 'Unchanged cache was extracted again.'}
[IO.File]::WriteAllText($taskManifest,'{"version":2}',$taskUtf8)
Invoke-TestExtraction
if([IO.File]::ReadAllText((Join-Path $taskCache 'manifest.json'))-ne'{"version":2}'){throw 'Updated bundle reused stale cached fixtures.'}
if(@(Get-ChildItem -LiteralPath (Join-Path $taskRoot 'fixture-cache-history') -Directory).Count-ne1){throw 'Previous fixture cache was not preserved.'}
[IO.File]::AppendAllText($taskGenerator,"`n# changed generator`n",$taskUtf8)
Invoke-TestExtraction
if(@(Get-Content -LiteralPath (Join-Path $taskSource 'runs.txt')).Count-ne3){throw 'Changed generator reused stale cached fixtures.'}
$taskOutside=Join-Path (Split-Path -Parent $taskRoot) ('outside-cache-'+[Guid]::NewGuid().ToString('N'))
$taskRejected=$false
try{Expand-RecoveryFixtureCache -BuildRoot $taskRoot -Python $Python312 -Generator $taskGenerator -Source $taskSource -Destination $taskOutside -GeneratorArguments @($taskSource,$taskOutside)}catch{$taskRejected=$true}
if(-not $taskRejected-or(Test-Path -LiteralPath $taskOutside)){throw 'Outside cache destination was touched.'}
Write-Output 'PASS FixtureCache: 6 checks; fresh reuse, changed bundle/generator invalidation, previous cache preservation and outside-path rejection.'
