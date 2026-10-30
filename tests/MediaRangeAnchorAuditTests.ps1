$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskOut=Join-Path $taskRoot ('.build\media-range-anchor-audit-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskOut|Out-Null
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskSources=@('tests\MediaRangeAnchorAuditTests.cs','src\Recovery\Recovery\Engines\FragmentedMediaRecovery.cs','src\Recovery\Recovery\Engines\FragmentedMediaRecovery.Units.cs','src\Recovery\Recovery\Engines\FragmentedMediaRecovery.Ranges.cs','src\Recovery\Recovery\Engines\AacSyntaxTables.cs','src\Recovery\Recovery\Engines\AacLcValidator.cs','src\Recovery\Recovery\Engines\HevcSampleValidator.cs')|ForEach-Object{Join-Path $taskRoot $_}
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskOut 'MediaRangeAnchorAuditTests.exe')) @taskSources
if($LASTEXITCODE-ne0){throw 'Media range anchor audit build failed.'}
& (Join-Path $taskOut 'MediaRangeAnchorAuditTests.exe')|Tee-Object -FilePath (Join-Path $PSScriptRoot 'MediaRangeAnchorAuditTests.result.txt')
if($LASTEXITCODE-ne0){throw 'Media range anchor audit failed.'}
