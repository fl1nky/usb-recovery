param([string]$ApplicationDirectory='', [switch]$Show)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
if(-not $ApplicationDirectory){$ApplicationDirectory=Join-Path $taskRoot '.build\app'}
$taskApp=[IO.Path]::GetFullPath($ApplicationDirectory)
$taskProgram=Join-Path $taskApp 'USB-Recovery.exe'
if(-not(Test-Path -LiteralPath $taskProgram -PathType Leaf)){throw 'Build the application first or provide -ApplicationDirectory.'}
$taskFixture=Join-Path $PSScriptRoot 'fixtures\document-media-preview\avc-aac.mp4'
if((Get-FileHash -LiteralPath $taskFixture -Algorithm SHA256).Hash.ToLowerInvariant()-ne'0e81099086a15412d54529d02244140ba12687d161e7e6cc9d17798e009ae2b9'){throw 'Controlled preview fixture SHA256 differs.'}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskHarness=Join-Path $taskApp 'DocumentMediaPreviewTests.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:"+$taskProgram) ("/out:"+$taskHarness) (Join-Path $PSScriptRoot 'DocumentMediaPreviewTests.cs') (Join-Path $PSScriptRoot 'FrameworkTarget.cs')
if($LASTEXITCODE-ne0){throw 'Preview harness build failed.'}
Copy-Item -LiteralPath (Join-Path $taskApp 'USB-Recovery.exe.config') -Destination ($taskHarness+'.config')
$taskArguments=@($taskRoot,$taskFixture)
if($Show){$taskArguments+='--show'}
& $taskHarness @taskArguments
if($LASTEXITCODE-ne0){throw 'Document/media preview focused test failed.'}
