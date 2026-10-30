$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskOut=Join-Path $taskRoot ('.build\archive-text-ui-'+[Guid]::NewGuid().ToString('N'))
$taskWorker=Join-Path $taskOut 'tools\recovery-helper'
New-Item -ItemType Directory -Force -Path $taskWorker|Out-Null
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskWorker 'recovery-helper.exe')) (Join-Path $PSScriptRoot 'ArchiveTextProtocolFixture.cs')
if($LASTEXITCODE-ne0){throw 'Archive text protocol fixture build failed.'}
$taskSources=@('tests\ArchiveTextUiTests.cs','src\Recovery\UI\ArchiveSearchPanel.cs','src\Recovery\UI\ArchiveMessageTextForm.cs','src\Recovery\Infrastructure\HelperClient.cs','src\Recovery\Infrastructure\ApplicationPaths.cs','src\Recovery\UI\Controls\UiTheme.cs','src\Recovery\UI\Controls\ModernControls.cs','src\Recovery\UI\Controls\RecoveryMotion.cs')|ForEach-Object{Join-Path $taskRoot $_}
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskOut 'ArchiveTextUiTests.exe')) @taskSources
if($LASTEXITCODE-ne0){throw 'Archive text UI test build failed.'}
& (Join-Path $taskOut 'ArchiveTextUiTests.exe')|Tee-Object -FilePath (Join-Path $PSScriptRoot 'ArchiveTextUiTests.result.txt')
if($LASTEXITCODE-ne0){throw 'Archive text UI tests failed.'}
