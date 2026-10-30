$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
$taskOut=Join-Path $taskRoot ('.build\archive-text-protocol-audit-'+[Guid]::NewGuid().ToString('N'))
$taskWorker=Join-Path $taskOut 'tools\recovery-helper'
New-Item -ItemType Directory -Force -Path $taskWorker|Out-Null
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskWorker 'recovery-helper.exe')) (Join-Path $PSScriptRoot 'ArchiveTextProtocolAuditFixture.cs')
if($LASTEXITCODE-ne0){throw 'Archive protocol audit fixture build failed.'}
$taskSources=@('tests\ArchiveTextProtocolAuditTests.cs','src\Recovery\UI\ArchiveSearchPanel.cs','src\Recovery\UI\ArchiveMessageTextForm.cs','src\Recovery\Infrastructure\HelperClient.cs','src\Recovery\Infrastructure\ApplicationPaths.cs','src\Recovery\UI\Controls\UiTheme.cs','src\Recovery\UI\Controls\ModernControls.cs','src\Recovery\UI\Controls\RecoveryMotion.cs')|ForEach-Object{Join-Path $taskRoot $_}
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+(Join-Path $taskOut 'ArchiveTextProtocolAuditTests.exe')) @taskSources
if($LASTEXITCODE-ne0){throw 'Archive protocol audit build failed.'}
& (Join-Path $taskOut 'ArchiveTextProtocolAuditTests.exe')|Tee-Object -FilePath (Join-Path $PSScriptRoot 'ArchiveTextProtocolAuditTests.result.txt')
if($LASTEXITCODE-ne0){throw 'Archive protocol audit failed.'}
