param([string]$OutputDirectory='')
$ErrorActionPreference='Stop'
$taskRoot=Split-Path -Parent $PSScriptRoot
if(-not$OutputDirectory){$OutputDirectory=Join-Path $taskRoot ('.build\telegram-platform-ui-'+[Guid]::NewGuid().ToString('N'))}
$taskOutput=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $taskOutput){throw 'Preserve existing Telegram platform UI evidence; select a fresh output directory.'}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskWorker=Join-Path $taskOutput 'tools\recovery-helper'
New-Item -ItemType Directory -Path $taskWorker -Force|Out-Null
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /codepage:65001 /reference:System.Web.Extensions.dll ("/out:"+(Join-Path $taskWorker 'recovery-helper.exe')) (Join-Path $PSScriptRoot 'TelegramPlatformProtocolFixture.cs')
if($LASTEXITCODE-ne0){throw 'Controlled Telegram stdin worker compilation failed.'}
$taskSources=@('tests\TelegramPlatformUiTests.cs','src\Recovery\UI\ArchiveSearchPanel.cs','src\Recovery\UI\ArchiveMessageTextForm.cs','src\Recovery\Infrastructure\HelperClient.cs','src\Recovery\Infrastructure\TelegramAnalysisService.cs','src\Recovery\Infrastructure\ApplicationPaths.cs','src\Recovery\UI\Controls\UiTheme.cs','src\Recovery\UI\Controls\ModernControls.cs','src\Recovery\UI\Controls\RecoveryMotion.cs')|ForEach-Object{Join-Path $taskRoot $_}
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /codepage:65001 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/out:"+(Join-Path $taskOutput 'TelegramPlatformUiTests.exe')) @taskSources
if($LASTEXITCODE-ne0){throw 'Telegram native UI/protocol test compilation failed.'}
& (Join-Path $taskOutput 'TelegramPlatformUiTests.exe') 2>&1|Tee-Object -FilePath (Join-Path $taskOutput 'result.log')
if($LASTEXITCODE-ne0){throw 'Telegram native UI/protocol test failed.'}
