$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskOutput = Join-Path $PSScriptRoot 'TelegramUiWork'
$taskWorker = Join-Path $taskOutput 'tools\recovery-helper'
New-Item -ItemType Directory -Force -Path $taskWorker | Out-Null
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll "/out:$taskWorker\recovery-helper.exe" "$PSScriptRoot\TelegramUiProtocolFixture.cs"
if ($LASTEXITCODE -ne 0) { throw 'Fixture build failed.' }
& $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll "/out:$taskOutput\TelegramUiTests.exe" "$PSScriptRoot\TelegramUiTests.cs" "$taskRoot\src\Recovery\UI\ArchiveSearchPanel.cs" "$taskRoot\src\Recovery\UI\ArchiveMessageTextForm.cs" "$taskRoot\src\Recovery\Infrastructure\HelperClient.cs" "$taskRoot\src\Recovery\Infrastructure\ApplicationPaths.cs" "$taskRoot\src\Recovery\UI\Controls\UiTheme.cs" "$taskRoot\src\Recovery\UI\Controls\ModernControls.cs" "$taskRoot\src\Recovery\UI\Controls\RecoveryMotion.cs"
if ($LASTEXITCODE -ne 0) { throw 'UI tests build failed.' }
& "$taskOutput\TelegramUiTests.exe" | Tee-Object -FilePath "$PSScriptRoot\TelegramUiTests.result.txt"
if ($LASTEXITCODE -ne 0) { throw 'UI tests failed.' }
