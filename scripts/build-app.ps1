$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $taskCompiler)){throw '.NET Framework compiler not found.'}
New-Item -ItemType Directory -Force -Path $taskLayout.App|Out-Null
$taskSources=@(Get-ChildItem -LiteralPath $taskLayout.Source -Recurse -File -Filter '*.cs'|Sort-Object FullName|Select-Object -ExpandProperty FullName)
if(-not $taskSources.Count){throw 'No application sources found.'}
$taskArguments=@('/nologo','/target:winexe','/platform:x64','/optimize+','/warnaserror+',('/win32manifest:'+ (Join-Path $taskLayout.Source 'app.manifest')),'/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll',('/out:'+(Join-Path $taskLayout.App 'USB-Recovery.exe')))
& $taskCompiler @taskArguments @taskSources
if($LASTEXITCODE-ne 0){throw 'Application build failed.'}
Write-Output ('Built: '+(Join-Path $taskLayout.App 'USB-Recovery.exe'))