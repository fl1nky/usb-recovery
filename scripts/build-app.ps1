param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
if ($OutputDirectory) {
    $taskBuildRoot = [IO.Path]::GetFullPath((Join-Path $taskLayout.Root '.build'))
    $taskOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) { [IO.Path]::GetFullPath($OutputDirectory) } else { [IO.Path]::GetFullPath((Join-Path $taskLayout.Root $OutputDirectory)) }
    if (-not $taskOutput.StartsWith($taskBuildRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Isolated build output must stay under this checkout .build directory.' }
    $taskLayout.App = $taskOutput
}
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(-not(Test-Path -LiteralPath $taskCompiler)){throw '.NET Framework compiler not found.'}
New-Item -ItemType Directory -Force -Path $taskLayout.App|Out-Null
$taskSources=@(Get-ChildItem -LiteralPath $taskLayout.Source -Recurse -File -Filter '*.cs'|Sort-Object FullName|Select-Object -ExpandProperty FullName)
if(-not $taskSources.Count){throw 'No application sources found.'}
$taskArguments=@('/nologo','/target:winexe','/platform:x64','/optimize+','/warnaserror+','/codepage:65001',('/win32manifest:'+ (Join-Path $taskLayout.Source 'app.manifest')),'/reference:System.IO.Compression.dll','/reference:System.IO.Compression.FileSystem.dll','/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/reference:System.Runtime.WindowsRuntime.dll','/reference:System.Xaml.dll',('/reference:'+(Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF\PresentationCore.dll')),('/reference:'+(Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF\PresentationFramework.dll')),('/reference:'+(Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF\WindowsBase.dll')),('/reference:'+(Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\WPF\WindowsFormsIntegration.dll')),('/out:'+(Join-Path $taskLayout.App 'USB-Recovery.exe')))
& $taskCompiler @taskArguments @taskSources
if($LASTEXITCODE-ne 0){throw 'Application build failed.'}
Copy-Item -LiteralPath (Join-Path $taskLayout.Source 'app.config') -Destination (Join-Path $taskLayout.App 'USB-Recovery.exe.config')
Write-Output ('Built: '+(Join-Path $taskLayout.App 'USB-Recovery.exe'))
