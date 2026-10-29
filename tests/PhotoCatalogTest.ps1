$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:"$PSScriptRoot\PhotoCatalogTests.exe" "$taskRoot\PhotoCatalog.cs" "$PSScriptRoot\PhotoCatalogTests.cs"
if ($LASTEXITCODE -ne 0) { throw 'PhotoCatalog test compilation failed.' }
& "$PSScriptRoot\PhotoCatalogTests.exe" | Tee-Object -FilePath "$PSScriptRoot\PhotoCatalogTests.log"
if ($LASTEXITCODE -ne 0) { throw 'PhotoCatalog tests failed.' }
