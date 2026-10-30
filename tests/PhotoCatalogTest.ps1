$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskTestOutput=Join-Path $taskRoot '.build\tests'
New-Item -ItemType Directory -Force -Path $taskTestOutput|Out-Null
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /out:"$taskTestOutput\PhotoCatalogTests.exe" "$taskRoot\src\Recovery\Recovery\Results\PhotoCatalog.cs" "$PSScriptRoot\PhotoCatalogTests.cs"
if ($LASTEXITCODE -ne 0) { throw 'PhotoCatalog test compilation failed.' }
& "$taskTestOutput\PhotoCatalogTests.exe" | Tee-Object -FilePath "$taskTestOutput\PhotoCatalogTests.log"
if ($LASTEXITCODE -ne 0) { throw 'PhotoCatalog tests failed.' }
