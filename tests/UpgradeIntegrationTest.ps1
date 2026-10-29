$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskHarness = Join-Path $taskRoot 'UpgradeIntegrationTests.exe'
try {
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:"$taskRoot\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\UpgradeIntegrationTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Integration test compilation failed.' }
    & $taskHarness $taskRoot | Tee-Object -FilePath "$PSScriptRoot\UpgradeIntegrationTests.log"
    if ($LASTEXITCODE -ne 0) { throw 'Integration tests failed.' }
} finally {
    if (Test-Path -LiteralPath $taskHarness) { Remove-Item -LiteralPath $taskHarness }
}
