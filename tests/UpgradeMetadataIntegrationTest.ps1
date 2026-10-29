param(
    [Parameter(Mandatory = $true)][string]$ApplicationDirectory,
    [Parameter(Mandatory = $true)][string]$Fixture,
    [Parameter(Mandatory = $true)][string]$Expected,
    [Parameter(Mandatory = $true)][ValidateSet('unaligned', 'ntfs', 'fat')][string]$Mode
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskApp = [System.IO.Path]::GetFullPath($ApplicationDirectory)
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskHarness = Join-Path $taskApp 'UpgradeMetadataIntegrationTests.exe'
try {
    & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:"$taskApp\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\UpgradeMetadataIntegrationTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Packaged integration test compilation failed.' }
    & $taskHarness $taskRoot $Fixture $Expected $Mode | Tee-Object -FilePath "$PSScriptRoot\UpgradeMetadataIntegration-$Mode.log"
    if ($LASTEXITCODE -ne 0) { throw "Packaged $Mode integration failed." }
} finally {
    if (Test-Path -LiteralPath $taskHarness) { Remove-Item -LiteralPath $taskHarness }
}
