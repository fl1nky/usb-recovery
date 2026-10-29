param([string]$Python312='')
$ErrorActionPreference='Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
function Build-Test([string]$Name,[string[]]$Files,[string[]]$References=@('System.Web.Extensions.dll')) {
    $taskArguments=@('/nologo','/target:exe','/platform:x64','/warnaserror+',('/out:'+(Join-Path $PSScriptRoot ($Name+'.exe'))))
    $taskArguments += $References | ForEach-Object { '/reference:'+$_ }
    $taskArguments += $Files | ForEach-Object { Join-Path $taskRoot $_ }
    & $taskCompiler @taskArguments
    if ($LASTEXITCODE -ne 0) { throw ('Compile failed: '+$Name) }
}
& (Join-Path $taskRoot 'build.ps1')
Build-Test 'HelperProtocolFixture' @('tests\HelperProtocolFixture.cs')
Build-Test 'HelperClientTests' @('HelperClient.cs','tests\HelperClientTests.cs')
Build-Test 'SourceRecoveryTests' @('RecoverySources.cs','WpdInterop.cs','tests\SourceRecoveryTests.cs')
Build-Test 'AdditionalSourceTests' @('RecoverySources.cs','AdditionalSources.cs','WpdInterop.cs','tests\AdditionalSourceTests.cs')
Build-Test 'V3UiRenderTests' @('tests\V3UiRenderTests.cs') @('System.Windows.Forms.dll','System.Drawing.dll',(Join-Path $taskRoot 'USB-Recovery.exe'))
foreach ($taskName in 'HelperClientTests','SourceRecoveryTests','AdditionalSourceTests','V3UiRenderTests') {
    & (Join-Path $PSScriptRoot ($taskName+'.exe')) | Tee-Object -FilePath (Join-Path $PSScriptRoot ($taskName+'.result.txt'))
    if ($LASTEXITCODE -ne 0) { throw ('Test failed: '+$taskName) }
}
$taskHarness=Join-Path $taskRoot 'V3PackagedIntegrationTests.exe'
try {
    & $taskCompiler /nologo /target:exe /platform:x64 /warnaserror+ /reference:System.Web.Extensions.dll /reference:"$taskRoot\USB-Recovery.exe" /out:"$taskHarness" "$PSScriptRoot\V3PackagedIntegrationTests.cs"
    if ($LASTEXITCODE -ne 0) { throw 'Packaged test compile failed' }
    & $taskHarness $taskRoot | Tee-Object -FilePath (Join-Path $PSScriptRoot 'V3PackagedIntegration.result.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Packaged test failed' }
} finally { if (Test-Path -LiteralPath $taskHarness) { Remove-Item -LiteralPath $taskHarness } }
if ($Python312) {
    foreach ($taskTest in 'EngineTests.py','ReviewEngineTests.py','PortableFormatsTests.py') {
        & $Python312 (Join-Path $PSScriptRoot $taskTest)
        if ($LASTEXITCODE -ne 0) { throw ('Python test failed: '+$taskTest) }
    }
}
