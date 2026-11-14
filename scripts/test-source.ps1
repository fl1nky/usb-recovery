param(
    [Parameter(Mandatory = $true)][string]$Python312,
    [ValidateSet('Quick', 'Full')][string]$Suite = 'Quick'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'SourceTests.ps1')
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskTests = @(Get-RecoverySourceTests -Suite $Suite -Root $taskRoot)
if (-not $taskTests.Count) { throw 'The requested test suite is empty.' }

& (Join-Path $taskRoot 'tests/SourceRegistry.Tests.ps1')
foreach ($taskTest in $taskTests) {
    Write-Output ('Source check: ' + $taskTest)
    & $Python312 (Join-Path $PSScriptRoot 'run-source-test.py') (Join-Path $taskRoot ('tests/' + $taskTest))
    if ($LASTEXITCODE -ne 0) { throw ('Source regression failed: ' + $taskTest) }
}
Write-Output ('Source suite passed: ' + $Suite + ', ' + $taskTests.Count + ' programs.')
