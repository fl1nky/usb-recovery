$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/SourceTests.ps1')
$taskTemporary = Join-Path ([IO.Path]::GetTempPath()) ('owned-source-registry-' + [Guid]::NewGuid().ToString('N'))
$taskRegistry = Join-Path $taskTemporary 'registry.json'
$taskFixtures = Join-Path $taskTemporary 'tests'
$taskChecks = 0

function Write-TestRegistry($Entries, $Schema = 1) {
    @{schema = $Schema; tests = @($Entries)} | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $taskRegistry -Encoding UTF8
}

function Assert-RegistryRejected($Entries, $Schema = 1) {
    Write-TestRegistry $Entries $Schema
    $rejected = $false
    try { Get-RecoverySourceTests -Root $taskTemporary -Manifest $taskRegistry | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Invalid source registry was accepted.' }
    $script:taskChecks++
}

try {
    New-Item -ItemType Directory -Path $taskFixtures -Force | Out-Null
    'fixture' | Set-Content -LiteralPath (Join-Path $taskFixtures 'FirstTests.py')
    'fixture' | Set-Content -LiteralPath (Join-Path $taskFixtures 'SecondTests.py')
    $first = @{file = 'FirstTests.py'; suite = 'quick'}
    $second = @{file = 'SecondTests.py'; suite = 'full'}
    Write-TestRegistry @($first, $second)
    $full = @(Get-RecoverySourceTests -Root $taskTemporary -Manifest $taskRegistry)
    $quick = @(Get-RecoverySourceTests -Suite Quick -Root $taskTemporary -Manifest $taskRegistry)
    if ($full.Count -ne 2 -or $quick.Count -ne 1 -or $quick[0] -ne 'FirstTests.py') { throw 'Suite selection changed.' }
    $taskChecks++

    Assert-RegistryRejected @($first, @{file = 'firstTests.py'; suite = 'full'})
    Assert-RegistryRejected @(@{file = '../FirstTests.py'; suite = 'quick'})
    Assert-RegistryRejected @(@{file = 'MissingTests.py'; suite = 'full'})
    Assert-RegistryRejected @(@{file = 'FirstTests.py'; suite = 'optional'})
    Assert-RegistryRejected @($first) 2
    Assert-RegistryRejected @()
    Write-TestRegistry @($first, @{file = 'MissingTests.py'; suite = 'full'})
    $rejected = $false
    try { Get-RecoverySourceTests -Suite Quick -Root $taskTemporary -Manifest $taskRegistry | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Quick mode hid a missing mandatory full test.' }
    $taskChecks++
    Write-Output ('Source registry: ' + $taskChecks + ' checks passed; no tests executed by discovery.')
}
finally {
    # This is the fixed, task-owned directory created above, never a registry path.
    $taskResolved = [IO.Path]::GetFullPath($taskTemporary)
    $taskParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($taskResolved.StartsWith($taskParent, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($taskResolved).StartsWith('owned-source-registry-')) {
        Remove-Item -LiteralPath $taskResolved -Recurse -Force
    }
}
