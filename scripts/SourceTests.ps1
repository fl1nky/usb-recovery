function Get-RecoverySourceTests {
    [CmdletBinding()]
    param(
        [ValidateSet('Quick', 'Full')][string]$Suite = 'Full',
        [string]$Root = (Split-Path -Parent $PSScriptRoot),
        [string]$Manifest = (Join-Path $PSScriptRoot 'source-tests.json')
    )

    $registry = Get-Content -LiteralPath $Manifest -Raw -ErrorAction Stop | ConvertFrom-Json
    if ($registry.schema -ne 1 -or @($registry.tests).Count -eq 0) {
        throw 'Invalid source test registry.'
    }

    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($test in $registry.tests) {
        if ($test.file -isnot [string] -or $test.file -cnotmatch '^[A-Za-z0-9]+Tests\.py$' -or
            $test.suite -cnotin @('quick', 'full') -or -not $seen.Add($test.file)) {
            throw 'Invalid or duplicate source test entry.'
        }
        if (-not (Test-Path -LiteralPath (Join-Path $Root ('tests/' + $test.file)) -PathType Leaf)) {
            throw ('Mandatory source test is missing: ' + $test.file)
        }
    }

    # Validate the whole registry before returning even the quick subset.
    foreach ($test in $registry.tests) {
        if ($Suite -eq 'Full' -or $test.suite -eq 'quick') {
            $test.file
        }
    }
}
