# Shared repository layout for build, tests and portable packaging.
$script:RecoveryRepositoryRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Get-RecoveryLayout {
    $taskRoot=$script:RecoveryRepositoryRoot
    if(-not(Test-Path -LiteralPath (Join-Path $taskRoot 'src\Recovery\Recovery.csproj'))-and-not(Test-Path -LiteralPath (Join-Path $taskRoot 'helpers\recovery_engine\engine.py'))){throw 'Recovery source tree not found.'}
    [pscustomobject]@{
        Root=$taskRoot
        Source=(Join-Path $taskRoot 'src\Recovery')
        App=(Join-Path $taskRoot '.build\app')
        Portable=(Join-Path $taskRoot 'dist\USB-Recovery')
        Tests=(Join-Path $taskRoot 'tests')
        Tools=(Join-Path $taskRoot 'tools')
    }
}
