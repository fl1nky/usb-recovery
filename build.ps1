param([ValidateSet('Build','Helper','Package','Test','All')][string]$Action='Build',[string]$Python312='',[switch]$SkipTests)
$ErrorActionPreference='Stop'
switch($Action){
 'Build' { & (Join-Path $PSScriptRoot 'scripts\build-app.ps1') }
 'Helper' { & (Join-Path $PSScriptRoot 'scripts\build-helper.ps1') -Python312 $Python312 -SkipTests:$SkipTests }
 'Package' { & (Join-Path $PSScriptRoot 'scripts\package.ps1') }
 'Test' { & (Join-Path $PSScriptRoot 'scripts\test.ps1') }
 'All' { & (Join-Path $PSScriptRoot 'scripts\build-app.ps1'); & (Join-Path $PSScriptRoot 'scripts\build-helper.ps1') -Python312 $Python312 -SkipTests:$SkipTests; & (Join-Path $PSScriptRoot 'scripts\package.ps1'); & (Join-Path $PSScriptRoot 'scripts\test.ps1') }
}