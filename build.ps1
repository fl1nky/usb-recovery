param([ValidateSet('Build','Helper','Native','Package','Test','All')][string]$Action='Build',[string]$Python312='',[string]$NativeRuntime='',[switch]$SkipTests)
$ErrorActionPreference='Stop'
switch($Action){
 'Build' { & (Join-Path $PSScriptRoot 'scripts\build-app.ps1') }
 'Helper' { & (Join-Path $PSScriptRoot 'scripts\build-helper.ps1') -Python312 $Python312 -SkipTests:$SkipTests }
 'Native' { if(-not$NativeRuntime){throw 'Provide -NativeRuntime from scripts/build-native-recovery.py.'}; & (Join-Path $PSScriptRoot 'scripts\install-native-runtime.ps1') -RuntimeDirectory $NativeRuntime }
 'Package' { & (Join-Path $PSScriptRoot 'scripts\package.ps1') }
 'Test' { & (Join-Path $PSScriptRoot 'scripts\test.ps1') }
 'All' { if($NativeRuntime){& (Join-Path $PSScriptRoot 'scripts\install-native-runtime.ps1') -RuntimeDirectory $NativeRuntime}; & (Join-Path $PSScriptRoot 'scripts\install-native-runtime.ps1') -RuntimeDirectory (Join-Path $PSScriptRoot 'tools/native-recovery') -VerifyOnly; & (Join-Path $PSScriptRoot 'scripts\build-app.ps1'); & (Join-Path $PSScriptRoot 'scripts\build-helper.ps1') -Python312 $Python312 -SkipTests:$SkipTests; & (Join-Path $PSScriptRoot 'scripts\package.ps1'); & (Join-Path $PSScriptRoot 'scripts\test.ps1') }
}