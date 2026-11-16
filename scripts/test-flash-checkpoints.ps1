param([Parameter(Mandatory)][string]$Python312,[switch]$BlockNetwork)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
$taskRoot=$taskLayout.Root
$taskLog=Join-Path $taskRoot ('.build\flash-checkpoints-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskLog -Force|Out-Null
$taskGroup='USBRecoveryFlash-'+[Guid]::NewGuid().ToString('N')
$taskRules=[Collections.Generic.List[string]]::new()
$taskBlocked=[Collections.Generic.List[string]]::new()
$taskSuites=@();$taskFailure=$null;$taskCleanup=@();$taskStage='setup';$taskAppHash=$null
$taskOldCompatibility=[Environment]::GetEnvironmentVariable('__COMPAT_LAYER','Process')
$taskOldPip=[Environment]::GetEnvironmentVariable('PIP_NO_INDEX','Process')
$taskPython=[IO.Path]::GetFullPath($Python312)
$taskEnvPython=Join-Path $taskRoot '.build\engine-env\Scripts\python.exe'
$taskApp=Join-Path $taskLayout.App 'USB-Recovery.exe'
function Block-FlashProgram([string]$Program){
 if(-not$BlockNetwork){return}
 if($taskBlocked.Contains($Program)){return}
 $taskName=$taskGroup+'-'+$taskRules.Count;$taskRules.Add($taskName)
 New-NetFirewallRule -Name $taskName -Group $taskGroup -DisplayName 'USB Recovery flash tests' -Direction Outbound -Action Block -Program $Program -Profile Any -Enabled True -ErrorAction Stop|Out-Null
 $taskRule=Get-NetFirewallRule -Name $taskName -PolicyStore ActiveStore -ErrorAction Stop
 $taskFilter=$taskRule|Get-NetFirewallApplicationFilter -ErrorAction Stop
 if([string]$taskRule.Enabled-ne'True'-or[string]$taskRule.Action-ne'Block'-or[string]$taskRule.Direction-ne'Outbound'-or$taskFilter.Program-ne$Program){throw 'Requested program block was not active.'}
 $taskBlocked.Add($Program)
}
try{
 if($BlockNetwork){
  if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requires an already elevated CI runner; no elevation is requested.'}
  if((Get-Service MpsSvc -ErrorAction Stop).Status-ne'Running'-or@(Get-NetFirewallProfile -ErrorAction Stop|Where-Object {-not$_.Enabled}).Count){throw 'Firewall service/profiles unavailable.'}
 }
 $env:__COMPAT_LAYER='RunAsInvoker';$env:PIP_NO_INDEX='1'
 Block-FlashProgram $taskPython;Block-FlashProgram $taskEnvPython;Block-FlashProgram $taskApp
 Block-FlashProgram (Join-Path $taskLayout.Tools 'testdisk-7.2\photorec_win.exe')
 Push-Location $taskRoot
 try{
  $taskStage='prepare-environment'
  & (Join-Path $PSScriptRoot 'prepare-helper-env.ps1') -Python312 $taskPython *>&1|Tee-Object -FilePath (Join-Path $taskLog 'prepare.log')
  $taskStage='build-app'
  & (Join-Path $PSScriptRoot 'build-app.ps1') *>&1|Tee-Object -FilePath (Join-Path $taskLog 'build.log')
  $taskAppHash=(Get-FileHash -LiteralPath $taskApp).Hash.ToLowerInvariant()
  $taskLegacy=Join-Path $taskLog 'legacy-archive'
  $taskArchives=Join-Path $taskLog 'archive-checkpoints'
  & $taskEnvPython (Join-Path $taskLayout.Tests 'build_archive_salvage_fixtures.py') $taskLegacy 2>&1|Tee-Object -FilePath (Join-Path $taskLog 'legacy-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'Archive fixture generation failed.'}
  & $taskEnvPython (Join-Path $taskLayout.Tests 'build_archive_checkpoint_fixtures.py') $taskArchives 2>&1|Tee-Object -FilePath (Join-Path $taskLog 'checkpoint-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'Archive checkpoint fixtures failed.'}
  $taskFragmentedLegacy=Join-Path $taskLog 'fragmented-zip-legacy'
  $taskFragmentedCheckpoints=Join-Path $taskLog 'fragmented-zip-checkpoints'
  & $taskEnvPython (Join-Path $taskLayout.Tests 'build_fragmented_zip_fixtures.py') $taskFragmentedLegacy 2>&1|Tee-Object -FilePath (Join-Path $taskLog 'fragmented-zip-legacy-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'Fragmented ZIP legacy fixtures failed.'}
  & $taskEnvPython (Join-Path $taskLayout.Tests 'build_fragmented_zip_checkpoint_fixtures.py') $taskFragmentedCheckpoints 2>&1|Tee-Object -FilePath (Join-Path $taskLog 'fragmented-zip-checkpoint-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'Fragmented ZIP checkpoint fixtures failed.'}
  & $taskEnvPython (Join-Path $taskLayout.Tests 'DeepRecoveryFixtures.py') 2>&1|Tee-Object -FilePath (Join-Path $taskLog 'container-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'Container fixtures failed.'}
  $taskManifest=Join-Path $taskLog 'console.manifest'
  $taskXml=[Xml.XmlDocument]::new();$taskXml.PreserveWhitespace=$true;$taskXml.XmlResolver=$null
  $taskXml.Load((Join-Path $taskLayout.Source 'app.manifest'))
  $taskLevels=@($taskXml.GetElementsByTagName('requestedExecutionLevel'))
  if($taskLevels.Count-ne1-or@($taskXml.GetElementsByTagName('longPathAware')|Where-Object InnerText -eq 'true').Count-ne1){throw 'Missing compatibility attributes.'}
  $taskLevels[0].SetAttribute('level','asInvoker');$taskXml.Save($taskManifest)
  $taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
  foreach($taskName in 'ExtraPhotoTests','PartitionCheckpointTests','RangeCarverCheckpointTests','ArchiveCheckpointTests','ArchiveSalvageTests','ArchiveIoFailureTests','FragmentedZipCheckpointTests','FragmentedZipRecoveryTests','UserSignatureRecoveryTests','ContainerCarverCompatibilityTests','RecoveryContinuityTests','RecoveryRestartTests'){
   $taskStage=$taskName
   $taskExe=Join-Path $taskLayout.App ($taskName+'-Flash.exe')
   & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:"+$taskManifest) /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll ("/reference:"+$taskApp) ("/out:"+$taskExe) (Join-Path $taskLayout.Tests ($taskName+'.cs')) (Join-Path $taskLayout.Tests 'FrameworkTarget.cs')
   if($LASTEXITCODE-ne0){throw ('Compilation failed: '+$taskName)}
   Copy-Item -LiteralPath ($taskApp+'.config') -Destination ($taskExe+'.config')
   Block-FlashProgram $taskExe
   $taskArguments=@($taskRoot)
   if($taskName-eq'ArchiveCheckpointTests'){$taskArguments+=$taskArchives}
   if($taskName-eq'ArchiveSalvageTests'){$taskArguments=@($taskLegacy)}
   if($taskName-eq'FragmentedZipCheckpointTests'){$taskArguments+=$taskFragmentedCheckpoints}
   if($taskName-eq'FragmentedZipRecoveryTests'){$taskArguments=@($taskFragmentedLegacy)}
   & $taskExe @taskArguments 2>&1|Tee-Object -FilePath (Join-Path $taskLog ($taskName+'.log'))
   if($LASTEXITCODE-ne0){throw ('Focused flash test failed: '+$taskName)}
   $taskSuites+=$taskName
  }
  if((Get-FileHash -LiteralPath $taskApp).Hash.ToLowerInvariant()-ne$taskAppHash){throw 'Application changed during validation.'}
 }finally{Pop-Location}
}catch{
 $taskFailure=[string]$_
 if($env:GITHUB_ACTIONS-eq'true'){Write-Output ('::error title=Focused flash validation failed::Stage: '+$taskStage)}
 throw
}finally{
 if($BlockNetwork){
  try{Get-NetFirewallRule -ErrorAction Stop|Where-Object Group -eq $taskGroup|Remove-NetFirewallRule -ErrorAction Stop}catch{$taskCleanup+=[string]$_}
  try{if(@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object Group -eq $taskGroup).Count){$taskCleanup+='Temporary rules remain.'}}catch{$taskCleanup+=[string]$_}
 }
 [Environment]::SetEnvironmentVariable('__COMPAT_LAYER',$taskOldCompatibility,'Process')
 [Environment]::SetEnvironmentVariable('PIP_NO_INDEX',$taskOldPip,'Process')
 $taskReceipt=[ordered]@{status=$(if($null-eq$taskFailure-and$taskCleanup.Count-eq0){'passed'}else{'failed'});scope='Focused C# flash/transaction regressions; not the full source/helper/package gate';stage=$taskStage;managed_suites=$taskSuites;app_sha256=$taskAppHash;network_isolation_requested=[bool]$BlockNetwork;blocked_programs=@($taskBlocked);cleanup_confirmed=($taskCleanup.Count-eq0);cleanup_errors=$taskCleanup;egress_probe_performed=$false;gui_tests_run=$false;real_devices_tested=$false;logs=$taskLog;failure=$taskFailure}
 $taskReceipt|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $taskRoot '.build\flash-checkpoints-validation.json') -Encoding utf8
 if($taskCleanup.Count){throw 'Flash test rule cleanup failed; inspect receipt.'}
}
