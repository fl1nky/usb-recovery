param([Parameter(Mandatory)][string]$Python312,[switch]$BlockNetwork,[switch]$ManagedOnly)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$taskLayout=Get-RecoveryLayout
$taskGroup='USBRecoveryHeadless-'+[Guid]::NewGuid().ToString('N')
$taskRules=[Collections.Generic.List[string]]::new()
$taskBlockedPrograms=[Collections.Generic.List[string]]::new()
$taskResults=@();$taskFailure=$null;$taskIsolationConfirmed=$false;$taskBuilds=@()
$taskManifest=$null;$taskManifestSha=$null
$taskPython=[IO.Path]::GetFullPath($Python312)
$taskEnvPython=Join-Path $taskLayout.Root '.build\engine-env\Scripts\python.exe'
$taskHelper=Join-Path $taskLayout.Tools 'recovery-helper\recovery-helper.exe'
$taskApp=Join-Path $taskLayout.App 'USB-Recovery.exe'
$taskPrograms=@($taskPython,$taskEnvPython,$taskHelper,$taskApp)|Select-Object -Unique
$taskLogRoot=Join-Path $taskLayout.Root ('.build\headless-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $taskLogRoot -Force|Out-Null
$taskInitialOutputs=@($taskEnvPython,$taskHelper,$taskApp)|Where-Object {Test-Path -LiteralPath $_}
$taskOldPip=@{}
foreach($taskKey in 'PIP_NO_INDEX','PIP_DISABLE_PIP_VERSION_CHECK','PIP_CONFIG_FILE'){$taskOldPip[$taskKey]=[Environment]::GetEnvironmentVariable($taskKey,'Process')}

function Add-HeadlessBlockRule([string]$Program){
 if(-not $BlockNetwork){return}
 $taskRuleName=$taskGroup+'-'+$taskRules.Count
 # Register before creation so finally also catches a partially created rule.
 $taskRules.Add($taskRuleName)
 New-NetFirewallRule -Name $taskRuleName -Group $taskGroup -DisplayName 'USB Recovery headless temporary test' -Direction Outbound -Action Block -Program $Program -Profile Any -Enabled True -ErrorAction Stop|Out-Null
 $taskRule=Get-NetFirewallRule -Name $taskRuleName -PolicyStore ActiveStore -ErrorAction Stop
 $taskFilter=$taskRule|Get-NetFirewallApplicationFilter -ErrorAction Stop
 if([string]$taskRule.Enabled-ne'True'-or[string]$taskRule.Direction-ne'Outbound'-or[string]$taskRule.Action-ne'Block'-or$taskFilter.Program-ne$Program){throw 'Temporary outbound rule was not active for the requested program.'}
 $taskBlockedPrograms.Add($Program)
}

try{
 if(-not(Test-Path -LiteralPath $taskPython -PathType Leaf)){throw 'Python interpreter not found.'}
 if($env:GITHUB_ACTIONS-eq'true'-and$ManagedOnly){throw 'CI requires the complete source build; managed-only mode is for local follow-up.'}
 if($env:GITHUB_ACTIONS-eq'true'-and$taskInitialOutputs.Count){throw 'CI requires a clean checkout without previous build outputs.'}
 if($BlockNetwork){
  if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Network-isolated checks require an already elevated CI runner.'}
  if((Get-Service -Name MpsSvc -ErrorAction Stop).Status-ne'Running'){throw 'Windows Firewall service is not running.'}
  if(@(Get-NetFirewallProfile -ErrorAction Stop|Where-Object {-not $_.Enabled}).Count){throw 'Firewall profile disabled.'}
  foreach($taskProgram in $taskPrograms){Add-HeadlessBlockRule $taskProgram}
  $taskIsolationConfirmed=$true
 }
 $env:PIP_NO_INDEX='1';$env:PIP_DISABLE_PIP_VERSION_CHECK='1';$env:PIP_CONFIG_FILE='NUL'
 Push-Location $taskLayout.Root
 try{
  if(-not $ManagedOnly){
   & $taskPython (Join-Path $taskLayout.Tests 'BootstrapBuildTests.py') 2>&1|Tee-Object -FilePath (Join-Path $taskLogRoot 'bootstrap-tests.log')
   if($LASTEXITCODE-ne0){throw 'Bootstrap integrity controls failed.'}
   & (Join-Path $PSScriptRoot 'build-app.ps1') *>&1|Tee-Object -FilePath (Join-Path $taskLogRoot 'build-app.log')
   $taskBuilds+='application'
   # Mandatory source tests and the complete source/license rebuild bundle run.
   & (Join-Path $PSScriptRoot 'build-helper.ps1') -Python312 $taskPython *>&1|Tee-Object -FilePath (Join-Path $taskLogRoot 'build-helper.log')
   $taskBuilds+='helper-with-mandatory-source-tests-and-rebuild-bundle'
  }elseif(-not(Test-Path -LiteralPath $taskEnvPython -PathType Leaf)-or-not(Test-Path -LiteralPath $taskHelper -PathType Leaf)-or-not(Test-Path -LiteralPath $taskApp -PathType Leaf)){
   throw 'Managed-only mode requires an existing source-built app, helper and build interpreter.'
  }
  $taskRaidFixtures=Join-Path $taskLayout.Root ('.build\raid10-headless-'+[Guid]::NewGuid().ToString('N'))
  & $taskEnvPython (Join-Path $taskLayout.Tests 'build_raid10_fixtures.py') --destination $taskRaidFixtures 2>&1|Tee-Object -FilePath (Join-Path $taskLogRoot 'raid10-fixtures.log')
  if($LASTEXITCODE-ne0){throw 'RAID10 fixture generation failed.'}
  $taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
  # Retain compatibility attributes, especially longPathAware, while giving
  # only these ordinary-file console tests their own asInvoker execution level.
  $taskManifest=Join-Path $taskLogRoot 'headless.manifest'
  $taskManifestXml=[Xml.XmlDocument]::new();$taskManifestXml.PreserveWhitespace=$true;$taskManifestXml.XmlResolver=$null
  $taskManifestXml.Load((Join-Path $taskLayout.Source 'app.manifest'))
  $taskLevels=@($taskManifestXml.GetElementsByTagName('requestedExecutionLevel'))
  $taskLongPaths=@($taskManifestXml.GetElementsByTagName('longPathAware'))
  if($taskLevels.Count-ne1-or$taskLongPaths.Count-ne1-or$taskLongPaths[0].InnerText-ne'true'){throw 'Application manifest compatibility attributes are missing.'}
  $taskLevels[0].SetAttribute('level','asInvoker')
  $taskManifestXml.Save($taskManifest)
  $taskManifestSha=(Get-FileHash -LiteralPath $taskManifest -Algorithm SHA256).Hash.ToLowerInvariant()
  foreach($taskName in 'RaidRecoveryTests','Raid10LayoutTests','StorageWorkflowTests'){
   $taskExe=Join-Path $taskLayout.App ($taskName+'-Headless.exe')
   & $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:"+$taskManifest) /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:"+$taskApp) ("/out:"+$taskExe) (Join-Path $taskLayout.Tests ($taskName+'.cs')) (Join-Path $taskLayout.Tests 'FrameworkTarget.cs')
   if($LASTEXITCODE-ne0){throw ('Headless build failed: '+$taskName)}
   Copy-Item -LiteralPath ($taskApp+'.config') -Destination ($taskExe+'.config')
   Add-HeadlessBlockRule $taskExe
   $taskArguments=@($taskLayout.Root)
   if($taskName-eq'Raid10LayoutTests'){$taskArguments+=$taskRaidFixtures}
   & $taskExe @taskArguments 2>&1|Tee-Object -FilePath (Join-Path $taskLogRoot ($taskName+'.log'))
   if($LASTEXITCODE-ne0){throw ('Headless test failed: '+$taskName)}
   $taskResults+=$taskName
  }
 }finally{Pop-Location}
}catch{$taskFailure=[string]$_;throw}
finally{
 $taskCleanup=@();$taskRemaining=@()
 if($BlockNetwork){
  # Query without a name filter: an absent group is empty, while query failures
  # remain errors and can never be mistaken for successful removal.
  try{Get-NetFirewallRule -ErrorAction Stop|Where-Object {$_.Group-eq$taskGroup}|Remove-NetFirewallRule -ErrorAction Stop}catch{$taskCleanup+=[string]$_}
  try{$taskRemaining=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop|Where-Object {$_.Group-eq$taskGroup}|Select-Object -ExpandProperty Name)}catch{$taskCleanup+=[string]$_}
  if($taskRemaining.Count){$taskCleanup+='Temporary outbound rules remain: '+($taskRemaining-join', ')}
 }
 foreach($taskKey in $taskOldPip.Keys){[Environment]::SetEnvironmentVariable($taskKey,$taskOldPip[$taskKey],'Process')}
 $taskHashes=@{}
 foreach($taskProgram in @($taskEnvPython,$taskHelper,$taskApp)){if(Test-Path -LiteralPath $taskProgram -PathType Leaf){$taskHashes[$taskProgram]=(Get-FileHash -LiteralPath $taskProgram -Algorithm SHA256).Hash.ToLowerInvariant()}}
 $taskReceipt=[ordered]@{status=$(if($null-eq$taskFailure-and$taskCleanup.Count-eq0){'passed'}else{'failed'});mode=$(if($ManagedOnly){'managed_only_existing_build'}else{'full_source_build'});network_isolation_requested=[bool]$BlockNetwork;outbound_rules_verified=$taskIsolationConfirmed;egress_probe_performed=$false;blocked_programs=@($taskBlockedPrograms);temporary_rule_count=$taskRules.Count;remaining_rules=$taskRemaining;cleanup_confirmed=($taskCleanup.Count-eq0-and$taskRemaining.Count-eq0);initial_outputs_present=$taskInitialOutputs;builds_completed=$taskBuilds;headless_managed_suites=$taskResults;artifact_sha256=$taskHashes;headless_manifest=$taskManifest;headless_manifest_sha256=$taskManifestSha;logs=$taskLogRoot;failure=$taskFailure;cleanup_errors=$taskCleanup;gui_tests_run=$false;real_devices_tested=$false}
 $taskReceipt|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $taskLayout.Root '.build\headless-validation.json') -Encoding UTF8
 if($taskCleanup.Count){throw 'Headless firewall cleanup failed; see receipt.'}
}
