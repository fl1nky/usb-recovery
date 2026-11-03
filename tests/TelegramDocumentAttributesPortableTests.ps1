param(
    [Parameter(Mandatory=$true)][string]$ApplicationDirectory,
    [switch]$CompileOnly,
    [string]$ExpectedHelperSha256,
    [string]$EvidenceDirectory
)
$ErrorActionPreference='Stop'
$taskProject=Split-Path -Parent $PSScriptRoot
$taskApp=[IO.Path]::GetFullPath($ApplicationDirectory)
$taskCompiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$taskSource=Join-Path $PSScriptRoot 'TelegramDocumentAttributesPortableTests.cs'
$taskPhase=Join-Path $taskProject '.build\telegram-document-attributes-portable-harness-20261103\v01'
if(-not $EvidenceDirectory){$EvidenceDirectory=Join-Path $taskPhase ('run-'+[Guid]::NewGuid().ToString('N'))}
$taskEvidence=[IO.Path]::GetFullPath($EvidenceDirectory)
if(Test-Path -LiteralPath $taskEvidence){throw 'Preserve existing evidence; choose a new output directory.'}
New-Item -ItemType Directory -Path $taskEvidence|Out-Null
$taskAppExe=Join-Path $taskApp 'USB-Recovery.exe'
if(-not(Test-Path -LiteralPath $taskAppExe -PathType Leaf)){throw 'Application dependency missing.'}
$taskCompiled=Join-Path $taskEvidence 'TelegramDocumentAttributesPortableTests.exe'
$taskHarness=Join-Path $taskApp ('TelegramDocumentAttributesPortableTests-'+[Guid]::NewGuid().ToString('N')+'-OfflineHarness.exe')
$taskSources=@($taskSource,(Join-Path $PSScriptRoot 'FrameworkTarget.cs'))
$taskBefore=@{}
foreach($taskPath in @($taskSources)+@($PSCommandPath,$taskAppExe)){$taskBefore[$taskPath]=(Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash.ToLowerInvariant()}
& $taskCompiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 "/win32manifest:$taskProject\src\Recovery\app.manifest" /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll /reference:System.IO.Compression.dll "/reference:$taskAppExe" "/main:TelegramDocumentAttributesPortableTests" "/out:$taskCompiled" @taskSources 2>&1|Set-Content -LiteralPath (Join-Path $taskEvidence 'compile.log') -Encoding UTF8
$taskCompileExit=$LASTEXITCODE
if($taskCompileExit-ne0){throw ('Portable attributes harness compile failed; exit '+$taskCompileExit)}
foreach($taskPath in $taskBefore.Keys){if((Get-FileHash -LiteralPath $taskPath -Algorithm SHA256).Hash.ToLowerInvariant()-ne$taskBefore[$taskPath]){throw 'Compile source/dependency changed.'}}
[ordered]@{schema=1;status='COMPILE_ONLY_PASS';native_compile_exit=$taskCompileExit;harness_sha256=(Get-FileHash -LiteralPath $taskCompiled -Algorithm SHA256).Hash.ToLowerInvariant();dependencies=$taskBefore;product_helper_run=$false;scope='C# static compilation only; no acceptance or recovery inferred.'}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $taskEvidence 'compile-receipt.json') -Encoding UTF8
if($CompileOnly){Write-Output ('Compiled only; no helper launched. Evidence: '+$taskEvidence);return}
. (Join-Path $PSScriptRoot 'OfflineEvidence.ps1')
$taskWorker=Join-Path $taskApp 'tools\recovery-helper\recovery-helper.exe'
if($ExpectedHelperSha256-notmatch'^[a-f0-9]{64}$'-or$ExpectedHelperSha256-eq'43f9c3a0a9947427110f509f6c8c84823872f253d45ff2197d6ec985c2669e64'-or(Get-RecoveryEvidenceHash $taskWorker)-ne$ExpectedHelperSha256){throw 'Supply the exact newly built helper SHA; old baseline helper is intentionally unsupported.'}
$taskGroup='TelegramDocumentAttributesOffline-'+[Guid]::NewGuid().ToString('N')
$taskResult=New-RecoveryOfflineEvidence $taskApp 'Independent31 native/171 controlled SQLite inputs through public C# APIs; no device/profile/network access.' $PSCommandPath
$taskOldPath=$env:PATH
$taskOldPythonHome=$env:PYTHONHOME
$taskOldPythonPath=$env:PYTHONPATH
try{
    if(@(Get-NetFirewallProfile|Where-Object {-not $_.Enabled}).Count){throw 'Firewall profiles disabled.'}
    if(Test-Path -LiteralPath $taskHarness){throw 'Preserve existing runtime harness.'}
    Copy-Item -LiteralPath $taskCompiled -Destination $taskHarness -ErrorAction Stop
    if((Get-RecoveryEvidenceHash $taskHarness)-ne(Get-RecoveryEvidenceHash $taskCompiled)){throw 'Runtime harness differs from the static compiler output.'}
    Initialize-RecoveryHarnessRuntime $taskHarness $taskApp
    foreach($taskProgram in @($taskHarness,$taskWorker,$taskAppExe)){New-NetFirewallRule -DisplayName 'Telegram attributes temporary offline check' -Name ($taskGroup+'-'+$taskResult.outbound_rules) -Group $taskGroup -Direction Outbound -Action Block -Program $taskProgram -Profile Any -Enabled True|Out-Null;$taskResult.outbound_rules++}
    $taskRules=@(Get-NetFirewallRule -Group $taskGroup)
    if($taskRules.Count-ne3-or@($taskRules|Where-Object {$_.Action-ne'Block'-or$_.Enabled-ne'True'}).Count){throw 'Required offline blocks did not activate.'}
    $env:PATH=Join-Path $env:WINDIR 'System32';$env:PYTHONHOME=$null;$env:PYTHONPATH=$null
    $taskResult.python_on_path=[bool](Get-Command python.exe -ErrorAction SilentlyContinue)
    if($taskResult.python_on_path){throw 'Python present on restricted PATH.'}
    $taskProof=New-RecoveryTestSources @($taskSource,$PSCommandPath)
    $taskLog=Join-Path $taskEvidence 'portable.result.txt'
    $taskStarted=[DateTime]::UtcNow.ToString('o')
    $taskExit=Invoke-RecoveryOfflineHarness $taskResult 'TelegramDocumentAttributesPortable' $taskHarness @($taskProject) $taskLog $taskProof
    if($taskExit-ne0){throw ('Portable attributes acceptance failed; exit '+$taskExit)}
    Add-RecoveryTestEvidence $taskResult 'TelegramDocumentAttributesPortable' $taskLog $taskHarness $taskProof $taskStarted
    $taskResult.status='passed'
}catch{$taskResult.failure=[string]$_;$taskResult.status='failed'}finally{
    $env:PATH=$taskOldPath;$env:PYTHONHOME=$taskOldPythonHome;$env:PYTHONPATH=$taskOldPythonPath
    Complete-RecoveryOfflineRun $taskResult $taskGroup @($taskHarness) (Join-Path $taskEvidence 'offline-validation.json')
}
if($taskResult.status-ne'passed'){throw ('Portable Telegram attributes validation failed: '+$taskResult.failure)}
Get-Content -LiteralPath $taskLog -Tail 1
