$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'ProjectPaths.ps1')
$layout=Get-RecoveryLayout
$app=Join-Path $layout.App 'USB-Recovery.exe'
if(-not(Test-Path -LiteralPath $app -PathType Leaf)){throw 'Build the application first.'}
$manifest=Join-Path $layout.Root '.build\benchmark-as-invoker.manifest'
$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null
$xml.Load((Join-Path $layout.Source 'app.manifest'))
$levels=@($xml.GetElementsByTagName('requestedExecutionLevel'))
if($levels.Count-ne1){throw 'Application manifest execution level missing.'}
$levels[0].SetAttribute('level','asInvoker');$xml.Save($manifest)
$exe=Join-Path $layout.App 'NativeStorageBenchmark.exe'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:exe /platform:x64 /optimize+ /warnaserror+ /codepage:65001 ("/win32manifest:"+$manifest) /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ("/reference:"+$app) ("/out:"+$exe) (Join-Path $layout.Tests 'benchmarks\NativeStorageBenchmark.cs') (Join-Path $layout.Tests 'FrameworkTarget.cs')
if($LASTEXITCODE-ne0){throw 'Benchmark driver compilation failed.'}
Copy-Item -LiteralPath ($app+'.config') -Destination ($exe+'.config')
Write-Output ('Built owned-image benchmark driver: '+$exe)
