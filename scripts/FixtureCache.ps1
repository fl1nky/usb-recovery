function Get-RecoveryFixtureFingerprint([string]$Source,[string]$Generator){
 $manifest=Join-Path $Source 'manifest.json'
 if(-not(Test-Path -LiteralPath $manifest -PathType Leaf)){throw 'Fixture bundle manifest is missing.'}
 return (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash+':'+(Get-FileHash -LiteralPath $Generator -Algorithm SHA256).Hash
}

function Expand-RecoveryFixtureCache {
 param([string]$BuildRoot,[string]$Python,[string]$Generator,[string]$Source,[string]$Destination,[string[]]$GeneratorArguments)
 $build=[IO.Path]::GetFullPath($BuildRoot).TrimEnd('\')
 $target=[IO.Path]::GetFullPath($Destination)
 if(-not $target.StartsWith($build+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture cache must stay inside the build directory.'}
 for($parent=[IO.DirectoryInfo]$target;$null-ne$parent;$parent=$parent.Parent){
  if($parent.Exists-and($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked fixture cache paths are forbidden.'}
 }
 $fingerprint=Get-RecoveryFixtureFingerprint $Source $Generator
 $marker=Join-Path $target '.fixture-source.sha256'
 if(Test-Path -LiteralPath $target -PathType Leaf){throw 'Fixture cache destination is a file.'}
 if(Test-Path -LiteralPath $target -PathType Container){
  if((Test-Path -LiteralPath $marker -PathType Leaf)-and(Test-Path -LiteralPath (Join-Path $target 'manifest.json') -PathType Leaf)-and[IO.File]::ReadAllText($marker).Trim()-eq$fingerprint){return}
  if(@(Get-ChildItem -LiteralPath $target -Recurse -Force|Where-Object {$_.Attributes-band[IO.FileAttributes]::ReparsePoint}).Count){throw 'Linked fixture cache entries are forbidden.'}
  $history=Join-Path $build 'fixture-cache-history'
  for($parent=[IO.DirectoryInfo]$history;$null-ne$parent;$parent=$parent.Parent){
   if($parent.Exists-and($parent.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'Linked fixture history paths are forbidden.'}
  }
  New-Item -ItemType Directory -Force -Path $history|Out-Null
  $previous=[IO.Path]::GetFullPath((Join-Path $history ((Split-Path -Leaf $target)+'-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[Guid]::NewGuid().ToString('N'))))
  if(-not $previous.StartsWith($build+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture history escaped the build directory.'}
  Move-Item -LiteralPath $target -Destination $previous
 }
 & $Python $Generator @GeneratorArguments
 if($LASTEXITCODE-ne0){throw 'Pinned fixture bundle extraction failed.'}
 if((Get-RecoveryFixtureFingerprint $Source $Generator)-ne$fingerprint){throw 'Fixture source changed during extraction.'}
 if(-not(Test-Path -LiteralPath (Join-Path $target 'manifest.json') -PathType Leaf)){throw 'Fixture extraction did not publish a manifest.'}
 [IO.File]::WriteAllText($marker,$fingerprint+"`n",(New-Object Text.UTF8Encoding($false)))
}
