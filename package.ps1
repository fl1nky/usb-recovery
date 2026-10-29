$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$taskReady = [IO.Path]::GetFullPath((Join-Path $taskRoot 'Готовая программа'))
if (-not $taskReady.StartsWith($taskRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Package target outside artifact.' }
foreach ($taskRequired in 'USB-Recovery.exe','tools\recovery-helper\recovery-helper.exe','tools\platform-tools\adb.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $taskRoot $taskRequired) -PathType Leaf)) { throw "Missing packaged dependency: $taskRequired" }
}
function Copy-TaskTree([string]$Source, [string]$Target) {
    New-Item -ItemType Directory -Path $Target -Force | Out-Null
    if (@(Get-ChildItem -LiteralPath $Source -Recurse -Force | Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -gt 0) { throw 'Package sources contain reparse point.' }
    if (@(Get-ChildItem -LiteralPath $Target -Recurse -Force | Where-Object {($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0}).Count -gt 0) { throw 'Package target contains reparse point.' }
    & (Join-Path $env:WINDIR 'System32\robocopy.exe') $Source $Target /E /XJ /R:1 /W:1 /MT:16 /NFL /NDL /NJH /NJS /NP /XD .git __pycache__ .pytest_cache | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'Package copying failed.' }
}
New-Item -ItemType Directory -Path $taskReady -Force | Out-Null
# Only generated dependencies are refreshed. Archives/results are not targets.
foreach ($taskStale in 'tools\recovery-helper','tools\signal','helpers','vendor') {
    $taskStalePath = [IO.Path]::GetFullPath((Join-Path $taskReady $taskStale))
    if (-not $taskStalePath.StartsWith($taskReady.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe package cleanup target.' }
    for ($taskAncestor = [IO.DirectoryInfo]$taskStalePath; $null -ne $taskAncestor; $taskAncestor = $taskAncestor.Parent) {
        if ($taskAncestor.Exists -and ($taskAncestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Package cleanup contains reparse point.' }
    }
    if (Test-Path -LiteralPath $taskStalePath) {
        if (@(Get-ChildItem -LiteralPath $taskStalePath -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw 'Unsafe generated package tree.' }
        Remove-Item -LiteralPath $taskStalePath -Recurse -Force
    }
}
if (Test-Path -LiteralPath (Join-Path $taskReady 'build-signal-helpers.ps1')) { Remove-Item -LiteralPath (Join-Path $taskReady 'build-signal-helpers.ps1') }
foreach ($taskPattern in '*.cs','*.manifest','build*.ps1','package.ps1','README.md','VALIDATION.md','V3-VALIDATION.md','V3-STATUS.md','UI-UPGRADE.md','THIRD-PARTY.md','TELEGRAM-RELEASE.md','USB-DEEP-GUIDE.md','USB-DEEP-VALIDATION.md','MODERN-RECOVERY.md','QUALITY-RELEASE.md','COMPETITOR-COMPARISON.md','COMPETITIVE-UPDATE.md','RECOVERY-UPGRADE.md','RECOVERY-OCT30.md','STORAGE-SUPPORT.md') {
    Get-ChildItem -LiteralPath $taskRoot -Filter $taskPattern -File | Where-Object { $_.Name -ne 'build-signal-helpers.ps1' } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $taskReady $_.Name) -Force }
}
Copy-Item -LiteralPath (Join-Path $taskRoot 'USB-Recovery.exe') -Destination (Join-Path $taskReady 'USB-Recovery.exe') -Force
$taskDocs = Join-Path $taskRoot 'docs'
if (Test-Path -LiteralPath $taskDocs -PathType Container) {
    New-Item -ItemType Directory -Path (Join-Path $taskReady 'docs') -Force | Out-Null
    Get-ChildItem -LiteralPath $taskDocs -File -Filter '*.md' | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $taskReady ('docs\' + $_.Name)) -Force }
    if (Test-Path -LiteralPath (Join-Path $taskDocs 'images') -PathType Container) { Copy-TaskTree (Join-Path $taskDocs 'images') (Join-Path $taskReady 'docs\images') }
}

Copy-TaskTree (Join-Path $taskRoot 'helpers\recovery_engine') (Join-Path $taskReady 'helpers\recovery_engine')
Copy-TaskTree (Join-Path $taskRoot 'vendor\iphone-backup-decrypt') (Join-Path $taskReady 'vendor\iphone-backup-decrypt')
foreach ($taskTool in 'recovery-helper','testdisk-7.2') { Copy-TaskTree (Join-Path $taskRoot "tools\$taskTool") (Join-Path $taskReady "tools\$taskTool") }
$taskAdbTarget = Join-Path $taskReady 'tools\platform-tools'
New-Item -ItemType Directory -Path $taskAdbTarget -Force | Out-Null
foreach ($taskAdb in 'adb.exe','AdbWinApi.dll','AdbWinUsbApi.dll','NOTICE.txt','source.properties') { Copy-Item -LiteralPath (Join-Path $taskRoot "tools\platform-tools\$taskAdb") -Destination (Join-Path $taskAdbTarget $taskAdb) -Force }
$taskTestsTarget = Join-Path $taskReady 'tests'
New-Item -ItemType Directory -Path $taskTestsTarget -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $taskRoot 'tests') -File | Where-Object { $_.Extension -in @('.cs','.py','.ps1') -or $_.Name -match '(result\.txt|regression\.txt|-validation\.json|Portable.*\.json|minimal-ui.*\.png)$' -or $_.Name -in @('ReviewEngine-report.md','PortableFormats-report.md','ArchiveSearchNotes.md','PhotoCatalogTests.log','RecoveryCoreTests.log','UpgradeMetadataIntegration-summary.md','EngineTests.result.txt','PortableFormats.result.txt','v3-ui.png','USB-methods.png','USB-results.png','Modern-main.png','Modern-extra.png','Modern-results.png','Modern-compact.png','UX-main.png','UX-basic.png','UX-hub.png','UX-hub-compact.png','UX-results-compact.png','UX-expert.png','UX-results.png','UX-compact.png','official-recovery-datasets.json','ARCHIVE-SALVAGE.md','NTFS-STRUCTURE.md','CommercialComparison-baseline.json','CommercialComparison-after.json','ComparisonOctober30-report.md','CommercialComparison-protocol.md','CommercialComparison-dmde-ntfs.scanlog','CommercialComparison-dmde-unaligned.scanlog','Competition-main.png','Competition-main-compact.png','Competition-folders.png','Competition-folders-compact.png') } | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $taskTestsTarget $_.Name) -Force }
$taskFixture = 'tests\photorec-20261011T231546120952Z\fixtures\expected.png'
New-Item -ItemType Directory -Path (Split-Path -Parent (Join-Path $taskReady $taskFixture)) -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $taskRoot $taskFixture) -Destination (Join-Path $taskReady $taskFixture) -Force
$taskTelegramFixtures = Join-Path $taskRoot 'tests\TelegramNativeFixtures'
if (-not (Test-Path -LiteralPath (Join-Path $taskTelegramFixtures 'manifest.json') -PathType Leaf)) { throw 'Missing synthetic Telegram native fixtures.' }
Copy-TaskTree $taskTelegramFixtures (Join-Path $taskReady 'tests\TelegramNativeFixtures')
Copy-TaskTree (Join-Path $taskRoot 'tests\TelegramMediaFixtures') (Join-Path $taskReady 'tests\TelegramMediaFixtures')
if(Test-Path -LiteralPath (Join-Path $taskRoot 'tests\StorageFixtures')){Copy-TaskTree (Join-Path $taskRoot 'tests\StorageFixtures') (Join-Path $taskReady 'tests\StorageFixtures')}
Copy-Item -LiteralPath (Join-Path $taskRoot 'НАЧНИ ЗДЕСЬ.txt') -Destination (Join-Path $taskReady 'НАЧНИ ЗДЕСЬ.txt') -Force
$taskHashes = Get-ChildItem -LiteralPath $taskReady -Recurse -File | Where-Object { $_.Extension -in @('.exe','.dll','.pyd') } | ForEach-Object {
    [pscustomobject]@{ path=$_.FullName.Substring($taskReady.Length+1).Replace('\','/'); sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); bytes=$_.Length }
}
$taskHashes | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $taskReady 'package-sha256.json') -Encoding UTF8
Write-Output ('Packaged: ' + $taskReady)
Write-Output ('Runtime files hashed: ' + @($taskHashes).Count)
