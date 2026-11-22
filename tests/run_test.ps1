param(
    [Parameter(Mandatory=$true)]
    [string]$TestName
)

$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\danil\Desktop\projects\usb-recovery'
$csc = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$wpf = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF'

$testFile = Join-Path $repo "tests\$TestName.cs"
if (-not (Test-Path $testFile)) {
    throw "Test file not found: $testFile"
}

$testBinDir = Join-Path $repo ".build\tests"
if (-not (Test-Path $testBinDir)) {
    New-Item -ItemType Directory -Path $testBinDir -Force | Out-Null
}
$exe = Join-Path $testBinDir "$TestName.exe"

$refs = @(
    '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Web.Extensions.dll',
    '/reference:System.Runtime.WindowsRuntime.dll',
    '/reference:System.Xaml.dll',
    "/reference:$wpf\PresentationCore.dll",
    "/reference:$wpf\PresentationFramework.dll",
    "/reference:$wpf\WindowsBase.dll",
    "/reference:$wpf\WindowsFormsIntegration.dll"
)

$srcFiles = @(Get-ChildItem -LiteralPath "$repo\src" -Recurse -File -Filter '*.cs' | Select-Object -ExpandProperty FullName)

$extraSources = @()
if ($TestName -in @('LongPathRecoveryTests', 'ContentQualityTests', 'DeepRecoveryTests', 'ModernRecoveryTests')) {
    $extraSources += (Join-Path $repo "tests\FilesystemRecoveryTests.cs")
}
if ($TestName -eq 'ArchiveTextProtocolAuditTests') {
    $extraSources += (Join-Path $repo "tests\ArchiveTextProtocolAuditFixture.cs")
}
if ($TestName -in @('ArchiveTextWorkflowTests', 'ArchiveTextUiTests', 'ArchiveTextPortableTests')) {
    $extraSources += (Join-Path $repo "tests\ArchiveTextProtocolFixture.cs")
}
if ($TestName -eq 'HelperCheckpointProtocolTests') {
    $extraSources += (Join-Path $repo "tests\HelperProtocolFixture.cs")
}
if ($TestName -eq 'TelegramPlatformUiTests') {
    $extraSources += (Join-Path $repo "tests\TelegramPlatformProtocolFixture.cs")
}
if ($TestName -eq 'TelegramUiTests') {
    $extraSources += (Join-Path $repo "tests\TelegramUiProtocolFixture.cs")
}

$args = @(
    '/nologo',
    '/target:exe',
    "/out:$exe",
    "/main:$TestName",
    "/win32manifest:$repo\tests\test.manifest"
) + $refs + $srcFiles + $extraSources + @($testFile)

Write-Host "Compiling $TestName..."
& $csc $args
if ($LASTEXITCODE -ne 0) {
    throw "Compilation of $TestName failed with code $LASTEXITCODE"
}
Copy-Item (Join-Path $repo "src\Recovery\app.config") "$exe.config" -Force

$runArgs = @($repo)
if ($TestName -eq 'DocumentMediaPreviewTests') {
    $runArgs += (Join-Path $repo 'tests\fixtures\document-media-preview\avc-aac.mp4')
}
if ($TestName -eq 'Ext4RecoveryTests') {
    $runArgs = @(
        (Join-Path $repo '.build\ext4-fixtures-current'),
        (Join-Path $repo ('.build\ext4-tests-' + [Guid]::NewGuid().ToString('N')))
    )
}
if ($TestName -eq 'ApfsRecoveryTests') {
    $runArgs = @(
        (Join-Path $repo '.build\apfs-fixtures-current'),
        (Join-Path $repo ('.build\apfs-tests-' + [Guid]::NewGuid().ToString('N')))
    )
}
if ($TestName -eq 'RefsRecoveryTests') {
    $runArgs = @(
        (Join-Path $repo '.build\refs-fixtures-current'),
        (Join-Path $repo ('.build\refs-tests-' + [Guid]::NewGuid().ToString('N')))
    )
}
if ($TestName -eq 'ArchiveSalvageTests') {
    $runArgs = @(Join-Path $repo '.build\archive-salvage-inputs-current')
}
if ($TestName -eq 'FragmentedZipRecoveryTests') {
    $runArgs = @(Join-Path $repo '.build\fragmented-zip-inputs-current')
}

Write-Host "Running $TestName..."
try {
    & $exe @runArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Test $TestName failed with exit code $LASTEXITCODE"
    }
} finally {
    if (Test-Path $exe) {
        Remove-Item $exe -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path "$exe.config") {
        Remove-Item "$exe.config" -Force -ErrorAction SilentlyContinue
    }
}
