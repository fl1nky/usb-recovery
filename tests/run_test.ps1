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

$exe = Join-Path $repo "tests\$TestName.exe"

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

$args = @(
    '/nologo',
    '/target:exe',
    "/out:$exe",
    "/main:$TestName"
) + $refs + $srcFiles + @($testFile)

Write-Host "Compiling $TestName..."
& $csc $args
if ($LASTEXITCODE -ne 0) {
    throw "Compilation of $TestName failed with code $LASTEXITCODE"
}

Write-Host "Running $TestName..."
try {
    & $exe
    if ($LASTEXITCODE -ne 0) {
        throw "Test $TestName failed with exit code $LASTEXITCODE"
    }
} finally {
    if (Test-Path $exe) {
        Remove-Item $exe -Force -ErrorAction SilentlyContinue
    }
}
