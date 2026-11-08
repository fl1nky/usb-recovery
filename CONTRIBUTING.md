# Contributing to USB-Recovery

Thank you for your interest in contributing to **USB-Recovery**, the premier free and open-source data recovery project!

## Guiding Principles

1. **100% Free & Open Source**: No paywalls, no file-size caps, no feature gating. All algorithms remain free under the GNU AGPLv3.
2. **Zero Telemetry & Offline Verification**: USB-Recovery never phones home, uses telemetry, or makes outbound network requests. All tests run in isolated, offline network environments blocked by firewall policies.
3. **Reproducible & Deterministic**: File recovery engines must be backed by synthetic test fixtures with verifiable SHA-256 assertions.
4. **Safety First**: Non-destructive read-only access to storage sources. Never write to the source media.

## Development Setup

### Prerequisites
- Windows 10/11 x64 or Windows Server 2016+
- .NET Framework 4.8 developer pack (built-in `csc.exe` in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`)
- PowerShell 5.1+

### Building the Project
From the repository root:
```powershell
.\scripts\build-app.ps1
```
The compiled executable will be placed in `.build\app\USB-Recovery.exe`.

### Running Offline Quality Tests
To run the automated suite:
```powershell
$env:__COMPAT_LAYER = 'RunAsInvoker'
.\tests\QualityOfflineTests.ps1 -ApplicationDirectory .build\app
```

## Pull Request Guidelines
- Ensure all tests pass without errors.
- Do not check in large binary disk images to Git; use synthetic image generators or fixtures.
- Keep comments and documentation clear and accurate.
