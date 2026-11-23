# Contributing to USB Recovery

Build the Windows application from the repository root using PowerShell and the .NET Framework 4.8 compiler.

```powershell
.\scripts\build-app.ps1
.\tests\run_test.ps1 RecoveryRestartTests
```

The application is written to `.build\app\USB-Recovery.exe`. The restart test uses generated files. A portable release also includes external engines, their dependencies and licenses.

## Find the code

| If you are changing | Start here |
|---|---|
| Scan order, retry or cancellation | [RecoveryPipeline](src/Recovery/Recovery/RecoveryPipeline.cs) and [session persistence](src/Recovery/Recovery/RecoverySession.cs) |
| PhotoRec arguments, process lifetime or scan completion | [PhotoRecRunner](src/Recovery/Recovery/Engines/PhotoRecRunner.cs) and its [integration test](tests/PhotoRecRunnerTests.cs) |
| NTFS record and stream recovery | [Native component build and validation](docs/development/native-ntfs-build.md) |
| Another engine, the UI or export | [Architecture map](docs/development/architecture.md) |

To run the PhotoRec integration test on a fresh checkout, restore the pinned tools using Python 3.12+ and run the test at your current Windows privilege level.

```powershell
python scripts/bootstrap-build.py --native-only
$env:__COMPAT_LAYER = 'RunAsInvoker'
.\tests\run_test.ps1 PhotoRecRunnerTests
```

## Submit a change

Describe the input that used to fail and how someone can reproduce the result. For recovery changes, include the expected file contents or SHA256 and the result of an interrupted run. Use a small generated image or a redistributable fixture. Keep personal data, recovered files and generated builds out of Git.

For performance or competitor claims, record the versions, settings, reference files and results on the same images. Existing comparisons include the scope of each experiment. [Comparison reports](docs/guides/comparison.md)
