# Contributing

USB Recovery is a Windows application with a local Python helper. Start with a
small, independently testable change. The application code is AGPLv3; bundled
dependencies retain their own licenses.

## Build from a clean checkout

Use Windows x64, PowerShell, the .NET Framework compiler and Python 3.12 for
development. Users of the portable ZIP do not need Python. Run these commands
with Python 3.12 selected in PATH:

```powershell
python scripts/bootstrap-build.py
.\scripts\prepare-helper-env.ps1 -Python312 (Get-Command python.exe).Source
.\scripts\build-app.ps1
.\scripts\test-source.ps1 -Python312 .build/engine-env/Scripts/python.exe -Suite Quick
```

Bootstrap downloads the checksum-pinned release once and restores build inputs,
never an old application/helper executable. Environment preparation installs
the pinned local dependencies without contacting the package index.
The quick suite is for feedback; it does not replace the complete helper build
or packaged acceptance. See [Build and tests](docs/development/build.md).

## Find the right module

- Sources and working copies: `src/Recovery/Sources`.
- Recovery algorithms: `src/Recovery/Recovery/Engines`.
- Archive protocol models: `src/Recovery/Archive`.
- Archive search transport: `src/Recovery/Infrastructure/ArchiveSearchService.cs`.
- Local importers and image processing: `helpers/recovery_engine`.
- HTML export reader: `helpers/recovery_engine/telegram_html.py`.

[Architecture](docs/development/architecture.md) describes the pipeline and the
boundaries between source, recovered candidate, verified content and export.

## Change a parser or recovery method

1. Add an owned fixture that fails before the change. Preserve original input,
   expected bytes/text, identifiers and unknown fields.
2. Keep parsing separate from UI and process transport. Preserve protocol field
   names; introduce incompatible protocol changes explicitly.
3. Check malformed/truncated input and resource limits. Read sources without
   modifying them and export to a separate destination.
4. Add the test once to `scripts/source-tests.json`. Use `quick` for short,
   self-contained checks; the full suite includes every entry. Missing mandatory
   tests fail discovery, even in quick mode.
5. Run relevant tests, then the full build/acceptance appropriate to the changed
   application or helper. Report source, frozen and release results separately.

`tests/TelegramHtmlTests.py` is a small end-to-end example: it reads an owned
export, checks complete Unicode text and identifiers, excludes active markup
and verifies that the input bytes stay unchanged.

## Keep changes reviewable

Use clear names, normal formatting and comments explaining format constraints.
Separate moving/formatting code from algorithm changes. Avoid putting recovered
files, personal exports, secrets, large images or build outputs in Git.

Local source checks do not block the machine's network. Network-blocked checks
are a separate explicit mode on an already elevated runner; state which mode
actually ran. No test count proves recovery on real devices.
