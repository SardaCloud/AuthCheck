# Contributing

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com. Licensed under the MIT License.

Thank you for helping. Issues and pull requests are welcome.

## Reporting a problem

Open an issue with the AuthCheck version, the Windows version and edition,
and the part of the report that looks wrong. If you attach output, **remove
user names, tenant and device IDs and host names first**. For a security
problem, follow [SECURITY.md](SECURITY.md) instead.

## Building and testing

You need Windows and the .NET 9 SDK.

```powershell
.\build.ps1 -Arch All -Test -Package
.\tests\contract.ps1 -Exe .\out\x64\AuthCheck.exe
```

`dotnet test` runs the unit tests as the architecture of the SDK you use. To
check the 32-bit structure layouts on a 64-bit machine with the x86 runtime
installed, run `dotnet test --arch x86`. CI runs the tests natively on x64, x86
and ARM64.

## Rules of the house

- **Documented interfaces only.** Use a Win32 API, LSA message, WMI class or
  registry location that Microsoft documents or declares in the Windows SDK.
  Do not call undocumented exports, and do not decode a value whose meaning
  is not documented; show it raw instead.
- **Every native structure is declared from the SDK header** and has a
  layout test in `tests/AuthCheck.Tests/LayoutTests.cs`. Measure the
  expected sizes and offsets with the Windows compiler for x64 and x86.
- **Never output a secret.** Not in text, `/Json` or `/Log`, not even with
  `/Verbose`. If an API returns one, do not read it.
- **Read-only.** AuthCheck changes nothing and starts no process.
- **Verdicts need a reason.** A new check states its thresholds, and BAD is
  kept for what is broken now. Add it to the table in the README.
- **The JSON contract is stable.** Add keys freely; do not rename or remove
  them before 2.0. Document them in `docs/json-output.md`.
- Each source file starts with the copyright and licence lines used
  throughout the repository. The build treats warnings as errors.

By contributing you agree that your contribution is licensed under the
MIT License.
