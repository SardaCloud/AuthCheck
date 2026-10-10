# Changelog

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com. Licensed under the MIT License.

All notable changes to AuthCheck.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and AuthCheck uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-10

First public release: sign-in, device and management status for Windows in
one report, read through documented Windows APIs, WMI and the registry,
without running `dsregcmd`, `klist` or `cmdkey`.

### Added

- **Device registration** (`/Device`, alias `/Dsreg`): Microsoft Entra
  joined, hybrid joined or registered; the Active Directory domain; tenant,
  device ID, identity provider and joining user; the device certificate and
  its validity; the MDM URLs Microsoft Entra offers; the settings sync
  endpoints, decoded. Read with `NetGetAadJoinInformation` and
  `NetGetJoinInformation`.
- **Primary Refresh Token and single sign-on**: PRT eligibility, the user's
  Windows Hello for Business key, and the Cloud Kerberos state behind
  `klist cloud_debug`: whether it is enabled by policy and whether this logon
  holds a cloud TGT.
- **Device management** (`/Mdm`): who manages the device, through the MDM
  Registration API, the enrollment and OMA-DM records and the certificate
  store. Microsoft Intune, the `*.dm.microsoft.com` management channel and
  third-party MDM are told apart; each enrollment shows its server, last
  sync, last result and MDM certificate. The Configuration Manager client
  shows its version, site, management point, service state, MDM bridge and
  co-management state, the last read from ConfigMgr's own `CCM_System` WMI
  class. Coexistence with a third-party MDM is named as such.
- **Kerberos tickets** (`/Kerberos`, alias `/Klist`): every ticket cached for
  the logon session, with times, flags, ticket and session-key encryption
  and the KDC called.
- **Stored credentials** (`/Credentials`, alias `/Cmdkey`): every Credential
  Manager entry with its target, type, user name, persistence and last
  change. Secrets are never read, and are wiped before the buffer is freed.
- **Checks** marked OK, WARN or BAD, and exit codes `0`, `1` and `2`: device
  and MDM certificate validity, Entra registration, MDM enrollment, sync age
  and result, co-management consistency, the ConfigMgr service, Cloud
  Kerberos, the TGT, and DES or RC4 in tickets and session keys.
- **`/Json`**: JSON Lines on stdout ending in a `result` line that carries the
  whole report, documented in `docs/json-output.md`. Also `/Quiet`,
  `/Verbose`, `/NoLogo`, `/Log <file>` and `/?` with examples.
- One self-contained `AuthCheck.exe` for **x64, ARM64 and x86**, with the
  Sarda Cloud icon and version information. No elevation, no installation,
  no .NET runtime needed.
- Unit tests that check every native structure against the sizes and offsets
  the Windows compiler measures, run on x64, x86 and ARM64, and a
  command-line contract test, `tests/contract.ps1`.

[1.0.0]: https://github.com/SardaCloud/AuthCheck/releases/tag/v1.0.0
