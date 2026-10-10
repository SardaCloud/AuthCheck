<p align="center">
  <img src="assets/AuthCheck-256.png" width="104" alt="AuthCheck icon: the Sarda Cloud sheep with a green check mark">
</p>

<h1 align="center">AuthCheck</h1>

<p align="center">
  <b>Sign-in, device and management status for Windows, read straight from the APIs Windows itself uses.</b><br>
  One report instead of <code>dsregcmd /status</code>, <code>klist</code>, <code>cmdkey /list</code> and an MDM diagnostics report.
</p>

<p align="center">
  <a href="https://github.com/SardaCloud/AuthCheck/actions/workflows/build.yml"><img src="https://github.com/SardaCloud/AuthCheck/actions/workflows/build.yml/badge.svg" alt="Build"></a>
  <a href="https://github.com/SardaCloud/AuthCheck/releases/latest"><img src="https://img.shields.io/github/v/release/SardaCloud/AuthCheck" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
</p>

<p align="center">
  <a href="https://www.sardacloud.com">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="assets/sardacloud-logo-white.png">
      <img src="assets/sardacloud-logo-blue.png" width="200" alt="Sarda Cloud">
    </picture>
  </a>
</p>

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com. Licensed under the [MIT License](LICENSE).

---

## Why

When sign-in or management misbehaves on a Windows device, the evidence is
spread over several tools: `dsregcmd /status` for the Microsoft Entra join and
the Primary Refresh Token, `klist` for Kerberos, `cmdkey /list` for saved
credentials, and the MDM diagnostics report or the registry for Intune,
Configuration Manager and co-management. Their output is made for people, it
changes between Windows versions, and some of it needs an elevated prompt.

AuthCheck reads the same facts through **documented Windows APIs, WMI and the
registry**, never by running those tools, and gives you one report, a
verdict on each part, an exit code and, if you want it, JSON.

- **Read-only.** Nothing is changed, and no elevation is needed.
- **No secrets.** No password, ticket, token or key reaches the output; only the facts about them.
- **One file.** A self-contained `AuthCheck.exe` for x64, ARM64 and x86. Nothing to install, no .NET needed.

## What it shows

| Section | Instead of | What you see | Read through |
| --- | --- | --- | --- |
| **Device registration** | `dsregcmd /status` | Microsoft Entra joined, hybrid joined or registered; the Active Directory domain; tenant, device ID and device certificate with its validity; the MDM URLs Entra offers | `NetGetAadJoinInformation`, `NetGetJoinInformation` |
| **Primary Refresh Token and SSO** | `dsregcmd /status`, `klist cloud_debug` | PRT eligibility, the Windows Hello for Business key, Cloud Kerberos policy and whether this logon holds a cloud TGT | `NetGetAadJoinInformation`, the Kerberos package's `KerbPrintCloudKerberosDebugMessage` |
| **Device management** | MDM diagnostics, *Access work or school*, the ConfigMgr control panel | Who manages the device: Microsoft Intune, a third-party MDM, Configuration Manager, co-management or coexistence. Each enrollment with its server, last sync, last result and MDM certificate; the ConfigMgr client, site, management point, service and co-management state | The MDM Registration API (`GetDeviceRegistrationInfo`), the enrollment and OMA-DM account registry, the certificate store, ConfigMgr's WMI class `CCM_System` |
| **Kerberos tickets** | `klist` | Every ticket cached for this logon session: client, server, start, end and renewal times, flags, ticket and session-key encryption, the KDC called | `LsaCallAuthenticationPackage` with `KerbQueryTicketCacheEx3Message` |
| **Stored credentials** | `cmdkey /list` | Every Credential Manager entry: target, type, user name, persistence and last change | `CredEnumerateW` |

## Download

Get the zip for the machine you will run AuthCheck **on** from
[Releases](https://github.com/SardaCloud/AuthCheck/releases/latest):

| Package | For |
| --- | --- |
| `AuthCheck-<version>-win-x64.zip` | 64-bit Intel or AMD. Almost certainly the one you want |
| `AuthCheck-<version>-win-arm64.zip` | Windows on ARM |
| `AuthCheck-<version>-win-x86.zip` | 32-bit Windows |

Unzip it anywhere and run `AuthCheck.exe`. It needs Windows 10 or later, or
Windows Server 2016 or later. To verify a download:

```powershell
(Get-FileHash .\AuthCheck-1.0.0-win-x64.zip -Algorithm SHA256).Hash.ToLower()
```

and compare it with `SHA256SUMS.txt` from the same release.

## Usage

```text
AuthCheck.exe [/<Action>] [switches]
AuthCheck.exe /Action <Action> [switches]
```

| Action | Shows | Alias |
| --- | --- | --- |
| `/Status` | Every section, in order. **The default.** | |
| `/Device` | Device registration, PRT and single sign-on | `/Dsreg` |
| `/Mdm` | MDM, Intune, third-party MDM, Configuration Manager, co-management | |
| `/Kerberos` | Cached Kerberos tickets | `/Klist` |
| `/Credentials` | Credential Manager entries | `/Cmdkey` |

| Switch | Effect |
| --- | --- |
| `/Json` | JSON Lines on stdout, ending in a `result` line that carries the whole report. The text report moves to stderr. See [docs/json-output.md](docs/json-output.md). |
| `/Quiet` | Show only warnings and problems. |
| `/Verbose` | Show more: every enrollment record, raw flags, ticket cache flags, credential comments and aliases. |
| `/NoLogo` | Leave out the banner. |
| `/Log <file>` | Append a plain-text copy of the report to a file. |
| `/?` | Help, with examples. Also `/h` and `/Help`. |

Switches start with `/` or `-` and are not case-sensitive, so `AuthCheck -klist`
works too. A switch AuthCheck does not know is an error, never silently ignored.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Ran, and nothing is BAD. Warnings may still be listed. |
| `1` | Could not run, or a section could not be read. |
| `2` | Ran, and at least one check is BAD. |

## Examples

### Everything at once

```powershell
AuthCheck
```

A Microsoft Entra hybrid joined, co-managed laptop (all names and identifiers
are invented):

```text
  AuthCheck 1.0 - sign-in, device and management status
  Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com

  Computer                : CONTOSO-LT042
  User                    : CONTOSO\alex
  Elevated                : no
  Windows                 : 10.0.26200.6584, 25H2, Enterprise, ARM64
  Collected               : 2026-10-10 09:41

==========================================================================
  DEVICE REGISTRATION  (dsregcmd /status)
==========================================================================
  Join state              : Microsoft Entra hybrid joined
  Active Directory        : CONTOSO (domain)
  Microsoft Entra         : joined
  Tenant                  : Contoso Ltd (8a1f3c52-6b7d-4e90-a1b2-c3d4e5f60718)
  Device ID               : 5f0c1d2e-9a8b-4c7d-8e6f-1234567890ab
  Identity provider       : login.windows.net
  Device certificate      : 6C1D0A7E9B2F44C3A85D1E07F93B2C4D5E6F7A8B
    Valid                 : 2026-03-02 to 2036-03-02
  MDM enrollment URL      : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
  MDM compliance URL      : https://portal.manage.microsoft.com/?portalAction=Compliance

  [OK  ] Microsoft Entra        hybrid joined
  [OK  ] Device certificate     valid until 2036-03-02

==========================================================================
  PRIMARY REFRESH TOKEN AND SINGLE SIGN-ON
==========================================================================
  PRT eligible            : yes - the device is Microsoft Entra joined
  Windows Hello key       : registered for alex@contoso.com
  Cloud Kerberos          : enabled by policy
  Cloud TGT               : present in this logon session

  Whether a PRT is held right now, and when it was issued and expires, is
  kept by the CloudAP security package and is not exposed through a
  documented API. These are the signals Windows does document.

  [OK  ] Cloud Kerberos         cloud TGT present in this logon session

==========================================================================
  DEVICE MANAGEMENT  (MDM, Intune, Configuration Manager)
==========================================================================
  Managed by              : Microsoft Intune and Configuration Manager (co-managed)
  MDM registration        : yes - MDM, device-wide, with Microsoft Entra ID
  MDM user                : alex@contoso.com
  MDM service             : https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc

  Microsoft Intune  [MS DM Server]
    Enrollment ID         : 6A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9
    User                  : alex@contoso.com
    Tenant ID             : 8a1f3c52-6b7d-4e90-a1b2-c3d4e5f60718
    Server                : https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx
    Last sync             : 2026-10-10 08:12 (1 hour ago)
    Last result           : success
    Certificate           : 9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A2F1E0D
    Valid                 : 2026-04-01 to 2027-03-31

  Configuration Manager
    Client version        : 5.00.9146.1000
    Site code             : PS1
    Management point      : CONTOSOCMG.CONTOSO.COM/CCM_Proxy_MutualAuth/72057594037927939
    CcmExec service       : Running
    MDM bridge            : registered (0B1C2D3E-4F50-4162-8374-95A6B7C8D9EA)
    Co-management         : yes - Configuration Manager reports this device as co-managed
    Workload mask         : 8255 (0x0000203F)

  [OK  ] MDM enrollment         Microsoft Intune
  [OK  ] Last MDM sync          Microsoft Intune: 1 hour ago
  [OK  ] MDM certificate        Microsoft Intune: valid until 2027-03-31
  [OK  ] Co-management          Microsoft Intune and Configuration Manager

==========================================================================
  KERBEROS TICKETS  (klist)
==========================================================================
  Cached tickets          : 2

  #0  krbtgt/CONTOSO.COM @ CONTOSO.COM
    Client                : alex @ CONTOSO.COM
    Valid                 : 2026-10-10 08:05 to 2026-10-10 18:05
    Renew until           : 2026-10-17 08:05
    Encryption            : AES-256-CTS-HMAC-SHA1-96
    Flags                 : forwardable forwarded renewable pre_authent name_canonicalize
    KDC called            : DC01.contoso.com

  #1  cifs/files.contoso.com @ CONTOSO.COM
    Client                : alex @ CONTOSO.COM
    Valid                 : 2026-10-10 08:07 to 2026-10-10 18:05
    Renew until           : 2026-10-17 08:05
    Encryption            : RC4-HMAC, session key AES-256-CTS-HMAC-SHA1-96
    Flags                 : forwardable forwarded renewable pre_authent ok_as_delegate name_canonicalize
    KDC called            : DC01.contoso.com

  [OK  ] Kerberos TGT           krbtgt/CONTOSO.COM, valid until 2026-10-10 18:05
  [WARN] Ticket encryption      RC4 in 1 ticket: cifs/files.contoso.com

==========================================================================
  STORED CREDENTIALS  (cmdkey /list)
==========================================================================
  Entries                 : 1

  Domain:target=files.contoso.com
    Type                  : Domain password
    User                  : CONTOSO\alex
    Persistence           : Enterprise (roams with the profile)
    Last written          : 2026-09-30 14:22

  Only the facts about each entry are shown. Secrets never reach the output.

  [+] Status: no problems, 1 warning.
```

### One section

```powershell
AuthCheck /Device          # join state and sign-in readiness: what dsregcmd /status shows
AuthCheck /Klist /Verbose  # cached Kerberos tickets with raw and cache flags
AuthCheck /Mdm /Quiet      # only MDM warnings and problems
```

### In a script

```powershell
# The last line of /Json is the whole report.
$report = AuthCheck /Json 2>$null | Select-Object -Last 1 | ConvertFrom-Json

$report.data.mdm.managedBy
# Microsoft Intune and Configuration Manager (co-managed)

$report.data.kerberos.tickets | Where-Object encryption -like 'RC4*' | Select-Object server, encryption

if ($report.exitCode -eq 2) { 'Something is broken; see the checks.' }
```

Every check is also its own JSON line, so problems can be picked out without
waiting for the result:

```powershell
AuthCheck /Json 2>$null | ConvertFrom-Json | Where-Object { $_.type -eq 'check' -and $_.status -ne 'ok' }
```

### As a scheduled check

```powershell
AuthCheck /Status /Quiet /Log C:\Logs\authcheck.log
```

prints only what needs attention, appends the full report to the log, and
exits `2` when a check is BAD, which a scheduler, Intune remediation or
monitoring agent can act on. Run it as the user whose sign-in you care about:
see *Logon sessions* below.

## Checks

Each section ends with verdicts. **BAD** means broken now and makes the exit
code `2`. **WARN** means it deserves a look.

| Section | Check | OK | WARN | BAD |
| --- | --- | --- | --- | --- |
| Device | Microsoft Entra | joined, hybrid joined or registered | neither joined nor registered | |
| Device | Device certificate | valid | expires within 30 days | missing, expired or not yet valid |
| PRT | Cloud Kerberos | cloud TGT present | enabled by policy, no cloud TGT in this logon | |
| MDM | MDM enrollment | enrolled with Intune or another MDM | Entra offers an MDM enrollment URL, but the device is not enrolled | |
| MDM | Last MDM sync | within 7 days | older than 7 days, or never | |
| MDM | MDM sync result | | the last session ended with an error code | |
| MDM | MDM certificate | valid | expires within 30 days, or not in the certificate store | expired or not yet valid |
| MDM | ConfigMgr client | | the CcmExec service is not running | |
| MDM | Co-management | Intune and ConfigMgr agree | ConfigMgr reports co-management without an Intune enrollment, or the reverse | |
| Kerberos | Kerberos TGT | present and valid | expired, or missing on a domain logon | |
| Kerberos | Ticket encryption | no DES or RC4 | RC4 in a ticket or session key | DES in a ticket or session key |
| Kerberos | Kerberos | | this logon session has no ticket cache | |

## How it works

- **Documented interfaces only.** Device registration comes from
  `NetGetAadJoinInformation` and `NetGetJoinInformation` (lmjoin.h); MDM from
  the MDM Registration API (mdmregistration.h); Kerberos from the LSA
  messages ntsecapi.h defines; credentials from `CredEnumerateW`
  (wincred.h); co-management from ConfigMgr's own WMI class `CCM_System`,
  through WMI's COM interfaces. Every structure is declared from the Windows
  SDK, and a unit test checks each size and offset against what the Windows
  compiler measures, on x64, x86 and ARM64.
- **The registry, where Windows keeps the record.** Enrollments
  (`HKLM\SOFTWARE\Microsoft\Enrollments`), OMA-DM accounts
  (`...\Provisioning\OMADM\Accounts`) and the ConfigMgr client
  (`...\SMS\Mobile Client`) are read, never written.
- **No other processes.** AuthCheck never starts `dsregcmd`, `klist`, `cmdkey`
  or anything else.
- **Secrets stay secret.** Windows returns the secret of a generic credential
  to whoever enumerates Credential Manager. AuthCheck never reads it and
  wipes it before freeing the buffer. Tickets, keys and tokens are never
  requested at all.

### Logon sessions

Kerberos tickets and saved credentials belong to a **logon session**. An
elevated prompt runs in a session of its own, with its own tickets, so run
AuthCheck in the window whose tickets you want to see; the report says
whether it is elevated. A remote PowerShell session has no ticket cache and no
credential set, and AuthCheck says so instead of failing.

## Limitations

- **PRT details.** Whether a Primary Refresh Token is held right now, and when
  it was issued and expires, is kept by the CloudAP security package and is
  not exposed through a documented API. AuthCheck reports the signals Windows
  does document: eligibility, the Windows Hello key and the Cloud Kerberos
  state. `dsregcmd /status` shows the rest.
- **Co-management workloads.** ConfigMgr reports which workloads it hands to
  Intune as a bit mask (`ComgmtWorkloads`). Microsoft does not document the
  bits, so AuthCheck shows the number rather than guess.
- **Enrollment types.** The four registration kinds mdmregistration.h defines
  are named; other enrollment type numbers are shown as they are.

## Privacy

The report contains identifiers: user names, tenant and device IDs, server
and host names. That is the point of it, but review a report before you
paste it into a ticket, a forum or an issue here.

## Building from source

You need Windows and the [.NET 9 SDK](https://dotnet.microsoft.com/download).

```powershell
git clone https://github.com/SardaCloud/AuthCheck
cd AuthCheck
.\build.ps1 -Arch All -Test -Package
.\tests\contract.ps1 -Exe .\out\x64\AuthCheck.exe
```

`build.ps1` publishes one self-contained `AuthCheck.exe` per architecture into
`out\`, checks that each is built for the processor it claims, and with
`-Package` zips them and writes `SHA256SUMS.txt`. `tests\contract.ps1` checks
the command-line contract: help, exit codes, refusals, every action and alias,
`/Json` and `/Log`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License and trademarks

AuthCheck is released under the [MIT License](LICENSE).

The Sarda Cloud name and logo are trademarks of Sarda Cloud Srl and are not
licensed under the MIT License. Microsoft, Windows, Microsoft Entra, Microsoft
Intune and Configuration Manager are trademarks of the Microsoft group of
companies. AuthCheck is an independent tool by Sarda Cloud Srl and is not
affiliated with or endorsed by Microsoft.

---

Copyright (C) 2026 Sarda Cloud Srl, [www.sardacloud.com](https://www.sardacloud.com)
