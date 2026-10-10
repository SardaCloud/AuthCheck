# AuthCheck JSON output

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com. Licensed under the MIT License.

With `/Json`, AuthCheck writes [JSON Lines](https://jsonlines.org/) to
**stdout**: one JSON object per line, UTF-8 without a byte order mark, lines
ending in `\n`. The human-readable report moves to **stderr**, so a person
watching still sees it and a script reading stdout gets nothing but JSON.

Every run, successful or not, writes a `start` line first and a `result`
line last. The `result` line carries the whole report; the lines in between
let a caller react as the report is produced.

```powershell
$report = AuthCheck /Json 2>$null | Select-Object -Last 1 | ConvertFrom-Json
```

## Line types

| `type` | When | Fields |
| --- | --- | --- |
| `start` | First line of every run | `tool` (`"AuthCheck"`), `version`, `action`, `utc` |
| `check` | Each verdict | `section`, `status` (`ok`, `warn`, `bad`), `label`, `detail` |
| `warn` | Something to know that is not a verdict, e.g. an unreadable registry key | `section`, `message` |
| `error` | A section that could not be read, or a fatal error | `section`, `message` |
| `result` | Last line of every run | `action`, `ok`, `exitCode`, `findings` (BAD checks), `warnings`, `data` |

`result.exitCode` is always the process exit code: `0` nothing is BAD, `1`
could not run or a section could not be read, `2` at least one check is BAD.
After a fatal error, such as an unknown switch, a malformed value or a `/Log`
file that cannot be written, `data` is empty and the `start` line's `action`
may be empty, but the stream still opens with `start`, carries an `error`
line and closes with `result`. `/Json /?` writes the help to stderr and a
`start` and `result` line with action `Help` to stdout.

Times are UTC, to the second, as `2026-10-10T09:41:00Z`. A value Windows does
not report is `null`. Section keys appear only for the sections the action
covers; a section that could not be read is `{ "error": "..." }`.

## `result.data`

### Session

| Key | Type | Meaning |
| --- | --- | --- |
| `computer` | string | Computer name |
| `user` | string | `DOMAIN\user` of the token AuthCheck runs with |
| `elevated` | bool | Whether that token is elevated. An elevated session has its own Kerberos tickets |
| `windows` | object | `version` (with the update build), `displayVersion` (e.g. `25H2`), `edition`, `architecture` (`x64`, `ARM64`, `x86`) |
| `processArchitecture` | string | The architecture AuthCheck runs as; differs from `windows.architecture` under emulation |
| `collected` | time | When the report was made |

### `device` (`/Device`, `/Status`)

| Key | Type | Meaning |
| --- | --- | --- |
| `joinState` | string | e.g. `Microsoft Entra hybrid joined` |
| `entra` | string | `joined`, `registered`, `none` or `unknown` |
| `hybrid` | bool | Microsoft Entra joined and domain joined |
| `activeDirectory` | object | `status` (`domain`, `workgroup`, `unjoined`, `unknown`) and `name` |
| `tenantId`, `tenantName`, `deviceId`, `idpDomain`, `joinUser` | string | As `NetGetAadJoinInformation` reports them |
| `certificate` | object | The device certificate: `subject`, `issuer`, `thumbprint`, `notBefore`, `notAfter` |
| `mdmEnrollmentUrl`, `mdmTermsOfUseUrl`, `mdmComplianceUrl` | string | The MDM URLs Microsoft Entra offers this device |
| `settingSyncUris` | string[] | The settings sync endpoints, decoded |

### `prt` (`/Device`, `/Status`)

| Key | Type | Meaning |
| --- | --- | --- |
| `eligible` | bool | The device is Microsoft Entra joined or registered |
| `windowsHello` | object | `registered`, `userEmail`, `keyId`, `keyName` of the user's Windows Hello for Business key |
| `cloudKerberos` | object | `available`; then `enabledByPolicy`, `cloudTgtPresent`, `asRepCallbackPresent`, `asRepCallbackUsed`, `spnOracleConfigured`, `kdcProxyPresent`, `publicKeyCredsPresent`, `passwordKeysPresent`, `passwordPresent`, `asRepSourceCred`, `version`; or `note` when Windows does not report it |
| `prtDetails` | string | Always `not exposed by a documented API` |

### `mdm` (`/Mdm`, `/Status`)

| Key | Type | Meaning |
| --- | --- | --- |
| `managedBy` | string | e.g. `Microsoft Intune and Configuration Manager (co-managed)` |
| `enrolled`, `intune`, `thirdParty` | bool | MDM enrollment found; with Intune; with another MDM |
| `registration` | object | From `GetDeviceRegistrationInfo`: `available`, `registered`, `kind`, `kindLabel`, `upn`, `serviceUri` |
| `enrollments` | object[] | `id`, `providerId`, `kind` (`intune`, `microsoftDeviceManagement`, `configMgr`, `windowsAuthority`, `thirdParty`, `other`), `name`, `type`, `state`, `upn`, `tenantId`, `server`, `omaDm` (`serverId`, `address`, `lastSuccess`, `lastAttempt`, `lastResult`), `certificate` (`thumbprint`, `found`, `store`, `notBefore`, `notAfter`) |
| `configMgr` | object | `installed`, `clientVersion`, `siteCode`, `managementPoint`, `service`, `coManaged`, `workloadMask` (raw, undocumented bits), `note` |
| `unreadable` | string[] | Registry keys that could not be read |

### `kerberos` (`/Kerberos`, `/Status`)

| Key | Type | Meaning |
| --- | --- | --- |
| `session` | bool | The logon session has a Kerberos ticket cache |
| `note` | string | Why not, when `session` is false |
| `tickets` | object[] | `client`, `clientRealm`, `server`, `serverRealm`, `start`, `end`, `renewUntil`, `encryption` and `encryptionType`, `sessionKey` and `sessionKeyType`, `flags` (names), `flagsRaw`, `cacheFlags`, `kdcCalled` |

### `credentials` (`/Credentials`, `/Status`)

| Key | Type | Meaning |
| --- | --- | --- |
| `credentialSet` | bool | The logon session has a credential set |
| `note` | string | Why not, when `credentialSet` is false |
| `entries` | object[] | `target`, `type`, `userName`, `persistence`, `lastWritten`, `alias`, `comment`, `flags`, `attributes`. Never the secret |

## Compatibility

New keys and new line types may be added in later 1.x versions. Existing
keys keep their names and meanings; a change that breaks them waits for 2.0.
