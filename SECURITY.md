# Security

Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com. Licensed under the MIT License.

## Reporting a vulnerability

Report privately, not in a public issue. Use GitHub's **Report a
vulnerability** button under the [Security tab](https://github.com/SardaCloud/AuthCheck/security),
or contact Sarda Cloud Srl through [www.sardacloud.com](https://www.sardacloud.com).

Please say what an attacker gains, how to reproduce it, and which version or
commit you used. You will get an acknowledgement within five working days.

## What AuthCheck promises

AuthCheck is a read-only diagnostic. It promises three things, and a way to
break any of them is in scope:

1. **No secret reaches its output.** No password, Kerberos ticket or session
   key, token or private key may appear on the console, in `/Json` output or
   in a `/Log` file, whatever the switches.
2. **It changes nothing.** It writes no registry value, no certificate, no
   credential, no ticket and no policy, and the only file it creates is the
   one `/Log` names.
3. **It starts no other process** and asks for no elevation.

Also in scope: a crafted registry value, WMI result or certificate that makes
AuthCheck crash, hang or misreport in a way that could mislead an
administrator, and the `/Json` contract being broken so that a caller is
misled about success.

## Known and accepted

**The report identifies people and machines.** User names, tenant and device
IDs, host names and server URLs are what the report is for. Review it before
sharing it.

**Windows hands generic-credential secrets to the caller.** `CredEnumerateW`
returns the secret of a generic credential to whoever enumerates Credential
Manager, as it does for `cmdkey`. AuthCheck never reads it, wipes it, and
frees the buffer at once. That the secret is briefly in AuthCheck's memory is
how the API works, not a vulnerability.

**Kerberos data is per logon session.** AuthCheck asks only about its own
session and never about another user's; that would need privileges it does
not request.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
