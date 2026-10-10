// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

namespace SardaCloud.AuthCheck.Cli;

static class Usage
{
    /// <summary>Every accepted spelling of every action, aliases included.</summary>
    public static readonly IReadOnlyDictionary<string, string> Actions =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Status"] = "Status",
            ["Device"] = "Device",
            ["Dsreg"] = "Device",
            ["Mdm"] = "Mdm",
            ["Kerberos"] = "Kerberos",
            ["Klist"] = "Kerberos",
            ["Credentials"] = "Credentials",
            ["Cmdkey"] = "Credentials"
        };

    /// <summary>The switches that take a value. Every other switch is a flag.</summary>
    public static readonly string[] TakesValue = ["Action", "Log"];

    /// <summary>Prints the help: to stdout normally, to stderr under /Json, where stdout is JSON only.</summary>
    public static void Print(TextWriter to)
    {
        to.WriteLine();
        to.WriteLine($"  {Product.Name} {Product.Version} - {Product.Purpose}");
        to.WriteLine($"  {Product.Copyright}");
        to.WriteLine($"  {Product.License}. {Product.Repository}");
        to.WriteLine(Text);
    }

    const string Text = """

  AuthCheck shows in one report how this device and the signed-in user
  authenticate and are managed: Microsoft Entra and Active Directory join,
  Primary Refresh Token readiness, MDM enrollment with Microsoft Intune,
  Configuration Manager co-management or a third-party MDM, cached Kerberos
  tickets and saved Credential Manager entries.

  Everything is read through documented Windows APIs, WMI and the registry.
  dsregcmd, klist and cmdkey are never run, nothing is changed, no elevation
  is needed, and no secret reaches the output: no password, ticket, token or
  key, only the facts about them.

  AuthCheck.exe [/<Action>] [switches]
  AuthCheck.exe /Action <Action> [switches]

ACTIONS
  /Status           Every section below, in order. The default.
  /Device           Microsoft Entra and Active Directory join, tenant,
                    device certificate, Windows Hello for Business key and
                    the Primary Refresh Token and Cloud Kerberos signals.
                    Alias /Dsreg.
  /Mdm              MDM enrollments and their last sync, Microsoft Intune,
                    third-party MDM, the Configuration Manager client and
                    co-management.
  /Kerberos         The Kerberos tickets cached for this logon session, with
                    their times, flags and encryption. Alias /Klist.
  /Credentials      Credential Manager entries: target, type, user name,
                    persistence and last change. Never the secret. Alias
                    /Cmdkey.

COMMON
  /Json             JSON Lines on stdout, ending in a "result" line that
                    carries the whole report. The text report moves to
                    stderr.
  /Quiet            Show only warnings and problems.
  /Verbose          Show more: every enrollment record, raw flags, ticket
                    cache flags, credential comments and aliases.
  /NoLogo           Leave out the banner.
  /Log <file>       Append a plain-text copy of the report to <file>.
  /?                This help. Also /h and /Help.

  Switches start with / or -, and are not case-sensitive.

CHECKS
  Each section ends with checks marked OK, WARN or BAD. BAD means something
  is broken now: an expired or missing device certificate, an expired MDM
  certificate, a DES-encrypted Kerberos ticket. WARN means it deserves a look:
  no MDM sync for 7 days, an RC4 ticket, a certificate expiring within 30
  days, Cloud Kerberos enabled without a cloud TGT.

EXIT CODES
  0                 Ran, and nothing is BAD.
  1                 Could not run, or a section could not be read.
  2                 Ran, and at least one check is BAD.

LOGON SESSIONS
  Kerberos tickets and saved credentials belong to a logon session. An
  elevated prompt runs in a session of its own, with its own tickets, so run
  AuthCheck in the window whose tickets you want to see. A remote PowerShell
  session has neither.

EXAMPLES
  AuthCheck
      Everything, as a readable report.

  AuthCheck /Device
      Join state and sign-in readiness: what dsregcmd /status shows.

  AuthCheck /Klist /Verbose
      The cached Kerberos tickets, with every flag.

  AuthCheck /Mdm /Quiet
      Only the MDM warnings and problems; the exit code says if any is BAD.

  AuthCheck /Json > authcheck.jsonl
      Machine-readable output for a script or a support case.

  AuthCheck /Json 2>$null | Select-Object -Last 1 | ConvertFrom-Json
      PowerShell: the whole report as one object, e.g. (...).data.mdm.

  AuthCheck /Status /Log C:\Logs\authcheck.log /Quiet
      A scheduled check that keeps a full transcript and prints problems.
""";
}
