// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;

namespace SardaCloud.AuthCheck.Reports;

/// <summary>Builds the dictionaries the JSON result is made of.</summary>
static class D
{
    public static Dictionary<string, object?> Of(params (string Key, object? Value)[] fields)
    {
        var d = new Dictionary<string, object?>(fields.Length);
        foreach ((string key, object? value) in fields) d[key] = value;
        return d;
    }

    public static Dictionary<string, object?>? Of(CertificateInfo? c) => c is null ? null : Of(
        ("subject", c.Subject),
        ("issuer", c.Issuer),
        ("thumbprint", c.Thumbprint),
        ("notBefore", c.NotBefore),
        ("notAfter", c.NotAfter));

    public static Dictionary<string, object?> Error(Exception ex) => Of(("error", ex.Message));
}

/// <summary>The verdict on a certificate's validity period.</summary>
static class CertificateCheck
{
    public const int WarnDays = 30;

    public static Finding Assess(string label, CertificateInfo? c, DateTimeOffset now, string? whose = null)
    {
        string prefix = whose is null ? "" : whose + ": ";
        if (c is null) return Finding.Bad(label, prefix + "missing");
        if (now < c.NotBefore) return Finding.Bad(label, $"{prefix}not valid until {Format.Date(c.NotBefore)}");
        if (now >= c.NotAfter) return Finding.Bad(label, $"{prefix}expired on {Format.Date(c.NotAfter)}");
        if (c.NotAfter - now < TimeSpan.FromDays(WarnDays))
            return Finding.Warn(label, $"{prefix}expires on {Format.Date(c.NotAfter)}, {Format.Relative(c.NotAfter, now)}");
        return Finding.Ok(label, $"{prefix}valid until {Format.Date(c.NotAfter)}");
    }
}

/// <summary>Who is running AuthCheck, where, and with which rights.</summary>
sealed record SessionContext(
    string Computer,
    string User,
    bool Elevated,
    string WindowsVersion,
    string? DisplayVersion,
    string? Edition,
    Architecture OsArchitecture,
    Architecture ProcessArchitecture,
    DateTimeOffset Collected)
{
    public static SessionContext Read(DateTimeOffset now)
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        string version = Environment.OSVersion.Version.ToString(3);
        string? display = null, edition = null;
        try
        {
            using RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using RegistryKey? cv = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (cv?.GetValue("UBR") is int ubr) version += "." + ubr;
            display = cv?.GetValue("DisplayVersion") as string;
            edition = cv?.GetValue("EditionID") as string;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }

        return new SessionContext(Environment.MachineName, identity.Name, elevated, version, display, edition,
                                  RuntimeInformation.OSArchitecture, RuntimeInformation.ProcessArchitecture, now);
    }

    public string WindowsText
    {
        get
        {
            var parts = new List<string> { WindowsVersion };
            if (!string.IsNullOrEmpty(DisplayVersion)) parts.Add(DisplayVersion);
            if (!string.IsNullOrEmpty(Edition)) parts.Add(Edition);
            parts.Add(Name(OsArchitecture));
            string text = string.Join(", ", parts);
            if (ProcessArchitecture != OsArchitecture)
            {
                // x86 runs natively on x64 Windows through WOW64; on ARM64
                // Windows, x86 and x64 code is emulated.
                string how = OsArchitecture == Architecture.Arm64 ? "emulated" : "under WOW64";
                text += $" (AuthCheck runs as {Name(ProcessArchitecture)}, {how})";
            }
            return text;
        }
    }

    /// <summary>The way Windows writes architectures: x86, x64, ARM64.</summary>
    public static string Name(Architecture a) => a switch
    {
        Architecture.X86 => "x86",
        Architecture.X64 => "x64",
        Architecture.Arm64 => "ARM64",
        Architecture.Arm => "ARM",
        _ => a.ToString()
    };
}

static class ContextReport
{
    public static void Show(Reporter r, SessionContext s)
    {
        r.Blank();
        r.Kv("Computer", s.Computer);
        r.Kv("User", s.User);
        r.Kv("Elevated", s.Elevated
            ? "yes - an elevated session has its own Kerberos tickets"
            : "no");
        r.Kv("Windows", s.WindowsText);
        r.Kv("Collected", Format.Time(s.Collected));
    }

    public static Dictionary<string, object?> Data(SessionContext s) => D.Of(
        ("computer", s.Computer),
        ("user", s.User),
        ("elevated", s.Elevated),
        ("windows", D.Of(
            ("version", s.WindowsVersion),
            ("displayVersion", s.DisplayVersion),
            ("edition", s.Edition),
            ("architecture", SessionContext.Name(s.OsArchitecture)))),
        ("processArchitecture", SessionContext.Name(s.ProcessArchitecture)),
        ("collected", s.Collected));
}
