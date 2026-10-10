// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Reflection;

namespace SardaCloud.AuthCheck;

/// <summary>The names and notices the tool shows about itself.</summary>
static class Product
{
    public const string Name = "AuthCheck";
    public const string Purpose = "sign-in, device and management status";
    public const string Copyright = "Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com";
    public const string License = "Licensed under the MIT License";
    public const string Repository = "https://github.com/SardaCloud/AuthCheck";

    /// <summary>The release version, e.g. 1.0.0, taken from the VERSION file at build time.</summary>
    public static string Version { get; } = ReadVersion();

    /// <summary>Major and minor only, as the banner shows it.</summary>
    public static string ShortVersion
    {
        get
        {
            string[] parts = Version.Split('.');
            return parts.Length >= 2 ? $"{parts[0]}.{parts[1]}" : Version;
        }
    }

    static string ReadVersion()
    {
        string? v = typeof(Product).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrWhiteSpace(v)) return "0.0.0";
        int plus = v.IndexOf('+');
        return plus >= 0 ? v[..plus] : v;
    }
}

/// <summary>Process exit codes, the same as the other Sarda Cloud tools use.</summary>
static class ExitCode
{
    /// <summary>Ran, and nothing needs attention.</summary>
    public const int Success = 0;

    /// <summary>Could not run, or could not read a section: bad switch, API failure.</summary>
    public const int Error = 1;

    /// <summary>Ran, and at least one check is BAD.</summary>
    public const int Findings = 2;
}

/// <summary>
/// A problem with the command line or the environment rather than a bug. The
/// message is shown on its own, without a stack trace.
/// </summary>
sealed class AuthCheckException(string message, int code = ExitCode.Error) : Exception(message)
{
    public int Code { get; } = code;
}
