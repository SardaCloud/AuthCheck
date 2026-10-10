// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using SardaCloud.AuthCheck.Native;

namespace SardaCloud.AuthCheck.Collectors;

enum EntraJoin { None, Joined, Registered, Unknown }

enum DomainJoin { Unknown, Unjoined, Workgroup, Domain }

/// <summary>The public facts of a certificate. Never its private key.</summary>
sealed record CertificateInfo(string Subject, string Issuer, string Thumbprint, DateTimeOffset NotBefore, DateTimeOffset NotAfter)
{
    public static CertificateInfo From(X509Certificate2 c) =>
        new(c.Subject, c.Issuer, c.Thumbprint, new DateTimeOffset(c.NotBefore), new DateTimeOffset(c.NotAfter));
}

/// <summary>What NetGetAadJoinInformation and NetGetJoinInformation report.</summary>
sealed record DeviceState(
    EntraJoin Entra,
    string? TenantId,
    string? TenantName,
    string? DeviceId,
    string? IdpDomain,
    string? JoinUser,
    string? MdmEnrollmentUrl,
    string? MdmTermsOfUseUrl,
    string? MdmComplianceUrl,
    string? SettingSyncUrl,
    CertificateInfo? Certificate,
    string? HelloUser,
    string? HelloKeyId,
    string? HelloKeyName,
    DomainJoin Domain,
    string? DomainName)
{
    public bool IsEntraRegistered => Entra is EntraJoin.Joined or EntraJoin.Registered;

    public bool IsHybrid => Entra == EntraJoin.Joined && Domain == DomainJoin.Domain;

    public string JoinSummary => (Entra, Domain) switch
    {
        (EntraJoin.Joined, DomainJoin.Domain) => "Microsoft Entra hybrid joined",
        (EntraJoin.Joined, _) => "Microsoft Entra joined",
        (EntraJoin.Registered, DomainJoin.Domain) => "Active Directory domain joined, Microsoft Entra registered",
        (EntraJoin.Registered, _) => "Microsoft Entra registered",
        (_, DomainJoin.Domain) => "Active Directory domain joined",
        _ => "Not joined to Microsoft Entra ID or a domain"
    };
}

static class DeviceCollector
{
    public static DeviceState Collect()
    {
        (DomainJoin domain, string? domainName) = ReadDomainJoin();

        int hr = NetApi.NetGetAadJoinInformation(null, out IntPtr info);
        if (hr < 0) throw new COMException($"NetGetAadJoinInformation failed with 0x{hr:X8}.", hr);
        if (info == IntPtr.Zero)
            return new DeviceState(EntraJoin.None, null, null, null, null, null, null, null, null, null,
                                   null, null, null, null, domain, domainName);
        try
        {
            var j = Marshal.PtrToStructure<NetApi.DSREG_JOIN_INFO>(info);
            NetApi.DSREG_USER_INFO user = j.pUserInfo == IntPtr.Zero
                ? default
                : Marshal.PtrToStructure<NetApi.DSREG_USER_INFO>(j.pUserInfo);

            EntraJoin entra = j.joinType switch
            {
                NetApi.DSREG_DEVICE_JOIN => EntraJoin.Joined,
                NetApi.DSREG_WORKPLACE_JOIN => EntraJoin.Registered,
                _ => EntraJoin.Unknown
            };

            return new DeviceState(
                entra,
                Str(j.pszTenantId),
                Str(j.pszTenantDisplayName),
                Str(j.pszDeviceId),
                Str(j.pszIdpDomain),
                Str(j.pszJoinUserEmail),
                Str(j.pszMdmEnrollmentUrl),
                Str(j.pszMdmTermsOfUseUrl),
                Str(j.pszMdmComplianceUrl),
                Str(j.pszUserSettingSyncUrl),
                ReadCertificate(j.pJoinCertificate),
                Str(user.pszUserEmail),
                Str(user.pszUserKeyId),
                Str(user.pszUserKeyName),
                domain,
                domainName);
        }
        finally
        {
            NetApi.NetFreeAadJoinInformation(info);
        }
    }

    static (DomainJoin, string?) ReadDomainJoin()
    {
        if (NetApi.NetGetJoinInformation(null, out IntPtr name, out int type) != 0)
            return (DomainJoin.Unknown, null);
        try
        {
            string? n = Str(name);
            return type switch
            {
                NetApi.NetSetupDomainName => (DomainJoin.Domain, n),
                NetApi.NetSetupWorkgroupName => (DomainJoin.Workgroup, n),
                NetApi.NetSetupUnjoined => (DomainJoin.Unjoined, null),
                _ => (DomainJoin.Unknown, null)
            };
        }
        finally
        {
            if (name != IntPtr.Zero) NetApi.NetApiBufferFree(name);
        }
    }

    /// <summary>Copies the public part of the join certificate before its context is freed.</summary>
    static CertificateInfo? ReadCertificate(IntPtr context)
    {
        if (context == IntPtr.Zero) return null;
        using var certificate = new X509Certificate2(context);
        return CertificateInfo.From(certificate);
    }

    static string? Str(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        string? s = Marshal.PtrToStringUni(p);
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }

    /// <summary>
    /// The settings sync URL arrives as base64-encoded JSON, {"Uris":[...]}.
    /// Returns the URIs inside it, or the value itself when it is a plain URL.
    /// </summary>
    internal static IReadOnlyList<string> SettingSyncUris(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        if (Uri.TryCreate(value, UriKind.Absolute, out _)) return [value];
        try
        {
            byte[] bytes = Convert.FromBase64String(value);
            using var json = System.Text.Json.JsonDocument.Parse(bytes);
            if (json.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object &&
                json.RootElement.TryGetProperty("Uris", out var uris) &&
                uris.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                return uris.EnumerateArray()
                           .Where(u => u.ValueKind == System.Text.Json.JsonValueKind.String)
                           .Select(u => u.GetString()!)
                           .ToList();
            }
        }
        catch (Exception ex) when (ex is FormatException or System.Text.Json.JsonException)
        {
        }
        return [value];
    }
}
