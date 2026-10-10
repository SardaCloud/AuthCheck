// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;
using SardaCloud.AuthCheck.Native;

namespace SardaCloud.AuthCheck.Collectors;

enum EnrollmentKind { Intune, MicrosoftDeviceManagement, ConfigMgr, WindowsAuthority, ThirdParty, Other }

/// <summary>What the MDM Registration API (GetDeviceRegistrationInfo) reports.</summary>
sealed record MdmApiRegistration(bool Registered, int Kind, string? Upn, string? ServiceUri)
{
    /// <summary>The DEVICEREGISTRATIONTYPE values mdmregistration.h defines.</summary>
    public string KindLabel => Kind switch
    {
        MdmRegistration.DEVICEREGISTRATIONTYPE_MDM_ONLY => "MDM only",
        MdmRegistration.DEVICEREGISTRATIONTYPE_MAM => "MAM",
        MdmRegistration.DEVICEREGISTRATIONTYPE_MDM_DEVICEWIDE_WITH_AAD => "MDM, device-wide, with Microsoft Entra ID",
        MdmRegistration.DEVICEREGISTRATIONTYPE_MDM_USERSPECIFIC_WITH_AAD => "MDM, user-specific, with Microsoft Entra ID",
        _ => $"registration kind {Kind}"
    };
}

/// <summary>An OMA-DM account: the MDM server the device syncs with, and when it last did.</summary>
sealed record OmaDmAccount(
    string Id,
    string? ServerId,
    string? Address,
    DateTimeOffset? LastSuccess,
    DateTimeOffset? LastAccess,
    int? LastResult);

sealed record MdmCertificate(string Thumbprint, CertificateInfo? Certificate, string? Store);

sealed record Enrollment(
    string Id,
    string? ProviderId,
    EnrollmentKind Kind,
    int? Type,
    int? State,
    string? Upn,
    string? TenantId,
    string? ServerUrl,
    OmaDmAccount? OmaDm,
    MdmCertificate? Certificate)
{
    public string DisplayName => Kind switch
    {
        EnrollmentKind.Intune => "Microsoft Intune",
        EnrollmentKind.MicrosoftDeviceManagement => "Microsoft Device Management",
        EnrollmentKind.ConfigMgr => "Configuration Manager",
        _ => ProviderId ?? MdmCollector.HostOf(ServerUrl) ?? "Unknown provider"
    };

    /// <summary>An MDM service the device syncs with, as opposed to a Windows-internal authority.</summary>
    public bool IsService => Kind is EnrollmentKind.Intune or EnrollmentKind.MicrosoftDeviceManagement
                                  or EnrollmentKind.ThirdParty or EnrollmentKind.Other;
}

sealed record ConfigMgrState(
    bool Installed,
    string? SiteCode,
    string? ClientVersion,
    string? ManagementPoint,
    string? Service,
    bool? CoManaged,
    string? WorkloadMask,
    string? WmiNote);

sealed record MdmState(
    MdmApiRegistration? Registration,
    string? RegistrationNote,
    IReadOnlyList<Enrollment> Enrollments,
    ConfigMgrState ConfigMgr,
    IReadOnlyList<string> Unreadable)
{
    public bool IntuneEnrolled => Enrollments.Any(e => e.Kind == EnrollmentKind.Intune);

    public bool ThirdPartyEnrolled => Enrollments.Any(e => e.Kind == EnrollmentKind.ThirdParty);

    public bool Enrolled => Registration?.Registered == true || IntuneEnrolled || ThirdPartyEnrolled;

    /// <summary>Who manages the device, in a few words.</summary>
    public string ManagedBy
    {
        get
        {
            var parts = new List<string>();
            if (IntuneEnrolled) parts.Add("Microsoft Intune");
            parts.AddRange(Enrollments.Where(e => e.Kind == EnrollmentKind.ThirdParty).Select(e => e.DisplayName));
            if (!IntuneEnrolled && Enrollments.Any(e => e.Kind == EnrollmentKind.MicrosoftDeviceManagement))
                parts.Add("Microsoft Device Management");
            if (parts.Count == 0 && Registration?.Registered == true)
                parts.Add(MdmCollector.HostOf(Registration.ServiceUri) ?? "an MDM service");
            if (ConfigMgr.Installed) parts.Add("Configuration Manager");

            if (parts.Count == 0) return "Nothing detected";
            var distinct = parts.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            string text = distinct.Count == 1
                ? distinct[0]
                : string.Join(", ", distinct.Take(distinct.Count - 1)) + " and " + distinct[^1];
            if (ConfigMgr.CoManaged == true && IntuneEnrolled) text += " (co-managed)";
            else if (ConfigMgr.Installed && ThirdPartyEnrolled) text += " (coexistence)";
            return text;
        }
    }
}

static class MdmCollector
{
    const string EnrollmentsKey = @"SOFTWARE\Microsoft\Enrollments";
    const string OmaDmAccountsKey = @"SOFTWARE\Microsoft\Provisioning\OMADM\Accounts";
    const string ConfigMgrClientKey = @"SOFTWARE\Microsoft\SMS\Mobile Client";
    const string CcmSetupKey = @"SOFTWARE\Microsoft\CCMSetup";

    // MAKE_HRESULT(SEVERITY_ERROR, facility, 11) for the two facilities mdmregistration.h uses.
    const int MREGISTER_E_DEVICE_NOT_REGISTERED = unchecked((int)0x8019000B);
    const int MENROLL_E_DEVICE_NOT_ENROLLED = unchecked((int)0x8018000B);

    public static MdmState Collect()
    {
        var unreadable = new List<string>();
        using RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

        (MdmApiRegistration? api, string? apiNote) = ReadRegistrationApi();
        Dictionary<string, OmaDmAccount> accounts = ReadOmaDmAccounts(hklm, unreadable);
        List<Enrollment> enrollments = ReadEnrollments(hklm, accounts, unreadable);
        ConfigMgrState configMgr = ReadConfigMgr(hklm, unreadable);
        return new MdmState(api, apiNote, enrollments, configMgr, unreadable);
    }

    // ------------------------------------------------------ registration API

    static (MdmApiRegistration?, string?) ReadRegistrationApi()
    {
        try
        {
            int hr = MdmRegistration.GetDeviceRegistrationInfo(MdmRegistration.DeviceRegistrationBasicInfo, out IntPtr p);
            if (hr is MREGISTER_E_DEVICE_NOT_REGISTERED or MENROLL_E_DEVICE_NOT_ENROLLED)
                return (new MdmApiRegistration(false, 0, null, null), null);
            if (hr < 0) return (null, $"GetDeviceRegistrationInfo returned 0x{hr:X8}");
            if (p == IntPtr.Zero) return (null, "GetDeviceRegistrationInfo returned no data");
            try
            {
                var info = Marshal.PtrToStructure<MdmRegistration.MANAGEMENT_REGISTRATION_INFO>(p);
                bool registered = info.fDeviceRegisteredWithManagement != 0;
                return (new MdmApiRegistration(
                    registered,
                    info.dwDeviceRegistionKind,
                    registered ? Str(info.pszUPN) : null,
                    registered ? Str(info.pszMDMServiceUri) : null), null);
            }
            finally
            {
                MdmRegistration.HeapFree(MdmRegistration.GetProcessHeap(), 0, p);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return (null, "the MDM Registration API is not available on this edition of Windows");
        }
    }

    // ------------------------------------------------------------- OMA-DM

    static Dictionary<string, OmaDmAccount> ReadOmaDmAccounts(RegistryKey hklm, List<string> unreadable)
    {
        var accounts = new Dictionary<string, OmaDmAccount>(StringComparer.OrdinalIgnoreCase);
        using RegistryKey? root = Open(hklm, OmaDmAccountsKey, unreadable);
        if (root is null) return accounts;

        foreach (string id in root.GetSubKeyNames())
        {
            using RegistryKey? account = Open(root, id, unreadable, $@"{OmaDmAccountsKey}\{id}");
            if (account is null) continue;
            using RegistryKey? protectedKey = Open(account, "Protected", unreadable, null);
            using RegistryKey? address = Open(account, @"Protected\AddrInfo", unreadable, null);
            using RegistryKey? connection = Open(account, @"Protected\ConnInfo", unreadable, null);

            accounts[id] = new OmaDmAccount(
                id,
                String(protectedKey, "ServerId"),
                String(address, "Addr"),
                ParseOmaDmTime(String(connection, "ServerLastSuccessTime")),
                ParseOmaDmTime(String(connection, "ServerLastAccessTime")),
                Int(connection, "LastSessionResult"));
        }
        return accounts;
    }

    /// <summary>OMA-DM writes its times as 20261010T090154Z.</summary>
    internal static DateTimeOffset? ParseOmaDmTime(string? value) =>
        value is not null && DateTimeOffset.TryParseExact(value, "yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTimeOffset t)
            ? t
            : null;

    // --------------------------------------------------------- enrollments

    static List<Enrollment> ReadEnrollments(RegistryKey hklm, Dictionary<string, OmaDmAccount> accounts,
                                            List<string> unreadable)
    {
        var list = new List<Enrollment>();
        using RegistryKey? root = Open(hklm, EnrollmentsKey, unreadable);
        if (root is null) return list;

        foreach (string id in root.GetSubKeyNames())
        {
            if (!Guid.TryParse(id, out _)) continue;
            using RegistryKey? key = Open(root, id, unreadable, $@"{EnrollmentsKey}\{id}");
            if (key is null) continue;

            string? provider = String(key, "ProviderID");
            string? discovery = StripQuery(String(key, "DiscoveryServiceFullURL"));
            string? upn = String(key, "UPN");
            accounts.TryGetValue(id, out OmaDmAccount? account);

            // Most subkeys are placeholders Windows keeps for its own use.
            if (provider is null && discovery is null && upn is null && account is null) continue;

            string? server = account?.Address ?? discovery;
            list.Add(new Enrollment(
                id,
                provider,
                Classify(provider, server),
                Int(key, "EnrollmentType"),
                Int(key, "EnrollmentState"),
                upn,
                String(key, "AADTenantID"),
                server,
                account,
                FindCertificate(String(key, "DMPCertThumbPrint"))));
        }

        list.Sort((a, b) => a.Kind != b.Kind
            ? a.Kind.CompareTo(b.Kind)
            : StringComparer.OrdinalIgnoreCase.Compare(a.ProviderId, b.ProviderId));
        return list;
    }

    /// <summary>
    /// Who an enrollment belongs to: by the ProviderID Windows records, or
    /// failing that by the documented service host of the MDM server.
    /// </summary>
    internal static EnrollmentKind Classify(string? providerId, string? serverUrl)
    {
        switch (providerId?.ToUpperInvariant())
        {
            case "MS DM SERVER": return EnrollmentKind.Intune;
            case "MICROSOFT DEVICE MANAGEMENT": return EnrollmentKind.MicrosoftDeviceManagement;
            case "WMI_BRIDGE_SCCM_SERVER": return EnrollmentKind.ConfigMgr;
            case "LOCAL AUTHORITY" or "DEPLOY AUTHORITY" or "CLOUD AUTHORITY": return EnrollmentKind.WindowsAuthority;
        }

        string? host = HostOf(serverUrl);
        if (host is null) return EnrollmentKind.Other;
        if (IsUnder(host, "manage.microsoft.com")) return EnrollmentKind.Intune;
        if (IsUnder(host, "dm.microsoft.com")) return EnrollmentKind.MicrosoftDeviceManagement;
        if (IsUnder(host, "microsoft.com") || IsUnder(host, "microsoftonline.com")) return EnrollmentKind.Other;
        return EnrollmentKind.ThirdParty;
    }

    internal static string? HostOf(string? url) =>
        url is not null && Uri.TryCreate(url, UriKind.Absolute, out Uri? u) && u.Host.Length > 0 ? u.Host : null;

    static bool IsUnder(string host, string domain) =>
        host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

    static string? StripQuery(string? url)
    {
        if (url is null) return null;
        int q = url.IndexOf('?');
        return q >= 0 ? url[..q] : url;
    }

    /// <summary>The MDM client certificate, looked up by thumbprint in the machine and user stores.</summary>
    static MdmCertificate? FindCertificate(string? thumbprint)
    {
        if (string.IsNullOrWhiteSpace(thumbprint)) return null;
        foreach (StoreLocation location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(StoreName.My, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection all = store.Certificates;
                try
                {
                    X509Certificate2Collection found = all.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                    if (found.Count > 0)
                        return new MdmCertificate(thumbprint, CertificateInfo.From(found[0]), $@"{location}\My");
                }
                finally
                {
                    foreach (X509Certificate2 c in all) c.Dispose();
                }
            }
            catch (CryptographicException)
            {
            }
        }
        return new MdmCertificate(thumbprint, null, null);
    }

    // --------------------------------------------------- Configuration Manager

    static ConfigMgrState ReadConfigMgr(RegistryKey hklm, List<string> unreadable)
    {
        string? siteCode = null, version = null;
        bool clientKey = false;
        using (RegistryKey? client = Open(hklm, ConfigMgrClientKey, unreadable))
        {
            if (client is not null)
            {
                clientKey = true;
                siteCode = String(client, "AssignedSiteCode");
                version = String(client, "SmsClientVersion") ?? String(client, "ProductVersion");
            }
        }

        string? service = Services.State("CcmExec");
        bool installed = clientKey || service is not null and not "NotInstalled";
        if (!installed) return new ConfigMgrState(false, null, null, null, service, null, null, null);

        // ConfigMgr's own verdict on co-management, and the workload mask it
        // applies. Readable without elevation.
        bool? coManaged = null;
        string? mask = null, note = null;
        try
        {
            var rows = Wmi.Query(@"root\ccm\InvAgt", "SELECT CoManaged, ComgmtWorkloads FROM CCM_System",
                                 ["CoManaged", "ComgmtWorkloads"]);
            if (rows.Count > 0)
            {
                coManaged = rows[0]["CoManaged"] as bool?;
                mask = Convert.ToString(rows[0]["ComgmtWorkloads"], CultureInfo.InvariantCulture);
                if (string.IsNullOrEmpty(mask)) mask = null;
            }
            else
            {
                note = "CCM_System has no instance yet";
            }
        }
        catch (COMException ex)
        {
            note = ex.Message;
        }

        string? managementPoint = null;
        try
        {
            var rows = Wmi.Query(@"root\ccm", "SELECT CurrentManagementPoint FROM SMS_Authority", ["CurrentManagementPoint"]);
            managementPoint = rows.Select(r => r["CurrentManagementPoint"] as string)
                                  .FirstOrDefault(s => !string.IsNullOrEmpty(s));
        }
        catch (COMException)
        {
        }
        if (managementPoint is null)
        {
            using RegistryKey? setup = Open(hklm, CcmSetupKey, unreadable);
            managementPoint = String(setup, "LastValidMP");
        }

        return new ConfigMgrState(true, siteCode, version, managementPoint, service, coManaged, mask, note);
    }

    // ------------------------------------------------------------ registry

    static RegistryKey? Open(RegistryKey root, string path, List<string> unreadable) =>
        Open(root, path, unreadable, path);

    /// <summary>Opens a key for reading. A key that is denied is noted when <paramref name="label"/> is given.</summary>
    static RegistryKey? Open(RegistryKey root, string path, List<string> unreadable, string? label)
    {
        try
        {
            return root.OpenSubKey(path, writable: false);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            if (label is not null) unreadable.Add($@"HKLM\{label}");
            return null;
        }
    }

    static string? String(RegistryKey? key, string name)
    {
        object? value = key?.GetValue(name);
        string? s = value switch
        {
            null => null,
            string text => text,
            string[] lines => string.Join(";", lines),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture)
        };
        return string.IsNullOrWhiteSpace(s) ? null : s.Trim();
    }

    static int? Int(RegistryKey? key, string name) => key?.GetValue(name) switch
    {
        int i => i,
        long l => unchecked((int)l),
        string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) => parsed,
        _ => null
    };

    static string? Str(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        string? s = Marshal.PtrToStringUni(p);
        return string.IsNullOrWhiteSpace(s) ? null : s;
    }
}
