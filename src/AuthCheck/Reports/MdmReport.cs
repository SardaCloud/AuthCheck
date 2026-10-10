// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Globalization;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;

namespace SardaCloud.AuthCheck.Reports;

static class MdmReport
{
    /// <summary>No successful MDM sync for longer than this is a warning.</summary>
    public static readonly TimeSpan SyncWarnAfter = TimeSpan.FromDays(7);

    public static void Show(Reporter r, MdmState m, DeviceState? device, DateTimeOffset now)
    {
        r.Kv("Managed by", m.ManagedBy);
        if (m.Registration is { } api)
        {
            r.Kv("MDM registration", api.Registered ? $"yes - {api.KindLabel}" : "no");
            r.Kv("MDM user", api.Upn);
            r.Kv("MDM service", api.ServiceUri);
        }
        else
        {
            r.Kv("MDM registration", m.RegistrationNote);
        }

        foreach (Enrollment e in m.Enrollments)
        {
            // The Configuration Manager bridge is shown with the client below.
            if (e.Kind == EnrollmentKind.ConfigMgr) continue;
            if (e.Kind == EnrollmentKind.WindowsAuthority && !r.Verbose) continue;
            bool showProvider = e.ProviderId is not null && !e.ProviderId.Equals(e.DisplayName, StringComparison.OrdinalIgnoreCase);
            r.Item(showProvider ? $"{e.DisplayName}  [{e.ProviderId}]" : e.DisplayName);
            r.Kv("Enrollment ID", e.Id, 4);
            r.Kv("User", e.Upn, 4);
            r.Kv("Tenant ID", e.TenantId, 4);
            r.Kv("Server", e.ServerUrl, 4);
            if (e.OmaDm is { } a)
            {
                r.Kv("Last sync", a.LastSuccess is { } ok ? $"{Format.Time(ok)} ({Format.Relative(ok, now)})" : "never", 4);
                r.Detail("Last attempt", a.LastAccess is { } at ? $"{Format.Time(at)} ({Format.Relative(at, now)})" : null, 4);
                r.Kv("Last result", a.LastResult switch { null => null, 0 => "success", int x => Format.Hex(x) }, 4);
            }
            if (e.Certificate is { } mc)
            {
                r.Kv("Certificate", mc.Thumbprint, 4);
                r.Kv("Valid", mc.Certificate is { } c
                    ? $"{Format.Date(c.NotBefore)} to {Format.Date(c.NotAfter)}"
                    : @"not found in LocalMachine\My or CurrentUser\My", 4);
            }
            r.Detail("Enrollment type", e.Type?.ToString(CultureInfo.InvariantCulture), 4);
            r.Detail("Enrollment state", e.State?.ToString(CultureInfo.InvariantCulture), 4);
        }

        ConfigMgrState cm = m.ConfigMgr;
        Enrollment? bridge = m.Enrollments.FirstOrDefault(e => e.Kind == EnrollmentKind.ConfigMgr);
        r.Item("Configuration Manager");
        if (!cm.Installed)
        {
            r.Kv("Client", "not installed", 4);
            r.Kv("MDM bridge", bridge is null ? null : $"enrollment {bridge.Id} remains from an earlier client", 4);
        }
        else
        {
            r.Kv("Client version", cm.ClientVersion, 4);
            r.Kv("Site code", cm.SiteCode, 4);
            r.Kv("Management point", cm.ManagementPoint, 4);
            r.Kv("CcmExec service", cm.Service, 4);
            r.Kv("MDM bridge", bridge is null ? "not registered" : $"registered ({bridge.Id})", 4);
            r.Kv("Co-management", CoManagementText(m), 4);
            r.Kv("Workload mask", WorkloadText(cm.WorkloadMask), 4);
            r.Kv("WMI", cm.WmiNote, 4);
        }

        foreach (string key in m.Unreadable) r.Warn($"Could not read {key}; run elevated to include it.");

        r.Blank();
        r.Checks(Assess(m, device, now));
    }

    public static IReadOnlyList<Finding> Assess(MdmState m, DeviceState? device, DateTimeOffset now)
    {
        var list = new List<Finding>();

        var services = m.Enrollments
            .Where(e => e.Kind is EnrollmentKind.Intune or EnrollmentKind.ThirdParty)
            .Select(e => e.DisplayName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (services.Count > 0)
            list.Add(Finding.Ok("MDM enrollment", string.Join(", ", services)));
        else if (m.Registration?.Registered == true)
            list.Add(Finding.Ok("MDM enrollment", $"enrolled with {MdmCollector.HostOf(m.Registration.ServiceUri) ?? "an MDM service"}"));
        else if (device?.MdmEnrollmentUrl is not null)
            list.Add(Finding.Warn("MDM enrollment", "Microsoft Entra offers an MDM enrollment URL, but the device is not enrolled"));

        foreach (Enrollment e in m.Enrollments.Where(e => e.IsService))
        {
            if (e.OmaDm is { } a)
            {
                if (a.LastSuccess is not { } last)
                    list.Add(Finding.Warn("Last MDM sync", $"{e.DisplayName}: no successful sync recorded"));
                else if (now - last > SyncWarnAfter)
                    list.Add(Finding.Warn("Last MDM sync", $"{e.DisplayName}: {Format.Relative(last, now)}"));
                else
                    list.Add(Finding.Ok("Last MDM sync", $"{e.DisplayName}: {Format.Relative(last, now)}"));

                if (a.LastResult is int code && code != 0)
                    list.Add(Finding.Warn("MDM sync result", $"{e.DisplayName}: the last session ended with {Format.Hex(code)}"));
            }

            if (e.Certificate is { } mc)
            {
                list.Add(mc.Certificate is null
                    ? Finding.Warn("MDM certificate", $"{e.DisplayName}: {mc.Thumbprint} is not in the certificate store")
                    : CertificateCheck.Assess("MDM certificate", mc.Certificate, now, e.DisplayName));
            }
        }

        ConfigMgrState cm = m.ConfigMgr;
        if (cm.Installed)
        {
            if (cm.Service is not null and not "Running")
                list.Add(Finding.Warn("ConfigMgr client", $"the CcmExec service is {cm.Service}"));

            if (cm.CoManaged == true)
            {
                list.Add(m.IntuneEnrolled
                    ? Finding.Ok("Co-management", "Microsoft Intune and Configuration Manager")
                    : Finding.Warn("Co-management", "Configuration Manager reports co-management, but no Intune enrollment was found"));
            }
            else if (cm.CoManaged == false && m.IntuneEnrolled)
            {
                list.Add(Finding.Warn("Co-management",
                    "Intune-enrolled with a Configuration Manager client, but Configuration Manager does not report co-management"));
            }
        }

        return list;
    }

    public static Dictionary<string, object?> Data(MdmState m) => D.Of(
        ("managedBy", m.ManagedBy),
        ("enrolled", m.Enrolled),
        ("intune", m.IntuneEnrolled),
        ("thirdParty", m.ThirdPartyEnrolled),
        ("registration", m.Registration is not { } api ? D.Of(("available", false), ("note", m.RegistrationNote)) : D.Of(
            ("available", true),
            ("registered", api.Registered),
            ("kind", api.Kind),
            ("kindLabel", api.KindLabel),
            ("upn", api.Upn),
            ("serviceUri", api.ServiceUri))),
        ("enrollments", m.Enrollments.Select(e => D.Of(
            ("id", e.Id),
            ("providerId", e.ProviderId),
            ("kind", e.Kind),
            ("name", e.DisplayName),
            ("type", e.Type),
            ("state", e.State),
            ("upn", e.Upn),
            ("tenantId", e.TenantId),
            ("server", e.ServerUrl),
            ("omaDm", e.OmaDm is not { } a ? null : D.Of(
                ("serverId", a.ServerId),
                ("address", a.Address),
                ("lastSuccess", a.LastSuccess),
                ("lastAttempt", a.LastAccess),
                ("lastResult", a.LastResult))),
            ("certificate", e.Certificate is not { } mc ? null : D.Of(
                ("thumbprint", mc.Thumbprint),
                ("found", mc.Certificate is not null),
                ("store", mc.Store),
                ("notBefore", mc.Certificate?.NotBefore),
                ("notAfter", mc.Certificate?.NotAfter))))).ToList()),
        ("configMgr", D.Of(
            ("installed", m.ConfigMgr.Installed),
            ("clientVersion", m.ConfigMgr.ClientVersion),
            ("siteCode", m.ConfigMgr.SiteCode),
            ("managementPoint", m.ConfigMgr.ManagementPoint),
            ("service", m.ConfigMgr.Service),
            ("coManaged", m.ConfigMgr.CoManaged),
            ("workloadMask", m.ConfigMgr.WorkloadMask),
            ("note", m.ConfigMgr.WmiNote))),
        ("unreadable", m.Unreadable));

    static string CoManagementText(MdmState m) => m.ConfigMgr.CoManaged switch
    {
        true => "yes - Configuration Manager reports this device as co-managed",
        false when m.ThirdPartyEnrolled => "no - coexistence with a third-party MDM",
        false => "no",
        null => "unknown"
    };

    /// <summary>
    /// The raw ComgmtWorkloads value. Microsoft does not document what each bit
    /// means, so AuthCheck shows the number rather than guess.
    /// </summary>
    static string? WorkloadText(string? mask)
    {
        if (mask is null) return null;
        return long.TryParse(mask, NumberStyles.Integer, CultureInfo.InvariantCulture, out long value)
            ? $"{value.ToString(CultureInfo.InvariantCulture)} (0x{value:X8})"
            : mask;
    }
}
