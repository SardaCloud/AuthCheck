// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;

namespace SardaCloud.AuthCheck.Reports;

static class DeviceReport
{
    public static void Show(Reporter r, DeviceState d, DateTimeOffset now)
    {
        r.Kv("Join state", d.JoinSummary);
        r.Kv("Active Directory", d.Domain switch
        {
            DomainJoin.Domain => $"{d.DomainName} (domain)",
            DomainJoin.Workgroup => $"{d.DomainName} (workgroup)",
            DomainJoin.Unjoined => "not joined",
            _ => "unknown"
        });
        r.Kv("Microsoft Entra", d.Entra switch
        {
            EntraJoin.Joined => "joined",
            EntraJoin.Registered => "registered",
            EntraJoin.Unknown => "unknown join type",
            _ => "not joined or registered"
        });

        if (d.Entra != EntraJoin.None)
        {
            r.Kv("Tenant", Tenant(d.TenantName, d.TenantId));
            r.Kv("Device ID", d.DeviceId);
            r.Kv("Identity provider", d.IdpDomain);
            r.Kv("Joined by", d.JoinUser);
            if (d.Certificate is { } c)
            {
                r.Kv("Device certificate", c.Thumbprint);
                r.Kv("Valid", $"{Format.Date(c.NotBefore)} to {Format.Date(c.NotAfter)}", 4);
                r.Detail("Subject", c.Subject, 4);
                r.Detail("Issuer", c.Issuer, 4);
            }
            r.Kv("MDM enrollment URL", d.MdmEnrollmentUrl);
            r.Detail("MDM terms of use URL", d.MdmTermsOfUseUrl);
            r.Kv("MDM compliance URL", d.MdmComplianceUrl);
            IReadOnlyList<string> sync = DeviceCollector.SettingSyncUris(d.SettingSyncUrl);
            for (int i = 0; i < sync.Count; i++)
                r.Detail(i == 0 ? "Settings sync" : "", sync[i]);
        }

        r.Blank();
        r.Checks(Assess(d, now));
    }

    public static IReadOnlyList<Finding> Assess(DeviceState d, DateTimeOffset now)
    {
        var list = new List<Finding>
        {
            d.Entra switch
            {
                EntraJoin.Joined => Finding.Ok("Microsoft Entra", d.IsHybrid ? "hybrid joined" : "joined"),
                EntraJoin.Registered => Finding.Ok("Microsoft Entra", "registered: a work or school account was added"),
                EntraJoin.Unknown => Finding.Warn("Microsoft Entra", "Windows reports join information of an unknown type"),
                _ => Finding.Warn("Microsoft Entra", "neither joined nor registered: no Primary Refresh Token, no Entra single sign-on")
            }
        };
        if (d.IsEntraRegistered)
            list.Add(CertificateCheck.Assess("Device certificate", d.Certificate, now));
        return list;
    }

    public static Dictionary<string, object?> Data(DeviceState d) => D.Of(
        ("joinState", d.JoinSummary),
        ("entra", d.Entra),
        ("hybrid", d.IsHybrid),
        ("activeDirectory", D.Of(("status", d.Domain), ("name", d.DomainName))),
        ("tenantId", d.TenantId),
        ("tenantName", d.TenantName),
        ("deviceId", d.DeviceId),
        ("idpDomain", d.IdpDomain),
        ("joinUser", d.JoinUser),
        ("certificate", D.Of(d.Certificate)),
        ("mdmEnrollmentUrl", d.MdmEnrollmentUrl),
        ("mdmTermsOfUseUrl", d.MdmTermsOfUseUrl),
        ("mdmComplianceUrl", d.MdmComplianceUrl),
        ("settingSyncUris", DeviceCollector.SettingSyncUris(d.SettingSyncUrl)));

    static string? Tenant(string? name, string? id) =>
        name is null ? id : id is null ? name : $"{name} ({id})";
}

static class PrtReport
{
    public static void Show(Reporter r, DeviceState? d, CloudKerberosResult cloud)
    {
        r.Kv("PRT eligible", d?.Entra switch
        {
            EntraJoin.Joined => "yes - the device is Microsoft Entra joined",
            EntraJoin.Registered => "yes - for the work or school account that was added",
            null => "unknown - the join state could not be read",
            _ => "no - the device has no Microsoft Entra registration"
        });

        if (d is not null)
        {
            r.Kv("Windows Hello key", d.HelloKeyId is null
                ? "none registered for this user"
                : d.HelloUser is null ? "registered" : $"registered for {d.HelloUser}");
            r.Detail("Key ID", d.HelloKeyId, 4);
            r.Detail("Key name", d.HelloKeyName, 4);
        }

        if (cloud.State is { } c)
        {
            r.Kv("Cloud Kerberos", c.EnabledByPolicy ? "enabled by policy" : "not enabled by policy");
            r.Kv("Cloud TGT", c.CloudReferralTgtAvailable ? "present in this logon session" : "not present");
            r.Detail("AS-REP callback", c.AsRepCallbackPresent ? (c.AsRepCallbackUsed ? "present, used" : "present, not used") : "not present", 4);
            r.Detail("SPN oracle", c.SpnOracleConfigured ? "configured" : "not configured", 4);
            r.Detail("KDC proxy", c.KdcProxyPresent ? "present in the cache" : "not present", 4);
            if (c.PublicKeyCredsPresent is bool pk) r.Detail("Public key credential", Format.YesNo(pk), 4);
            if (c.PasswordKeysPresent is bool pwk) r.Detail("Password-derived keys", Format.YesNo(pwk), 4);
            if (c.PasswordPresent is bool pw) r.Detail("Plaintext password", Format.YesNo(pw), 4);
            if (c.AsRepSourceCred is int src) r.Detail("AS-REP credential type", src.ToString(System.Globalization.CultureInfo.InvariantCulture), 4);
        }
        else
        {
            r.Kv("Cloud Kerberos", cloud.Note);
        }

        r.Blank();
        r.Note("Whether a PRT is held right now, and when it was issued and expires, is kept by the " +
               "CloudAP security package and is not exposed through a documented API. These are the " +
               "signals Windows does document.");
        r.Blank();
        r.Checks(Assess(d, cloud));
    }

    public static IReadOnlyList<Finding> Assess(DeviceState? d, CloudKerberosResult cloud)
    {
        var list = new List<Finding>();
        if (cloud.State is { EnabledByPolicy: true } c && d?.IsEntraRegistered != false)
        {
            list.Add(c.CloudReferralTgtAvailable
                ? Finding.Ok("Cloud Kerberos", "cloud TGT present in this logon session")
                : Finding.Warn("Cloud Kerberos", "enabled by policy, but this logon session has no cloud TGT"));
        }
        return list;
    }

    public static Dictionary<string, object?> Data(DeviceState? d, CloudKerberosResult cloud) => D.Of(
        ("eligible", d?.IsEntraRegistered),
        ("windowsHello", d is null ? null : D.Of(
            ("registered", d.HelloKeyId is not null),
            ("userEmail", d.HelloUser),
            ("keyId", d.HelloKeyId),
            ("keyName", d.HelloKeyName))),
        ("cloudKerberos", cloud.State is not { } c ? D.Of(("available", false), ("note", cloud.Note)) : D.Of(
            ("available", true),
            ("version", c.Version),
            ("enabledByPolicy", c.EnabledByPolicy),
            ("cloudTgtPresent", c.CloudReferralTgtAvailable),
            ("asRepCallbackPresent", c.AsRepCallbackPresent),
            ("asRepCallbackUsed", c.AsRepCallbackUsed),
            ("spnOracleConfigured", c.SpnOracleConfigured),
            ("kdcProxyPresent", c.KdcProxyPresent),
            ("publicKeyCredsPresent", c.PublicKeyCredsPresent),
            ("passwordKeysPresent", c.PasswordKeysPresent),
            ("passwordPresent", c.PasswordPresent),
            ("asRepSourceCred", c.AsRepSourceCred))),
        ("prtDetails", "not exposed by a documented API"));
}
