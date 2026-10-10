// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Globalization;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;

namespace SardaCloud.AuthCheck.Reports;

static class KerberosReport
{
    public static void Show(Reporter r, KerberosState k, DeviceState? device, string userDomain, DateTimeOffset now)
    {
        if (!k.HasSession)
        {
            r.Note(k.Note ?? "No Kerberos logon session.");
            r.Blank();
            r.Checks(Assess(k, device, userDomain, now));
            return;
        }

        r.Kv("Cached tickets", k.Tickets.Count.ToString(CultureInfo.InvariantCulture));
        for (int i = 0; i < k.Tickets.Count; i++)
        {
            KerberosTicket t = k.Tickets[i];
            r.Item($"#{i}  {t.Server} @ {t.ServerRealm}");
            r.Kv("Client", $"{t.Client} @ {t.ClientRealm}", 4);
            string expired = t.End is { } end && end <= now ? "  (expired)" : "";
            r.Kv("Valid", $"{Format.Time(t.Start)} to {Format.Time(t.End)}{expired}", 4);
            r.Kv("Renew until", Format.Time(t.RenewUntil), 4);
            r.Kv("Encryption", EncryptionText(t), 4);
            r.Kv("Flags", string.Join(" ", KerberosNames.Flags(t.Flags)), 4);
            r.Detail("Flags (raw)", Format.Hex(t.Flags), 4);
            r.Kv("KDC called", t.KdcCalled, 4);
            r.Detail("Cache flags", t.CacheFlags is uint cf ? Format.Hex(cf) : null, 4);
        }

        r.Blank();
        r.Checks(Assess(k, device, userDomain, now));
    }

    public static IReadOnlyList<Finding> Assess(KerberosState k, DeviceState? device, string userDomain, DateTimeOffset now)
    {
        var list = new List<Finding>();
        if (!k.HasSession)
        {
            list.Add(Finding.Warn("Kerberos", "this logon session has no Kerberos ticket cache"));
            return list;
        }

        KerberosTicket? tgt = k.Tickets.Where(t => t.IsTgt).OrderByDescending(t => t.End).FirstOrDefault();
        bool domainLogon = device is { Domain: DomainJoin.Domain, DomainName: { } domain }
                           && userDomain.Equals(domain, StringComparison.OrdinalIgnoreCase);
        if (tgt is not null)
        {
            list.Add(tgt.End is { } end && end <= now
                ? Finding.Warn("Kerberos TGT", $"{tgt.Server} expired at {Format.Time(end)}")
                : Finding.Ok("Kerberos TGT", $"{tgt.Server}, valid until {Format.Time(tgt.End)}"));
        }
        else if (domainLogon)
        {
            list.Add(Finding.Warn("Kerberos TGT", "none cached, although this is a domain logon"));
        }

        var des = k.Tickets.Where(t => Uses(t, KerberosNames.IsDes)).ToList();
        var rc4 = k.Tickets.Where(t => !des.Contains(t) && Uses(t, KerberosNames.IsRc4)).ToList();
        if (des.Count > 0)
            list.Add(Finding.Bad("Ticket encryption", $"DES in {Format.Plural(des.Count, "ticket")}: {Servers(des)}"));
        if (rc4.Count > 0)
            list.Add(Finding.Warn("Ticket encryption", $"RC4 in {Format.Plural(rc4.Count, "ticket")}: {Servers(rc4)}"));
        if (des.Count == 0 && rc4.Count == 0 && k.Tickets.Count > 0)
            list.Add(Finding.Ok("Ticket encryption", "no DES or RC4 in any ticket or session key"));

        return list;
    }

    public static Dictionary<string, object?> Data(KerberosState k) => D.Of(
        ("session", k.HasSession),
        ("note", k.Note),
        ("tickets", k.Tickets.Select(t => D.Of(
            ("client", t.Client),
            ("clientRealm", t.ClientRealm),
            ("server", t.Server),
            ("serverRealm", t.ServerRealm),
            ("start", t.Start),
            ("end", t.End),
            ("renewUntil", t.RenewUntil),
            ("encryption", KerberosNames.Encryption(t.EncryptionType)),
            ("encryptionType", t.EncryptionType),
            ("sessionKey", t.SessionKeyType is int s ? KerberosNames.Encryption(s) : null),
            ("sessionKeyType", t.SessionKeyType),
            ("flags", KerberosNames.Flags(t.Flags)),
            ("flagsRaw", t.Flags),
            ("cacheFlags", t.CacheFlags),
            ("kdcCalled", t.KdcCalled))).ToList()));

    static bool Uses(KerberosTicket t, Func<int, bool> weak) =>
        weak(t.EncryptionType) || (t.SessionKeyType is int s && weak(s));

    static string EncryptionText(KerberosTicket t)
    {
        string ticket = KerberosNames.Encryption(t.EncryptionType);
        return t.SessionKeyType is int s && s != t.EncryptionType
            ? $"{ticket}, session key {KerberosNames.Encryption(s)}"
            : ticket;
    }

    static string Servers(List<KerberosTicket> tickets)
    {
        var names = tickets.Select(t => t.Server).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return names.Count <= 3 ? string.Join(", ", names) : string.Join(", ", names.Take(3)) + $" and {names.Count - 3} more";
    }
}

static class CredentialReport
{
    public static void Show(Reporter r, CredentialState c)
    {
        if (!c.HasCredentialSet)
        {
            r.Note(c.Note ?? "No credential set.");
            return;
        }

        r.Kv("Entries", c.Entries.Count.ToString(CultureInfo.InvariantCulture));
        foreach (StoredCredential e in c.Entries)
        {
            r.Item(e.Target);
            r.Kv("Type", e.Type, 4);
            r.Kv("User", e.UserName, 4);
            r.Kv("Persistence", e.Persistence, 4);
            r.Kv("Last written", Format.Time(e.LastWritten), 4);
            r.Detail("Alias", e.TargetAlias, 4);
            r.Detail("Comment", e.Comment, 4);
            r.Detail("Flags", Format.Hex(e.Flags), 4);
            r.Detail("Attributes", e.AttributeCount.ToString(CultureInfo.InvariantCulture), 4);
        }
        r.Blank();
        r.Note("Only the facts about each entry are shown. Secrets never reach the output.");
    }

    public static Dictionary<string, object?> Data(CredentialState c) => D.Of(
        ("credentialSet", c.HasCredentialSet),
        ("note", c.Note),
        ("entries", c.Entries.Select(e => D.Of(
            ("target", e.Target),
            ("type", e.Type),
            ("userName", e.UserName),
            ("persistence", e.Persistence),
            ("lastWritten", e.LastWritten),
            ("alias", e.TargetAlias),
            ("comment", e.Comment),
            ("flags", e.Flags),
            ("attributes", e.AttributeCount))).ToList()));
}
