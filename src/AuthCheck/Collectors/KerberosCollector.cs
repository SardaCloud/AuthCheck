// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.ComponentModel;
using System.Runtime.InteropServices;
using SardaCloud.AuthCheck.Native;

namespace SardaCloud.AuthCheck.Collectors;

/// <summary>One cached ticket: the facts klist shows, never the ticket or its key.</summary>
sealed record KerberosTicket(
    string Client,
    string ClientRealm,
    string Server,
    string ServerRealm,
    DateTimeOffset? Start,
    DateTimeOffset? End,
    DateTimeOffset? RenewUntil,
    int EncryptionType,
    int? SessionKeyType,
    uint Flags,
    uint? CacheFlags,
    string? KdcCalled)
{
    public bool IsTgt => Server.StartsWith("krbtgt/", StringComparison.OrdinalIgnoreCase)
                      || Server.Equals("krbtgt", StringComparison.OrdinalIgnoreCase);
}

sealed record KerberosState(bool HasSession, string? Note, IReadOnlyList<KerberosTicket> Tickets);

/// <summary>KERB_CLOUD_KERBEROS_DEBUG_DATA, as ntsecapi.h declares it.</summary>
sealed record CloudKerberosState(
    int Version,
    bool EnabledByPolicy,
    bool AsRepCallbackPresent,
    bool AsRepCallbackUsed,
    bool CloudReferralTgtAvailable,
    bool SpnOracleConfigured,
    bool KdcProxyPresent,
    bool? PublicKeyCredsPresent,
    bool? PasswordKeysPresent,
    bool? PasswordPresent,
    int? AsRepSourceCred)
{
    /// <summary>
    /// Decodes the bit fields. The compiler that builds Windows allocates
    /// them from the least significant bit; version 0 has the first six only.
    /// </summary>
    public static CloudKerberosState Decode(int version, uint data)
    {
        bool Bit(int n) => (data & (1u << n)) != 0;
        bool full = version >= 1;
        return new CloudKerberosState(
            version,
            Bit(0), Bit(1), Bit(2), Bit(3), Bit(4), Bit(5),
            full ? Bit(6) : null,
            full ? Bit(7) : null,
            full ? Bit(8) : null,
            full ? (int)((data >> 9) & 0xFF) : null);
    }
}

/// <summary>The Cloud Kerberos state, or why it is not available.</summary>
sealed record CloudKerberosResult(CloudKerberosState? State, string? Note);

static class KerberosCollector
{
    /// <summary>The tickets cached for the caller's own logon session.</summary>
    public static KerberosState Collect()
    {
        using var kerberos = KerberosPackage.Open();

        int status = kerberos.Call(Lsa.KerbQueryTicketCacheEx3Message, out IntPtr reply);
        bool ex3 = status == Lsa.STATUS_SUCCESS;
        if (!ex3)
        {
            if (status == Lsa.STATUS_NO_SUCH_LOGON_SESSION) return NoSession;
            status = kerberos.Call(Lsa.KerbQueryTicketCacheExMessage, out reply);
            if (status == Lsa.STATUS_NO_SUCH_LOGON_SESSION) return NoSession;
            if (status != Lsa.STATUS_SUCCESS) throw KerberosPackage.Failure("The ticket cache query", status);
        }

        try
        {
            if (reply == IntPtr.Zero) return new KerberosState(true, null, []);
            return new KerberosState(true, null, ex3 ? ReadEx3(reply) : ReadEx(reply));
        }
        finally
        {
            KerberosPackage.Free(ref reply);
        }
    }

    /// <summary>The state behind "klist cloud_debug", for the caller's own logon session.</summary>
    public static CloudKerberosResult QueryCloud()
    {
        try
        {
            using var kerberos = KerberosPackage.Open();
            int status = kerberos.Call(Lsa.KerbPrintCloudKerberosDebugMessage, out IntPtr reply);
            if (status == Lsa.STATUS_NO_SUCH_LOGON_SESSION)
                return new CloudKerberosResult(null, "no Kerberos logon session");
            if (status != Lsa.STATUS_SUCCESS)
                return new CloudKerberosResult(null, $"not reported by this version of Windows (NTSTATUS 0x{status:X8})");

            try
            {
                if (reply == IntPtr.Zero) return new CloudKerberosResult(null, "no data returned");
                int version = Marshal.ReadInt32(reply, Lsa.CloudDebugVersionOffset);
                int length = Marshal.ReadInt32(reply, Lsa.CloudDebugLengthOffset);
                if (length < sizeof(uint)) return new CloudKerberosResult(null, "no data returned");
                uint data = unchecked((uint)Marshal.ReadInt32(reply, Lsa.CloudDebugDataOffset));
                return new CloudKerberosResult(CloudKerberosState.Decode(version, data), null);
            }
            finally
            {
                KerberosPackage.Free(ref reply);
            }
        }
        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
        {
            return new CloudKerberosResult(null, ex.Message);
        }
    }

    static readonly KerberosState NoSession = new(
        false,
        "This logon session has no Kerberos ticket cache. Network logons, such as a remote PowerShell session, and some service logons have none.",
        []);

    static List<KerberosTicket> ReadEx3(IntPtr reply)
    {
        int count = Marshal.ReadInt32(reply, 4);
        int size = Marshal.SizeOf<Lsa.KERB_TICKET_CACHE_INFO_EX3>();
        var tickets = new List<KerberosTicket>(Math.Max(0, count));
        for (int i = 0; i < count; i++)
        {
            var t = Marshal.PtrToStructure<Lsa.KERB_TICKET_CACHE_INFO_EX3>(reply + Lsa.TicketCacheResponseHeader + i * size);
            string kdc = Lsa.Read(t.KdcCalled);
            tickets.Add(new KerberosTicket(
                Lsa.Read(t.ClientName), Lsa.Read(t.ClientRealm), Lsa.Read(t.ServerName), Lsa.Read(t.ServerRealm),
                Time(t.StartTime), Time(t.EndTime), Time(t.RenewTime),
                t.EncryptionType, t.SessionKeyType, t.TicketFlags, t.CacheFlags,
                kdc.Length == 0 ? null : kdc));
        }
        return tickets;
    }

    static List<KerberosTicket> ReadEx(IntPtr reply)
    {
        int count = Marshal.ReadInt32(reply, 4);
        int size = Marshal.SizeOf<Lsa.KERB_TICKET_CACHE_INFO_EX>();
        var tickets = new List<KerberosTicket>(Math.Max(0, count));
        for (int i = 0; i < count; i++)
        {
            var t = Marshal.PtrToStructure<Lsa.KERB_TICKET_CACHE_INFO_EX>(reply + Lsa.TicketCacheResponseHeader + i * size);
            tickets.Add(new KerberosTicket(
                Lsa.Read(t.ClientName), Lsa.Read(t.ClientRealm), Lsa.Read(t.ServerName), Lsa.Read(t.ServerRealm),
                Time(t.StartTime), Time(t.EndTime), Time(t.RenewTime),
                t.EncryptionType, null, t.TicketFlags, null, null));
        }
        return tickets;
    }

    /// <summary>A FILETIME; zero and "never" (the largest value) are no time at all.</summary>
    internal static DateTimeOffset? Time(long fileTime)
    {
        if (fileTime <= 0 || fileTime == long.MaxValue) return null;
        try
        {
            return new DateTimeOffset(DateTime.FromFileTimeUtc(fileTime));
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }
}

/// <summary>An untrusted connection to the LSA, bound to the Kerberos package.</summary>
sealed class KerberosPackage : IDisposable
{
    readonly IntPtr _lsa;
    readonly uint _package;

    KerberosPackage(IntPtr lsa, uint package)
    {
        _lsa = lsa;
        _package = package;
    }

    public static KerberosPackage Open()
    {
        int status = Lsa.LsaConnectUntrusted(out IntPtr lsa);
        if (status != Lsa.STATUS_SUCCESS) throw Failure("Connecting to the LSA", status);

        IntPtr name = Marshal.StringToHGlobalAnsi("Kerberos");
        try
        {
            var packageName = new Lsa.LSA_STRING { Length = 8, MaximumLength = 9, Buffer = name };
            status = Lsa.LsaLookupAuthenticationPackage(lsa, ref packageName, out uint package);
            if (status != Lsa.STATUS_SUCCESS)
            {
                Lsa.LsaDeregisterLogonProcess(lsa);
                throw Failure("Finding the Kerberos package", status);
            }
            return new KerberosPackage(lsa, package);
        }
        finally
        {
            Marshal.FreeHGlobal(name);
        }
    }

    /// <summary>
    /// Sends a request about the caller's own logon session. Returns the call
    /// or protocol NTSTATUS; on success <paramref name="reply"/> must be freed.
    /// </summary>
    public int Call(int messageType, out IntPtr reply)
    {
        var request = new Lsa.KERB_SESSION_REQUEST { MessageType = messageType };
        int size = Marshal.SizeOf<Lsa.KERB_SESSION_REQUEST>();
        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(request, buffer, false);
            int status = Lsa.LsaCallAuthenticationPackage(_lsa, _package, buffer, size,
                                                          out reply, out _, out int protocol);
            if (status != Lsa.STATUS_SUCCESS || protocol != Lsa.STATUS_SUCCESS)
            {
                Free(ref reply);
                return status != Lsa.STATUS_SUCCESS ? status : protocol;
            }
            return Lsa.STATUS_SUCCESS;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static void Free(ref IntPtr reply)
    {
        if (reply == IntPtr.Zero) return;
        Lsa.LsaFreeReturnBuffer(reply);
        reply = IntPtr.Zero;
    }

    public static Exception Failure(string what, int status)
    {
        int win32 = Lsa.LsaNtStatusToWinError(status);
        return new InvalidOperationException(
            $"{what} failed: {new Win32Exception(win32).Message} (NTSTATUS 0x{status:X8}).");
    }

    public void Dispose() => Lsa.LsaDeregisterLogonProcess(_lsa);
}

/// <summary>Names for what ntsecapi.h defines: encryption types and ticket flags.</summary>
static class KerberosNames
{
    public static string Encryption(int etype) => etype switch
    {
        0 => "none",
        1 => "DES-CBC-CRC",
        2 => "DES-CBC-MD4",
        3 => "DES-CBC-MD5",
        17 => "AES-128-CTS-HMAC-SHA1-96",
        18 => "AES-256-CTS-HMAC-SHA1-96",
        19 => "AES-128-CTS-HMAC-SHA256-128",
        20 => "AES-256-CTS-HMAC-SHA384-192",
        23 => "RC4-HMAC",
        24 => "RC4-HMAC-EXP",
        -128 => "RC4-MD4",
        -133 => "RC4-HMAC-OLD",
        -135 => "RC4-HMAC-OLD-EXP",
        _ => $"etype {etype}"
    };

    public static bool IsDes(int etype) => etype is 1 or 2 or 3 or -132;

    public static bool IsRc4(int etype) => etype is 23 or 24 || (etype is <= -128 and >= -141 && etype != -132);

    static readonly (uint Bit, string Name)[] FlagNames =
    [
        (0x40000000, "forwardable"),
        (0x20000000, "forwarded"),
        (0x10000000, "proxiable"),
        (0x08000000, "proxy"),
        (0x04000000, "may_postdate"),
        (0x02000000, "postdated"),
        (0x01000000, "invalid"),
        (0x00800000, "renewable"),
        (0x00400000, "initial"),
        (0x00200000, "pre_authent"),
        (0x00100000, "hw_authent"),
        (0x00040000, "ok_as_delegate"),
        (0x00010000, "name_canonicalize")
    ];

    public static IReadOnlyList<string> Flags(uint flags) =>
        FlagNames.Where(f => (flags & f.Bit) != 0).Select(f => f.Name).ToList();
}
