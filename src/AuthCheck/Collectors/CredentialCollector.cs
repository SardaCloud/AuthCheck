// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.ComponentModel;
using System.Runtime.InteropServices;
using SardaCloud.AuthCheck.Native;

namespace SardaCloud.AuthCheck.Collectors;

/// <summary>One Credential Manager entry, as cmdkey /list shows it. Never the secret.</summary>
sealed record StoredCredential(
    string Target,
    string Type,
    string Persistence,
    string? UserName,
    string? TargetAlias,
    string? Comment,
    DateTimeOffset? LastWritten,
    uint Flags,
    uint AttributeCount);

sealed record CredentialState(bool HasCredentialSet, string? Note, IReadOnlyList<StoredCredential> Entries);

static class CredentialCollector
{
    public static CredentialState Collect()
    {
        if (!CredMan.CredEnumerate(null, CredMan.CRED_ENUMERATE_ALL_CREDENTIALS, out int count, out IntPtr list))
        {
            int error = Marshal.GetLastWin32Error();
            return error switch
            {
                CredMan.ERROR_NOT_FOUND => new CredentialState(true, null, []),
                CredMan.ERROR_NO_SUCH_LOGON_SESSION => new CredentialState(false,
                    "This logon session has no credential set. Network logons, such as a remote PowerShell session, and service logons have none.",
                    []),
                _ => throw new Win32Exception(error, $"CredEnumerate failed: {new Win32Exception(error).Message}")
            };
        }

        try
        {
            var entries = new List<StoredCredential>(count);
            for (int i = 0; i < count; i++)
            {
                IntPtr p = Marshal.ReadIntPtr(list, i * IntPtr.Size);
                var c = Marshal.PtrToStructure<CredMan.CREDENTIALW>(p);

                // Windows hands the secret of a generic credential to the
                // caller. AuthCheck never reads it, and wipes it before freeing.
                Wipe(c.CredentialBlob, c.CredentialBlobSize);

                entries.Add(new StoredCredential(
                    Str(c.TargetName) ?? "",
                    TypeName(c.Type),
                    PersistenceName(c.Persist),
                    Str(c.UserName),
                    Str(c.TargetAlias),
                    Str(c.Comment),
                    FileTime(c.LastWrittenHigh, c.LastWrittenLow),
                    c.Flags,
                    c.AttributeCount));
            }
            entries.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Target, b.Target));
            return new CredentialState(true, null, entries);
        }
        finally
        {
            CredMan.CredFree(list);
        }
    }

    static void Wipe(IntPtr blob, uint size)
    {
        if (blob == IntPtr.Zero || size == 0 || size > 64 * 1024) return;
        Marshal.Copy(new byte[size], 0, blob, (int)size);
    }

    internal static string TypeName(uint type) => type switch
    {
        1 => "Generic",
        2 => "Domain password",
        3 => "Domain certificate",
        4 => "Domain visible password",
        5 => "Generic certificate",
        6 => "Domain extended",
        _ => $"Type {type}"
    };

    internal static string PersistenceName(uint persist) => persist switch
    {
        1 => "Logon session",
        2 => "Local machine",
        3 => "Enterprise (roams with the profile)",
        _ => $"Persist {persist}"
    };

    static DateTimeOffset? FileTime(uint high, uint low) =>
        KerberosCollector.Time(unchecked((long)(((ulong)high << 32) | low)));

    static string? Str(IntPtr p)
    {
        if (p == IntPtr.Zero) return null;
        string? s = Marshal.PtrToStringUni(p);
        return string.IsNullOrEmpty(s) ? null : s;
    }
}
