// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>advapi32: Credential Manager (wincred.h).</summary>
static class CredMan
{
    public const int CRED_ENUMERATE_ALL_CREDENTIALS = 0x1;
    public const int ERROR_NOT_FOUND = 1168;
    public const int ERROR_NO_SUCH_LOGON_SESSION = 1312;

    [DllImport("advapi32.dll", EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode,
               ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CredEnumerate(string? filter, int flags, out int count, out IntPtr credentials);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern void CredFree(IntPtr buffer);

    /// <summary>
    /// CREDENTIALW. AuthCheck reads the metadata only. Windows returns the
    /// secret of a generic credential in CredentialBlob; AuthCheck never reads
    /// it and wipes it before freeing the buffer.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIALW
    {
        public uint Flags;
        public uint Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public uint LastWrittenLow;
        public uint LastWrittenHigh;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }
}
