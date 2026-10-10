// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>secur32 and advapi32: the LSA and the Kerberos package (ntsecapi.h).</summary>
static class Lsa
{
    // KERB_PROTOCOL_MESSAGE_TYPE, counted from the Windows 10 SDK.
    public const int KerbQueryTicketCacheExMessage = 14;
    public const int KerbQueryTicketCacheEx3Message = 25;
    public const int KerbPrintCloudKerberosDebugMessage = 36;

    public const int STATUS_SUCCESS = 0;
    public const int STATUS_NO_SUCH_LOGON_SESSION = unchecked((int)0xC000005F);

    [DllImport("secur32.dll", ExactSpelling = true)]
    public static extern int LsaConnectUntrusted(out IntPtr lsaHandle);

    [DllImport("secur32.dll", ExactSpelling = true)]
    public static extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle, ref LSA_STRING packageName, out uint authenticationPackage);

    [DllImport("secur32.dll", ExactSpelling = true)]
    public static extern int LsaCallAuthenticationPackage(
        IntPtr lsaHandle,
        uint authenticationPackage,
        IntPtr protocolSubmitBuffer,
        int submitBufferLength,
        out IntPtr protocolReturnBuffer,
        out int returnBufferLength,
        out int protocolStatus);

    [DllImport("secur32.dll", ExactSpelling = true)]
    public static extern int LsaFreeReturnBuffer(IntPtr buffer);

    [DllImport("secur32.dll", ExactSpelling = true)]
    public static extern int LsaDeregisterLogonProcess(IntPtr lsaHandle);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    public static extern int LsaNtStatusToWinError(int status);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    /// <summary>
    /// KERB_QUERY_TKT_CACHE_REQUEST, and KERB_CLOUD_KERBEROS_DEBUG_REQUEST,
    /// which has the same shape. A zero LogonId means the caller's own session.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_SESSION_REQUEST
    {
        public int MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public int EncryptionType;
        public uint TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO_EX3
    {
        public UNICODE_STRING ClientName;
        public UNICODE_STRING ClientRealm;
        public UNICODE_STRING ServerName;
        public UNICODE_STRING ServerRealm;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public int EncryptionType;
        public uint TicketFlags;
        public int SessionKeyType;
        public uint BranchId;
        public uint CacheFlags;
        public UNICODE_STRING KdcCalled;
    }

    /// <summary>The ticket array follows MessageType and CountOfTickets, aligned to 8 bytes.</summary>
    public const int TicketCacheResponseHeader = 8;

    /// <summary>KERB_CLOUD_KERBEROS_DEBUG_RESPONSE: MessageType, Version, Length, then Data.</summary>
    public const int CloudDebugVersionOffset = 4;
    public const int CloudDebugLengthOffset = 8;
    public const int CloudDebugDataOffset = 12;

    public static string Read(UNICODE_STRING s) =>
        s.Buffer == IntPtr.Zero || s.Length == 0 ? "" : Marshal.PtrToStringUni(s.Buffer, s.Length / 2);
}
