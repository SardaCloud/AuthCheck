// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>netapi32: Microsoft Entra and Active Directory join information (lmjoin.h).</summary>
static class NetApi
{
    public const int DSREG_UNKNOWN_JOIN = 0;
    public const int DSREG_DEVICE_JOIN = 1;
    public const int DSREG_WORKPLACE_JOIN = 2;

    public const int NetSetupUnknownStatus = 0;
    public const int NetSetupUnjoined = 1;
    public const int NetSetupWorkgroupName = 2;
    public const int NetSetupDomainName = 3;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int NetGetAadJoinInformation(string? pcszTenantId, out IntPtr ppJoinInfo);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    public static extern void NetFreeAadJoinInformation(IntPtr pJoinInfo);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int NetGetJoinInformation(string? lpServer, out IntPtr lpNameBuffer, out int bufferType);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential)]
    public struct DSREG_USER_INFO
    {
        public IntPtr pszUserEmail;
        public IntPtr pszUserKeyId;
        public IntPtr pszUserKeyName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DSREG_JOIN_INFO
    {
        public int joinType;
        public IntPtr pJoinCertificate;
        public IntPtr pszDeviceId;
        public IntPtr pszIdpDomain;
        public IntPtr pszTenantId;
        public IntPtr pszJoinUserEmail;
        public IntPtr pszTenantDisplayName;
        public IntPtr pszMdmEnrollmentUrl;
        public IntPtr pszMdmTermsOfUseUrl;
        public IntPtr pszMdmComplianceUrl;
        public IntPtr pszUserSettingSyncUrl;
        public IntPtr pUserInfo;
    }
}
