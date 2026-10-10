// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>mdmregistration: the MDM Registration API (mdmregistration.h).</summary>
static class MdmRegistration
{
    public const int DeviceRegistrationBasicInfo = 1;

    public const int DEVICEREGISTRATIONTYPE_MDM_ONLY = 0;
    public const int DEVICEREGISTRATIONTYPE_MAM = 5;
    public const int DEVICEREGISTRATIONTYPE_MDM_DEVICEWIDE_WITH_AAD = 6;
    public const int DEVICEREGISTRATIONTYPE_MDM_USERSPECIFIC_WITH_AAD = 13;

    /// <summary>Returns a MANAGEMENT_REGISTRATION_INFO that is freed with HeapFree.</summary>
    [DllImport("mdmregistration.dll", ExactSpelling = true)]
    public static extern int GetDeviceRegistrationInfo(int deviceInformationClass, out IntPtr ppDeviceRegistrationInfo);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetProcessHeap();

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool HeapFree(IntPtr hHeap, int dwFlags, IntPtr lpMem);

    [StructLayout(LayoutKind.Sequential)]
    public struct MANAGEMENT_REGISTRATION_INFO
    {
        public int fDeviceRegisteredWithManagement;
        public int dwDeviceRegistionKind;
        public IntPtr pszUPN;
        public IntPtr pszMDMServiceUri;
    }
}
