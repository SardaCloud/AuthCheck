// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>advapi32: the state of a Windows service, read through the Service Control Manager.</summary>
static class Services
{
    const int SC_MANAGER_CONNECT = 0x0001;
    const int SERVICE_QUERY_STATUS = 0x0004;
    const int ERROR_SERVICE_DOES_NOT_EXIST = 1060;

    [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode,
               ExactSpelling = true, SetLastError = true)]
    static extern IntPtr OpenSCManager(string? machineName, string? databaseName, int desiredAccess);

    [DllImport("advapi32.dll", EntryPoint = "OpenServiceW", CharSet = CharSet.Unicode,
               ExactSpelling = true, SetLastError = true)]
    static extern IntPtr OpenService(IntPtr scManager, string serviceName, int desiredAccess);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool QueryServiceStatus(IntPtr service, out SERVICE_STATUS status);

    [DllImport("advapi32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    struct SERVICE_STATUS
    {
        public int dwServiceType;
        public int dwCurrentState;
        public int dwControlsAccepted;
        public int dwWin32ExitCode;
        public int dwServiceSpecificExitCode;
        public int dwCheckPoint;
        public int dwWaitHint;
    }

    /// <summary>
    /// "Running", "Stopped" and so on; "NotInstalled" when the service does
    /// not exist; null when its state cannot be read.
    /// </summary>
    public static string? State(string serviceName)
    {
        IntPtr scm = OpenSCManager(null, null, SC_MANAGER_CONNECT);
        if (scm == IntPtr.Zero) return null;
        try
        {
            IntPtr service = OpenService(scm, serviceName, SERVICE_QUERY_STATUS);
            if (service == IntPtr.Zero)
                return Marshal.GetLastWin32Error() == ERROR_SERVICE_DOES_NOT_EXIST ? "NotInstalled" : null;
            try
            {
                if (!QueryServiceStatus(service, out SERVICE_STATUS status)) return null;
                return status.dwCurrentState switch
                {
                    1 => "Stopped",
                    2 => "StartPending",
                    3 => "StopPending",
                    4 => "Running",
                    5 => "ContinuePending",
                    6 => "PausePending",
                    7 => "Paused",
                    _ => $"Unknown({status.dwCurrentState})"
                };
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(scm);
        }
    }
}
