// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;

namespace SardaCloud.AuthCheck.Native;

/// <summary>
/// WMI through its COM interfaces (wbemcli.h), declared by hand so AuthCheck
/// needs no package and works the same on x86, x64 and ARM64.
/// </summary>
static class Wmi
{
    static readonly Guid CLSID_WbemLocator = new("4590f811-1d3a-11d0-891f-00aa004b2e24");

    const int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
    const int WBEM_FLAG_FORWARD_ONLY = 0x20;
    const int WBEM_S_TIMEDOUT = 0x40004;

    public const int WBEM_E_ACCESS_DENIED = unchecked((int)0x80041003);
    public const int WBEM_E_INVALID_NAMESPACE = unchecked((int)0x8004100E);
    public const int WBEM_E_INVALID_CLASS = unchecked((int)0x80041010);
    public const int E_ACCESSDENIED = unchecked((int)0x80070005);

    const int COINIT_MULTITHREADED = 0x0;
    const int RPC_E_CHANGED_MODE = unchecked((int)0x80010106);
    const int RPC_C_AUTHN_LEVEL_DEFAULT = 0;
    const int RPC_C_AUTHN_LEVEL_CALL = 3;
    const int RPC_C_IMP_LEVEL_IMPERSONATE = 3;
    const int RPC_C_AUTHN_WINNT = 10;
    const int RPC_C_AUTHZ_NONE = 0;
    const int EOAC_NONE = 0;

    static bool _securityInitialised;

    /// <summary>
    /// Runs a WQL query and returns the named properties of every instance.
    /// A property the class does not have comes back as null.
    /// </summary>
    public static List<Dictionary<string, object?>> Query(
        string wmiNamespace, string wql, IReadOnlyList<string> properties, int timeoutMs = 15000)
    {
        InitialiseSecurity();

        Type locatorType = Type.GetTypeFromCLSID(CLSID_WbemLocator, throwOnError: true)!;
        object locatorObject = Activator.CreateInstance(locatorType)!;
        IWbemServices? services = null;
        IEnumWbemClassObject? results = null;
        try
        {
            var locator = (IWbemLocator)locatorObject;
            int hr = locator.ConnectServer(wmiNamespace, null, null, null, 0, null, IntPtr.Zero, out services);
            if (hr < 0) throw new COMException($"WMI namespace {wmiNamespace}: {Describe(hr)}", hr);
            SetBlanket(services, typeof(IWbemServices));

            hr = services.ExecQuery("WQL", wql, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                    IntPtr.Zero, out results);
            if (hr < 0) throw new COMException($"WMI query in {wmiNamespace}: {Describe(hr)}", hr);
            SetBlanket(results, typeof(IEnumWbemClassObject));

            var rows = new List<Dictionary<string, object?>>();
            while (true)
            {
                hr = results.Next(timeoutMs, 1, out IWbemClassObject? row, out uint returned);
                if (hr < 0) throw new COMException($"WMI query in {wmiNamespace}: {Describe(hr)}", hr);
                if (returned == 0 || row is null)
                {
                    if (hr == WBEM_S_TIMEDOUT)
                        throw new COMException($"WMI query in {wmiNamespace} timed out.", hr);
                    break;
                }

                try
                {
                    var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (string name in properties)
                    {
                        hr = row.Get(name, 0, out object? value, out _, out _);
                        values[name] = hr >= 0 ? value : null;
                    }
                    rows.Add(values);
                }
                finally
                {
                    Marshal.ReleaseComObject(row);
                }
            }
            return rows;
        }
        finally
        {
            if (results is not null) Marshal.ReleaseComObject(results);
            if (services is not null) Marshal.ReleaseComObject(services);
            Marshal.ReleaseComObject(locatorObject);
        }
    }

    public static string Describe(int hr) => hr switch
    {
        WBEM_E_INVALID_NAMESPACE => "the namespace does not exist",
        WBEM_E_INVALID_CLASS => "the class does not exist",
        WBEM_E_ACCESS_DENIED or E_ACCESSDENIED => "access denied",
        _ => $"error 0x{hr:X8}"
    };

    /// <summary>
    /// Asks for impersonation, which some WMI providers need. If COM security
    /// was already set for the process, the proxy blankets still apply.
    /// </summary>
    static void InitialiseSecurity()
    {
        if (_securityInitialised) return;
        _securityInitialised = true;

        int hr = CoInitializeEx(IntPtr.Zero, COINIT_MULTITHREADED);
        if (hr < 0 && hr != RPC_E_CHANGED_MODE) return;
        CoInitializeSecurity(IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero, RPC_C_AUTHN_LEVEL_DEFAULT,
                             RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOAC_NONE, IntPtr.Zero);
    }

    static void SetBlanket(object proxy, Type interfaceType)
    {
        IntPtr p = Marshal.GetComInterfaceForObject(proxy, interfaceType);
        try
        {
            CoSetProxyBlanket(p, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, IntPtr.Zero,
                              RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, IntPtr.Zero, EOAC_NONE);
        }
        finally
        {
            Marshal.Release(p);
        }
    }

    [DllImport("ole32.dll", ExactSpelling = true)]
    static extern int CoInitializeEx(IntPtr pvReserved, int dwCoInit);

    [DllImport("ole32.dll", ExactSpelling = true)]
    static extern int CoInitializeSecurity(IntPtr pSecDesc, int cAuthSvc, IntPtr asAuthSvc, IntPtr pReserved1,
        int dwAuthnLevel, int dwImpLevel, IntPtr pAuthList, int dwCapabilities, IntPtr pReserved3);

    [DllImport("ole32.dll", ExactSpelling = true)]
    static extern int CoSetProxyBlanket(IntPtr pProxy, int dwAuthnSvc, int dwAuthzSvc, IntPtr pServerPrincName,
        int dwAuthnLevel, int dwImpLevel, IntPtr pAuthInfo, int dwCapabilities);

    [ComImport, Guid("dc12a687-737f-11cf-884d-00aa004b2e24"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IWbemLocator
    {
        [PreserveSig]
        int ConnectServer(
            [MarshalAs(UnmanagedType.BStr)] string strNetworkResource,
            [MarshalAs(UnmanagedType.BStr)] string? strUser,
            [MarshalAs(UnmanagedType.BStr)] string? strPassword,
            [MarshalAs(UnmanagedType.BStr)] string? strLocale,
            int lSecurityFlags,
            [MarshalAs(UnmanagedType.BStr)] string? strAuthority,
            IntPtr pCtx,
            out IWbemServices ppNamespace);
    }

    [ComImport, Guid("9556dc99-828c-11cf-a37e-00aa003240c7"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IWbemServices
    {
        // The first seventeen methods are never called. They are declared only
        // to hold their places in the vtable, in the order wbemcli.h gives.
        void OpenNamespace();
        void CancelAsyncCall();
        void QueryObjectSink();
        void GetObject();
        void GetObjectAsync();
        void PutClass();
        void PutClassAsync();
        void DeleteClass();
        void DeleteClassAsync();
        void CreateClassEnum();
        void CreateClassEnumAsync();
        void PutInstance();
        void PutInstanceAsync();
        void DeleteInstance();
        void DeleteInstanceAsync();
        void CreateInstanceEnum();
        void CreateInstanceEnumAsync();

        [PreserveSig]
        int ExecQuery(
            [MarshalAs(UnmanagedType.BStr)] string strQueryLanguage,
            [MarshalAs(UnmanagedType.BStr)] string strQuery,
            int lFlags,
            IntPtr pCtx,
            out IEnumWbemClassObject ppEnum);
    }

    [ComImport, Guid("027947e1-d731-11ce-a357-000000000001"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IEnumWbemClassObject
    {
        void Reset();

        [PreserveSig]
        int Next(int lTimeout, uint uCount, out IWbemClassObject? apObjects, out uint puReturned);
    }

    [ComImport, Guid("dc12a681-737f-11cf-884d-00aa004b2e24"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IWbemClassObject
    {
        void GetQualifierSet();

        [PreserveSig]
        int Get(
            [MarshalAs(UnmanagedType.LPWStr)] string wszName,
            int lFlags,
            [MarshalAs(UnmanagedType.Struct)] out object? pVal,
            out int pType,
            out int plFlavor);
    }
}
