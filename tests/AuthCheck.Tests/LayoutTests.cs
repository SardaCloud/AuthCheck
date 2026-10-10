// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Runtime.InteropServices;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Native;

namespace SardaCloud.AuthCheck.Tests;

/// <summary>
/// The structures AuthCheck hands to Windows must match the Windows SDK byte
/// for byte. The expected sizes and offsets were measured by compiling the SDK
/// headers with MSVC, for x64 (whose layout ARM64 shares) and for x86.
/// The test checks whichever architecture it runs as.
/// </summary>
public class LayoutTests
{
    static bool Is32 => RuntimeInformation.ProcessArchitecture == Architecture.X86;

    static int Pick(int x64, int x86) => Is32 ? x86 : x64;

    static int Offset<T>(string field) => (int)Marshal.OffsetOf<T>(field);

    [Fact]
    public void DsregJoinInfo()
    {
        Assert.Equal(Pick(96, 48), Marshal.SizeOf<NetApi.DSREG_JOIN_INFO>());
        Assert.Equal(Pick(8, 4), Offset<NetApi.DSREG_JOIN_INFO>("pJoinCertificate"));
        Assert.Equal(Pick(16, 8), Offset<NetApi.DSREG_JOIN_INFO>("pszDeviceId"));
        Assert.Equal(Pick(32, 16), Offset<NetApi.DSREG_JOIN_INFO>("pszTenantId"));
        Assert.Equal(Pick(48, 24), Offset<NetApi.DSREG_JOIN_INFO>("pszTenantDisplayName"));
        Assert.Equal(Pick(56, 28), Offset<NetApi.DSREG_JOIN_INFO>("pszMdmEnrollmentUrl"));
        Assert.Equal(Pick(80, 40), Offset<NetApi.DSREG_JOIN_INFO>("pszUserSettingSyncUrl"));
        Assert.Equal(Pick(88, 44), Offset<NetApi.DSREG_JOIN_INFO>("pUserInfo"));

        Assert.Equal(Pick(24, 12), Marshal.SizeOf<NetApi.DSREG_USER_INFO>());
        Assert.Equal(Pick(16, 8), Offset<NetApi.DSREG_USER_INFO>("pszUserKeyName"));
    }

    [Fact]
    public void LsaRequests()
    {
        Assert.Equal(Pick(16, 8), Marshal.SizeOf<Lsa.LSA_STRING>());
        Assert.Equal(Pick(8, 4), Offset<Lsa.LSA_STRING>("Buffer"));
        Assert.Equal(8, Marshal.SizeOf<Lsa.LUID>());
        Assert.Equal(12, Marshal.SizeOf<Lsa.KERB_SESSION_REQUEST>());
        Assert.Equal(4, Offset<Lsa.KERB_SESSION_REQUEST>("LogonId"));
        Assert.Equal(Pick(16, 8), Marshal.SizeOf<Lsa.UNICODE_STRING>());
    }

    [Fact]
    public void TicketCacheEx()
    {
        Assert.Equal(Pick(96, 64), Marshal.SizeOf<Lsa.KERB_TICKET_CACHE_INFO_EX>());
        Assert.Equal(Pick(48, 24), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX>("ServerRealm"));
        Assert.Equal(Pick(64, 32), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX>("StartTime"));
        Assert.Equal(Pick(88, 56), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX>("EncryptionType"));
        Assert.Equal(Pick(92, 60), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX>("TicketFlags"));
    }

    [Fact]
    public void TicketCacheEx3()
    {
        Assert.Equal(Pick(128, 88), Marshal.SizeOf<Lsa.KERB_TICKET_CACHE_INFO_EX3>());
        Assert.Equal(Pick(64, 32), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("StartTime"));
        Assert.Equal(Pick(80, 48), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("RenewTime"));
        Assert.Equal(Pick(96, 64), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("SessionKeyType"));
        Assert.Equal(Pick(100, 68), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("BranchId"));
        Assert.Equal(Pick(104, 72), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("CacheFlags"));
        Assert.Equal(Pick(112, 76), Offset<Lsa.KERB_TICKET_CACHE_INFO_EX3>("KdcCalled"));
    }

    [Fact]
    public void ResponseHeaders()
    {
        Assert.Equal(8, Lsa.TicketCacheResponseHeader);
        Assert.Equal(4, Lsa.CloudDebugVersionOffset);
        Assert.Equal(8, Lsa.CloudDebugLengthOffset);
        Assert.Equal(12, Lsa.CloudDebugDataOffset);
    }

    [Fact]
    public void Credential()
    {
        Assert.Equal(Pick(80, 52), Marshal.SizeOf<CredMan.CREDENTIALW>());
        Assert.Equal(Pick(16, 12), Offset<CredMan.CREDENTIALW>("Comment"));
        Assert.Equal(Pick(24, 16), Offset<CredMan.CREDENTIALW>("LastWrittenLow"));
        Assert.Equal(Pick(32, 24), Offset<CredMan.CREDENTIALW>("CredentialBlobSize"));
        Assert.Equal(Pick(40, 28), Offset<CredMan.CREDENTIALW>("CredentialBlob"));
        Assert.Equal(Pick(48, 32), Offset<CredMan.CREDENTIALW>("Persist"));
        Assert.Equal(Pick(64, 44), Offset<CredMan.CREDENTIALW>("TargetAlias"));
        Assert.Equal(Pick(72, 48), Offset<CredMan.CREDENTIALW>("UserName"));
    }

    [Fact]
    public void ManagementRegistrationInfo()
    {
        Assert.Equal(Pick(24, 16), Marshal.SizeOf<MdmRegistration.MANAGEMENT_REGISTRATION_INFO>());
        Assert.Equal(4, Offset<MdmRegistration.MANAGEMENT_REGISTRATION_INFO>("dwDeviceRegistionKind"));
        Assert.Equal(8, Offset<MdmRegistration.MANAGEMENT_REGISTRATION_INFO>("pszUPN"));
        Assert.Equal(Pick(16, 12), Offset<MdmRegistration.MANAGEMENT_REGISTRATION_INFO>("pszMDMServiceUri"));
    }

    [Fact]
    public void CloudKerberosBitFields()
    {
        // MSVC packs KERB_CLOUD_KERBEROS_DEBUG_DATA from the low bit: setting
        // CloudReferralTgtAvailable alone gives 8, AsRepSourceCred = 0x81 alone 66048.
        CloudKerberosState tgt = CloudKerberosState.Decode(1, 8);
        Assert.True(tgt.CloudReferralTgtAvailable);
        Assert.False(tgt.EnabledByPolicy);
        Assert.False(tgt.KdcProxyPresent);
        Assert.Equal(0, tgt.AsRepSourceCred);

        CloudKerberosState source = CloudKerberosState.Decode(1, 66048);
        Assert.Equal(0x81, source.AsRepSourceCred);
        Assert.False(source.CloudReferralTgtAvailable);
        Assert.False(source.PasswordPresent);

        CloudKerberosState v0 = CloudKerberosState.Decode(0, 0xFFFFFFFF);
        Assert.True(v0.EnabledByPolicy);
        Assert.Null(v0.PublicKeyCredsPresent);
        Assert.Null(v0.AsRepSourceCred);
    }
}
