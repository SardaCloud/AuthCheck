// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;
using SardaCloud.AuthCheck.Reports;

namespace SardaCloud.AuthCheck.Tests;

public class MdmTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData("MS DM Server", null, "Intune")]
    [InlineData("ms dm server", null, "Intune")]
    [InlineData("Microsoft Device Management", null, "MicrosoftDeviceManagement")]
    [InlineData("WMI_Bridge_SCCM_Server", null, "ConfigMgr")]
    [InlineData("Local Authority", null, "WindowsAuthority")]
    [InlineData(null, "https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx", "Intune")]
    [InlineData(null, "https://checkin.dm.microsoft.com/x", "MicrosoftDeviceManagement")]
    [InlineData("AirWatchMDM", "https://ds1234.awmdm.com/DeviceServices", "ThirdParty")]
    [InlineData(null, "https://mdm.contoso.com/omadm", "ThirdParty")]
    [InlineData(null, "https://evilmanage.microsoft.com.attacker.example/", "ThirdParty")]
    [InlineData(null, "https://login.microsoftonline.com/", "Other")]
    [InlineData("Contoso", null, "Other")]
    public void Classification(string? provider, string? url, string expected) =>
        Assert.Equal(expected, MdmCollector.Classify(provider, url).ToString());

    [Fact]
    public void OmaDmTimes()
    {
        Assert.Equal(new DateTimeOffset(2026, 10, 10, 9, 1, 54, TimeSpan.Zero), MdmCollector.ParseOmaDmTime("20261010T090154Z"));
        Assert.Null(MdmCollector.ParseOmaDmTime("yesterday"));
        Assert.Null(MdmCollector.ParseOmaDmTime(null));
    }

    static ConfigMgrState NoConfigMgr => new(false, null, null, null, "NotInstalled", null, null, null);

    static ConfigMgrState ConfigMgr(bool? coManaged, string service = "Running") =>
        new(true, "PS1", "5.00.9146.1000", "mp.contoso.com", service, coManaged, "8193", null);

    static Enrollment Intune(DateTimeOffset? lastSync, int? lastResult = 0, CertificateInfo? cert = null) =>
        new("11111111-1111-1111-1111-111111111111", "MS DM Server", EnrollmentKind.Intune, 6, 1, "alex@contoso.com",
            "tenant", "https://r.manage.microsoft.com/x",
            new OmaDmAccount("11111111-1111-1111-1111-111111111111", "MS DM Server", "https://r.manage.microsoft.com/x",
                             lastSync, lastSync, lastResult),
            new MdmCertificate("ABC", cert ?? new CertificateInfo("CN=x", "CN=y", "ABC", Now.AddDays(-30), Now.AddDays(300)), @"LocalMachine\My"));

    static Enrollment ThirdParty() =>
        new("22222222-2222-2222-2222-222222222222", "AirWatchMDM", EnrollmentKind.ThirdParty, 6, 1, "alex@contoso.com",
            null, "https://ds1234.awmdm.com/x", null, null);

    static MdmState State(ConfigMgrState cm, params Enrollment[] enrollments) =>
        new(new MdmApiRegistration(enrollments.Length > 0, 6, null, null), null, enrollments, cm, []);

    [Fact]
    public void ManagedBySummaries()
    {
        Assert.Equal("Microsoft Intune and Configuration Manager (co-managed)", State(ConfigMgr(true), Intune(Now)).ManagedBy);
        Assert.Equal("AirWatchMDM and Configuration Manager (coexistence)", State(ConfigMgr(false), ThirdParty()).ManagedBy);
        Assert.Equal("Microsoft Intune", State(NoConfigMgr, Intune(Now)).ManagedBy);
        Assert.Equal("Configuration Manager", State(ConfigMgr(false)).ManagedBy);
        Assert.Equal("Nothing detected", State(NoConfigMgr).ManagedBy);
    }

    [Fact]
    public void HealthyCoManagedDeviceIsAllOk()
    {
        var findings = MdmReport.Assess(State(ConfigMgr(true), Intune(Now.AddHours(-2))), null, Now);
        Assert.NotEmpty(findings);
        Assert.All(findings, f => Assert.Equal(CheckStatus.Ok, f.Status));
    }

    [Fact]
    public void StaleSyncAndFailedSessionAreWarnings()
    {
        var findings = MdmReport.Assess(State(NoConfigMgr, Intune(Now.AddDays(-9), lastResult: unchecked((int)0x80072EE7))), null, Now);
        Assert.Contains(findings, f => f.Label == "Last MDM sync" && f.Status == CheckStatus.Warn);
        Assert.Contains(findings, f => f.Label == "MDM sync result" && f.Detail.Contains("0x80072EE7"));
    }

    [Fact]
    public void NeverSyncedIsAWarning()
    {
        var findings = MdmReport.Assess(State(NoConfigMgr, Intune(null)), null, Now);
        Assert.Contains(findings, f => f.Label == "Last MDM sync" && f.Status == CheckStatus.Warn);
    }

    [Fact]
    public void ExpiredMdmCertificateIsBad()
    {
        var expired = new CertificateInfo("CN=x", "CN=y", "ABC", Now.AddDays(-400), Now.AddDays(-1));
        var findings = MdmReport.Assess(State(NoConfigMgr, Intune(Now, cert: expired)), null, Now);
        Assert.Contains(findings, f => f.Label == "MDM certificate" && f.Status == CheckStatus.Bad);
    }

    [Fact]
    public void CoManagementInconsistencies()
    {
        Assert.Contains(MdmReport.Assess(State(ConfigMgr(true)), null, Now),
                        f => f.Label == "Co-management" && f.Status == CheckStatus.Warn);
        Assert.Contains(MdmReport.Assess(State(ConfigMgr(false), Intune(Now)), null, Now),
                        f => f.Label == "Co-management" && f.Status == CheckStatus.Warn);
        Assert.Contains(MdmReport.Assess(State(ConfigMgr(true, "Stopped"), Intune(Now)), null, Now),
                        f => f.Label == "ConfigMgr client" && f.Status == CheckStatus.Warn);
    }

    [Fact]
    public void EnrollmentUrlWithoutEnrollmentIsAWarning()
    {
        var device = new DeviceState(EntraJoin.Joined, "t", "Contoso", "d", null, null,
            "https://enrollment.manage.microsoft.com/EnrollmentServer/Discovery.svc", null, null, null,
            null, null, null, null, DomainJoin.Workgroup, "WORKGROUP");
        var findings = MdmReport.Assess(State(NoConfigMgr), device, Now);
        Assert.Contains(findings, f => f.Label == "MDM enrollment" && f.Status == CheckStatus.Warn);
    }
}
