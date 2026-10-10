// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;
using SardaCloud.AuthCheck.Reports;

namespace SardaCloud.AuthCheck.Tests;

/// <summary>The verdicts: what is OK, what deserves a look, what is broken.</summary>
public class CheckTests
{
    static readonly DateTimeOffset Now = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    static CertificateInfo Cert(int validFromDays, int validToDays) =>
        new("CN=test", "CN=issuer", "ABCDEF", Now.AddDays(validFromDays), Now.AddDays(validToDays));

    static DeviceState Device(EntraJoin entra, DomainJoin domain = DomainJoin.Workgroup, string? domainName = "WORKGROUP",
                              CertificateInfo? cert = null, string? mdmUrl = null) =>
        new(entra, "tenant", "Contoso", "device", null, null, mdmUrl, null, null, null,
            cert, null, null, null, domain, domainName);

    // ---------------------------------------------------------- certificates

    [Fact]
    public void CertificateVerdicts()
    {
        Assert.Equal(CheckStatus.Bad, CertificateCheck.Assess("c", null, Now).Status);
        Assert.Equal(CheckStatus.Bad, CertificateCheck.Assess("c", Cert(-400, -1), Now).Status);
        Assert.Equal(CheckStatus.Bad, CertificateCheck.Assess("c", Cert(5, 400), Now).Status);
        Assert.Equal(CheckStatus.Warn, CertificateCheck.Assess("c", Cert(-300, 10), Now).Status);
        Assert.Equal(CheckStatus.Ok, CertificateCheck.Assess("c", Cert(-300, 100), Now).Status);
        Assert.StartsWith("Intune: ", CertificateCheck.Assess("c", Cert(-1, 100), Now, "Intune").Detail);
    }

    // ---------------------------------------------------------------- device

    [Fact]
    public void HybridJoinIsReported()
    {
        var d = Device(EntraJoin.Joined, DomainJoin.Domain, "CONTOSO", Cert(-10, 3000));
        Assert.True(d.IsHybrid);
        Assert.Equal("Microsoft Entra hybrid joined", d.JoinSummary);
        var findings = DeviceReport.Assess(d, Now);
        Assert.All(findings, f => Assert.Equal(CheckStatus.Ok, f.Status));
        Assert.Contains(findings, f => f.Detail == "hybrid joined");
    }

    [Fact]
    public void NotRegisteredIsAWarning()
    {
        var findings = DeviceReport.Assess(Device(EntraJoin.None), Now);
        Assert.Single(findings);
        Assert.Equal(CheckStatus.Warn, findings[0].Status);
    }

    [Fact]
    public void JoinedWithoutCertificateIsBad()
    {
        var findings = DeviceReport.Assess(Device(EntraJoin.Joined, cert: null), Now);
        Assert.Contains(findings, f => f.Label == "Device certificate" && f.Status == CheckStatus.Bad);
    }

    // ------------------------------------------------------- Cloud Kerberos

    [Fact]
    public void CloudKerberosWithoutTgtIsAWarning()
    {
        var enabledNoTgt = new CloudKerberosResult(CloudKerberosState.Decode(1, 0b0001), null);
        var enabledWithTgt = new CloudKerberosResult(CloudKerberosState.Decode(1, 0b1001), null);
        var disabled = new CloudKerberosResult(CloudKerberosState.Decode(1, 0), null);
        var joined = Device(EntraJoin.Joined, cert: Cert(-1, 100));

        Assert.Equal(CheckStatus.Warn, Assert.Single(PrtReport.Assess(joined, enabledNoTgt)).Status);
        Assert.Equal(CheckStatus.Ok, Assert.Single(PrtReport.Assess(joined, enabledWithTgt)).Status);
        Assert.Empty(PrtReport.Assess(joined, disabled));
        Assert.Empty(PrtReport.Assess(Device(EntraJoin.None), enabledNoTgt));
    }

    // -------------------------------------------------------------- Kerberos

    static KerberosTicket Ticket(string server, int etype, int? sessionKey = null, int endHours = 8) =>
        new("alex", "CONTOSO.COM", server, "CONTOSO.COM", Now.AddHours(-1), Now.AddHours(endHours), Now.AddDays(7),
            etype, sessionKey ?? etype, 0x40E10000, 1, "dc1.contoso.com");

    [Fact]
    public void WeakEncryption()
    {
        var k = new KerberosState(true, null,
        [
            Ticket("krbtgt/CONTOSO.COM", 18),
            Ticket("cifs/files.contoso.com", 23),
            Ticket("http/old.contoso.com", 18, sessionKey: 3)
        ]);
        var findings = KerberosReport.Assess(k, null, "CONTOSO", Now);
        Assert.Contains(findings, f => f.Status == CheckStatus.Bad && f.Detail.Contains("http/old.contoso.com"));
        Assert.Contains(findings, f => f.Status == CheckStatus.Warn && f.Detail.Contains("cifs/files.contoso.com"));
        Assert.Contains(findings, f => f.Label == "Kerberos TGT" && f.Status == CheckStatus.Ok);
    }

    [Fact]
    public void AesOnlyIsOk()
    {
        var k = new KerberosState(true, null, [Ticket("krbtgt/CONTOSO.COM", 18), Ticket("ldap/dc1", 17)]);
        Assert.Contains(KerberosReport.Assess(k, null, "CONTOSO", Now),
                        f => f.Label == "Ticket encryption" && f.Status == CheckStatus.Ok);
    }

    [Fact]
    public void DomainLogonWithoutTgtIsAWarning()
    {
        var domainDevice = Device(EntraJoin.Joined, DomainJoin.Domain, "CONTOSO", Cert(-1, 100));
        var empty = new KerberosState(true, null, []);
        Assert.Contains(KerberosReport.Assess(empty, domainDevice, "CONTOSO", Now),
                        f => f.Label == "Kerberos TGT" && f.Status == CheckStatus.Warn);
        Assert.DoesNotContain(KerberosReport.Assess(empty, domainDevice, "AzureAD", Now),
                              f => f.Label == "Kerberos TGT");
    }

    [Fact]
    public void ExpiredTgtIsAWarning()
    {
        var k = new KerberosState(true, null, [Ticket("krbtgt/CONTOSO.COM", 18, endHours: -1)]);
        Assert.Contains(KerberosReport.Assess(k, null, "CONTOSO", Now),
                        f => f.Label == "Kerberos TGT" && f.Status == CheckStatus.Warn);
    }

    [Fact]
    public void NoSessionIsAWarningNotAFailure()
    {
        var findings = KerberosReport.Assess(new KerberosState(false, "none", []), null, "CONTOSO", Now);
        Assert.Equal(CheckStatus.Warn, Assert.Single(findings).Status);
    }
}
