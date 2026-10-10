// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Text;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;

namespace SardaCloud.AuthCheck.Tests;

public class OutputTests
{
    [Fact]
    public void JsonShapes()
    {
        var data = new Dictionary<string, object?>
        {
            ["type"] = "result",
            ["ok"] = true,
            ["count"] = 2,
            ["mask"] = 0x7FFFF0FFu,
            ["none"] = null,
            ["when"] = new DateTimeOffset(2026, 10, 10, 11, 41, 7, TimeSpan.FromHours(2)),
            ["entra"] = EntraJoin.Joined,
            ["list"] = new List<object?> { "a", 1, false },
            ["nested"] = new Dictionary<string, object?> { ["k"] = "v" }
        };
        Assert.Equal(
            "{\"type\":\"result\",\"ok\":true,\"count\":2,\"mask\":2147479807,\"none\":null," +
            "\"when\":\"2026-10-10T09:41:07Z\",\"entra\":\"joined\",\"list\":[\"a\",1,false],\"nested\":{\"k\":\"v\"}}",
            JsonText.Object(data));
    }

    [Fact]
    public void JsonEscapesWhatItMustAndKeepsTheRest()
    {
        string json = JsonText.Object(new Dictionary<string, object?> { ["s"] = "C:\\Users\\\"Zoë\"\n" });
        Assert.Equal("{\"s\":\"C:\\\\Users\\\\\\\"Zoë\\\"\\n\"}", json);
    }

    [Fact]
    public void JsonStringsListsAreNotCharacterArrays()
    {
        string json = JsonText.Object(new Dictionary<string, object?> { ["flags"] = new List<string> { "renewable" } });
        Assert.Equal("{\"flags\":[\"renewable\"]}", json);
    }

    [Theory]
    [InlineData(30, "less than a minute")]
    [InlineData(60 * 5, "5 minutes")]
    [InlineData(60 * 60, "1 hour")]
    [InlineData(60 * 60 * 30, "30 hours")]
    [InlineData(60 * 60 * 24 * 12, "12 days")]
    public void Spans(int seconds, string expected) =>
        Assert.Equal(expected, Format.Span(TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void RelativeTimes()
    {
        var now = new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal("3 hours ago", Format.Relative(now.AddHours(-3), now));
        Assert.Equal("in 12 days", Format.Relative(now.AddDays(12), now));
    }

    [Fact]
    public void WrapKeepsWordsWhole()
    {
        var lines = Reporter.Wrap("one two three four five six", 9).ToList();
        Assert.Equal(["one two", "three", "four five", "six"], lines);
    }

    [Fact]
    public void SettingSyncUrisAreDecoded()
    {
        string blob = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"Uris\":[\"https://a.example/\",\"https://b.example/\"]}"));
        Assert.Equal(["https://a.example/", "https://b.example/"], DeviceCollector.SettingSyncUris(blob));
        Assert.Equal(["https://plain.example/"], DeviceCollector.SettingSyncUris("https://plain.example/"));
        Assert.Equal(["not base64!"], DeviceCollector.SettingSyncUris("not base64!"));
        Assert.Empty(DeviceCollector.SettingSyncUris(null));
    }

    [Fact]
    public void CredentialNames()
    {
        Assert.Equal("Generic", CredentialCollector.TypeName(1));
        Assert.Equal("Domain password", CredentialCollector.TypeName(2));
        Assert.Equal("Type 99", CredentialCollector.TypeName(99));
        Assert.Equal("Local machine", CredentialCollector.PersistenceName(2));
    }

    [Fact]
    public void KerberosNames()
    {
        Assert.Equal("AES-256-CTS-HMAC-SHA1-96", Collectors.KerberosNames.Encryption(18));
        Assert.Equal("RC4-HMAC", Collectors.KerberosNames.Encryption(23));
        Assert.Equal("etype 99", Collectors.KerberosNames.Encryption(99));
        Assert.True(Collectors.KerberosNames.IsDes(3));
        Assert.True(Collectors.KerberosNames.IsRc4(23));
        Assert.True(Collectors.KerberosNames.IsRc4(-128));
        Assert.False(Collectors.KerberosNames.IsRc4(18));
        Assert.Equal(["forwardable", "renewable", "initial", "pre_authent", "name_canonicalize"],
                     Collectors.KerberosNames.Flags(0x40E10000));
    }

    [Fact]
    public void FileTimes()
    {
        Assert.Null(KerberosCollector.Time(0));
        Assert.Null(KerberosCollector.Time(long.MaxValue));
        var t = new DateTimeOffset(2026, 10, 10, 9, 0, 0, TimeSpan.Zero);
        Assert.Equal(t, KerberosCollector.Time(t.UtcDateTime.ToFileTimeUtc()));
    }
}
