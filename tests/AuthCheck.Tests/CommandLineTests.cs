// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using SardaCloud.AuthCheck.Cli;

namespace SardaCloud.AuthCheck.Tests;

public class CommandLineTests
{
    static CommandLine Parse(params string[] args) => CommandLine.Parse(args, Usage.TakesValue);

    [Theory]
    [InlineData("/Device", "Device")]
    [InlineData("/dsreg", "Device")]
    [InlineData("-Klist", "Kerberos")]
    [InlineData("--kerberos", "Kerberos")]
    [InlineData("/CMDKEY", "Credentials")]
    [InlineData("/Mdm", "Mdm")]
    [InlineData("mdm", "Mdm")]
    [InlineData("/Action:Credentials", "Credentials")]
    [InlineData("/Action=klist", "Kerberos")]
    public void ActionsAndAliases(string arg, string expected)
    {
        CommandLine cl = Parse(arg);
        Assert.Equal(expected, cl.Action(Usage.Actions));
        cl.RejectUnknown();
    }

    [Fact]
    public void ActionAsSeparateValue()
    {
        CommandLine cl = Parse("/Action", "Device", "/Json");
        Assert.Equal("Device", cl.Action(Usage.Actions));
        Assert.True(cl.Flag("Json"));
        cl.RejectUnknown();
    }

    [Fact]
    public void NoActionMeansNull()
    {
        CommandLine cl = Parse("/Json");
        Assert.Null(cl.Action(Usage.Actions));
    }

    [Fact]
    public void TwoActionsAreRefused()
    {
        var ex = Assert.Throws<AuthCheckException>(() => Parse("/Device", "/Mdm").Action(Usage.Actions));
        Assert.Contains("one action", ex.Message);
    }

    [Fact]
    public void UnknownActionIsRefused()
    {
        Assert.Throws<AuthCheckException>(() => Parse("/Action", "Nope").Action(Usage.Actions));
    }

    [Fact]
    public void ActionSwitchTakesNoValue()
    {
        Assert.Throws<AuthCheckException>(() => Parse("/Device:yes").Action(Usage.Actions));
    }

    [Theory]
    [InlineData("/?")]
    [InlineData("-?")]
    [InlineData("/h")]
    [InlineData("--help")]
    [InlineData("/HELP")]
    public void Help(string arg) => Assert.True(Parse(arg).HelpRequested);

    [Fact]
    public void LogTakesTheNextToken()
    {
        CommandLine cl = Parse("/Log", @"C:\Logs\a.log", "/Quiet");
        Assert.Equal(@"C:\Logs\a.log", cl.Value("Log"));
        Assert.True(cl.Flag("Quiet"));
    }

    [Fact]
    public void LogWithColonKeepsTheDriveLetter()
    {
        Assert.Equal(@"C:\Logs\a.log", Parse(@"/Log:C:\Logs\a.log").Value("Log"));
    }

    [Fact]
    public void LogWithoutValueIsRefused()
    {
        Assert.Throws<AuthCheckException>(() => Parse("/Log"));
        Assert.Throws<AuthCheckException>(() => Parse("/Log", "/Json"));
    }

    [Fact]
    public void FlagsAcceptExplicitBooleans()
    {
        Assert.False(Parse("/Json:false").Flag("Json"));
        Assert.True(Parse("/Json:on").Flag("Json"));
        Assert.Throws<AuthCheckException>(() => Parse("/Json:maybe").Flag("Json"));
    }

    [Fact]
    public void UnknownSwitchIsReported()
    {
        CommandLine cl = Parse("/Device", "/NoSuchSwitch");
        cl.Action(Usage.Actions);
        var ex = Assert.Throws<AuthCheckException>(cl.RejectUnknown);
        Assert.Contains("/NoSuchSwitch", ex.Message);
    }

    [Fact]
    public void StrayWordIsReported()
    {
        CommandLine cl = Parse("/Device", "extra");
        cl.Action(Usage.Actions);
        var ex = Assert.Throws<AuthCheckException>(cl.RejectUnknown);
        Assert.Contains("extra", ex.Message);
    }

    [Fact]
    public void NegativeNumberIsNotASwitch()
    {
        CommandLine cl = Parse("-5");
        Assert.Throws<AuthCheckException>(cl.RejectUnknown);
    }

    [Theory]
    [InlineData(true, "/Json")]
    [InlineData(true, "--json")]
    [InlineData(true, "/Device", "-JSON")]
    [InlineData(true, "/Json:maybe")]
    [InlineData(true, "/Json", "/Log")]
    [InlineData(true, "/Quiet:maybe", "/Json")]
    [InlineData(false, "/Json:false")]
    [InlineData(false, "/Json:0")]
    [InlineData(false, "/Device")]
    [InlineData(false, "json")]
    [InlineData(false)]
    public void JsonIsRecognisedBeforeParsing(bool expected, params string[] args) =>
        Assert.Equal(expected, CommandLine.WantsJson(args));
}
