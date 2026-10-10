// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Globalization;

namespace SardaCloud.AuthCheck.Output;

/// <summary>How times, ages and codes look in the text report.</summary>
static class Format
{
    static readonly CultureInfo Invariant = CultureInfo.InvariantCulture;

    /// <summary>Local time to the minute, e.g. 2026-10-10 11:41.</summary>
    public static string Time(DateTimeOffset? t) =>
        t is null ? "" : t.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm", Invariant);

    /// <summary>Local date, e.g. 2026-10-10.</summary>
    public static string Date(DateTimeOffset? t) =>
        t is null ? "" : t.Value.ToLocalTime().ToString("yyyy-MM-dd", Invariant);

    /// <summary>A span as people say it: "5 minutes", "3 hours", "12 days".</summary>
    public static string Span(TimeSpan span)
    {
        span = span.Duration();
        if (span.TotalMinutes < 1) return "less than a minute";
        if (span.TotalHours < 1) return Plural((int)span.TotalMinutes, "minute");
        if (span.TotalDays < 2) return Plural((int)span.TotalHours, "hour");
        return Plural((int)span.TotalDays, "day");
    }

    /// <summary>"3 hours ago" or "in 12 days".</summary>
    public static string Relative(DateTimeOffset t, DateTimeOffset now) =>
        t <= now ? $"{Span(now - t)} ago" : $"in {Span(t - now)}";

    public static string Plural(int n, string unit) =>
        n == 1 ? $"1 {unit}" : $"{n.ToString(Invariant)} {unit}s";

    public static string Hex(int value) => "0x" + value.ToString("X8", Invariant);

    public static string Hex(uint value) => "0x" + value.ToString("X8", Invariant);

    public static string YesNo(bool value) => value ? "yes" : "no";
}
