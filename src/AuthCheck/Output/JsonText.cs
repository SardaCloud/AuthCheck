// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Buffers;
using System.Collections;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace SardaCloud.AuthCheck.Output;

/// <summary>
/// Writes AuthCheck's JSON without reflection. Only the shapes the tool emits
/// are supported: scalars, times, string-keyed dictionaries and sequences.
/// </summary>
static class JsonText
{
    static readonly JsonWriterOptions Options = new()
    {
        Indented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string Object(IDictionary<string, object?> fields)
    {
        var buffer = new ArrayBufferWriter<byte>(512);
        using (var writer = new Utf8JsonWriter(buffer, Options))
        {
            Write(writer, fields);
        }
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>A time as UTC to the second, e.g. 2026-10-10T09:41:00Z.</summary>
    public static string Time(DateTimeOffset t) =>
        t.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    static void Write(Utf8JsonWriter w, object? value)
    {
        switch (value)
        {
            case null: w.WriteNullValue(); break;
            case string s: w.WriteStringValue(s); break;
            case bool b: w.WriteBooleanValue(b); break;
            case int i: w.WriteNumberValue(i); break;
            case uint u: w.WriteNumberValue(u); break;
            case long l: w.WriteNumberValue(l); break;
            case ulong ul: w.WriteNumberValue(ul); break;
            case double d: w.WriteNumberValue(d); break;
            case DateTimeOffset t: w.WriteStringValue(Time(t)); break;
            case Enum e: w.WriteStringValue(CamelCase(e.ToString())); break;

            case IDictionary<string, object?> map:
                w.WriteStartObject();
                foreach ((string key, object? item) in map)
                {
                    w.WritePropertyName(key);
                    Write(w, item);
                }
                w.WriteEndObject();
                break;

            case IEnumerable sequence:
                w.WriteStartArray();
                foreach (object? item in sequence) Write(w, item);
                w.WriteEndArray();
                break;

            default:
                w.WriteStringValue(Convert.ToString(value, CultureInfo.InvariantCulture));
                break;
        }
    }

    static string CamelCase(string s) =>
        s.Length == 0 ? s : char.ToLowerInvariant(s[0]) + s[1..];
}
