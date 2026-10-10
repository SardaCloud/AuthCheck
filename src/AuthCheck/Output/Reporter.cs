// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using System.Text;
using SardaCloud.AuthCheck.Cli;

namespace SardaCloud.AuthCheck.Output;

enum CheckStatus { Ok, Warn, Bad }

/// <summary>A verdict on one aspect of what AuthCheck examined.</summary>
sealed record Finding(CheckStatus Status, string Label, string Detail)
{
    public static Finding Ok(string label, string detail) => new(CheckStatus.Ok, label, detail);
    public static Finding Warn(string label, string detail) => new(CheckStatus.Warn, label, detail);
    public static Finding Bad(string label, string detail) => new(CheckStatus.Bad, label, detail);
}

/// <summary>
/// The single output channel. The text report goes to the console. With
/// /Json, stdout carries JSON Lines only, ending in a result line, and the
/// text report moves to stderr so a person watching still sees it. /Log keeps
/// a plain-text copy of the report.
/// </summary>
sealed class Reporter : IDisposable
{
    const int Width = 74;
    const int ValueColumn = 28;
    const int LabelWidth = 22;

    readonly TextWriter _text;
    readonly StreamWriter? _json;
    readonly StreamWriter? _log;
    readonly bool _colour;
    string _section = "";
    bool _started;
    bool _finished;
    bool _lastBlank;

    public bool JsonMode { get; }
    public bool Quiet { get; }
    public bool Verbose { get; }
    public bool NoLogo { get; }

    /// <summary>BAD checks: any of them makes the exit code 2.</summary>
    public int Findings { get; private set; }

    /// <summary>WARN checks and other warnings.</summary>
    public int Warnings { get; private set; }

    /// <summary>Sections that could not be read: any of them makes the exit code 1.</summary>
    public int Failures { get; private set; }

    /// <summary>Why the /Log file could not be opened, or null. The caller reports it.</summary>
    public string? LogError { get; }

    /// <summary>
    /// Reads the output switches. The JSON writer is opened before the log,
    /// so that even a failure to open the log can be reported as JSON.
    /// </summary>
    public Reporter(CommandLine cl)
    {
        JsonMode = cl.Flag("Json");
        Quiet = cl.Flag("Quiet");
        Verbose = cl.Flag("Verbose");
        NoLogo = cl.Flag("NoLogo");
        string? logPath = cl.Value("Log");

        _text = Console.Out;
        if (JsonMode)
        {
            _json = OpenJson();
            _text = Console.Error;
        }
        _colour = !(JsonMode ? Console.IsErrorRedirected : Console.IsOutputRedirected);

        if (logPath is not null)
        {
            try
            {
                string full = Path.GetFullPath(logPath);
                Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                _log = new StreamWriter(full, append: true, new UTF8Encoding(false)) { AutoFlush = true };
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                           or ArgumentException or NotSupportedException)
            {
                LogError = $"Cannot write the log file '{logPath}': {ex.Message}";
            }
        }
    }

    /// <summary>stdout for JSON Lines: nothing else on it, no BOM, LF line ends.</summary>
    static StreamWriter OpenJson() =>
        new(Console.OpenStandardOutput(), new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

    static Dictionary<string, object?> StartLine(string action) => new()
    {
        ["type"] = "start",
        ["tool"] = Product.Name,
        ["version"] = Product.Version,
        ["action"] = action,
        ["utc"] = DateTimeOffset.UtcNow
    };

    static Dictionary<string, object?> ResultLine(string action, int code, int findings, int warnings,
                                                  IDictionary<string, object?> data) => new()
    {
        ["type"] = "result",
        ["action"] = action,
        ["ok"] = code == ExitCode.Success,
        ["exitCode"] = code,
        ["findings"] = findings,
        ["warnings"] = warnings,
        ["data"] = data
    };

    /// <summary>
    /// The whole JSON conversation of a run that ends before a Reporter can
    /// exist, such as a malformed command line: start, the error, the result.
    /// </summary>
    public static void EmitAlone(string action, int code, string? error)
    {
        using StreamWriter json = OpenJson();
        json.WriteLine(JsonText.Object(StartLine(action)));
        if (error is not null)
            json.WriteLine(JsonText.Object(new Dictionary<string, object?> { ["type"] = "error", ["section"] = "", ["message"] = error }));
        json.WriteLine(JsonText.Object(ResultLine(action, code, 0, 0, new Dictionary<string, object?>())));
    }

    // ------------------------------------------------------------- headings

    public void Banner(string action)
    {
        Emit(StartLine(action));
        _started = true;

        string title = $"  {Product.Name} {Product.ShortVersion} - {Product.Purpose}";
        string notice = $"  {Product.Copyright}";
        Log($"--- {Product.Name} {Product.Version} / {action} / {DateTime.Now:yyyy-MM-dd HH:mm:ss} ---");
        Log(title);
        Log(notice);
        if (Quiet || NoLogo) return;

        WriteLine("", null);
        WriteLine(title, ConsoleColor.Cyan);
        WriteLine(notice, ConsoleColor.DarkGray);
    }

    /// <summary>Starts a section. <paramref name="replaces"/> names the command it stands in for.</summary>
    public void Section(string id, string title, string? replaces = null)
    {
        _section = id;
        string heading = replaces is null ? title : $"{title}  ({replaces})";
        Out("");
        Out(new string('=', Width), ConsoleColor.DarkCyan);
        Out("  " + heading, ConsoleColor.Cyan);
        Out(new string('=', Width), ConsoleColor.DarkCyan);
    }

    // ---------------------------------------------------------------- lines

    /// <summary>A key and its value. Nothing is shown when the value is empty.</summary>
    public void Kv(string key, string? value, int indent = 2)
    {
        if (string.IsNullOrEmpty(value)) return;
        string pad = new(' ', indent);
        int keyWidth = Math.Max(1, ValueColumn - indent - 2);
        string k = key.PadRight(keyWidth);
        Log($"{pad}{k}: {value}");
        if (Quiet) return;
        _lastBlank = false;
        Write($"{pad}{k}: ", ConsoleColor.DarkGray);
        WriteLine(value, null);
    }

    /// <summary>Like <see cref="Kv"/>, shown only with /Verbose.</summary>
    public void Detail(string key, string? value, int indent = 2)
    {
        if (Verbose) Kv(key, value, indent);
    }

    /// <summary>The heading of one entry in a list: a ticket, an enrollment, a credential.</summary>
    public void Item(string text, int indent = 2)
    {
        Out("");
        Out(new string(' ', indent) + text);
    }

    /// <summary>An explanation, wrapped and dimmed.</summary>
    public void Note(string text, int indent = 2)
    {
        foreach (string line in Wrap(text, Width - indent))
            Out(new string(' ', indent) + line, ConsoleColor.DarkGray);
    }

    public void Blank() => Out("");

    /// <summary>A verdict. BAD raises the exit code to 2.</summary>
    public void Check(Finding f)
    {
        if (f.Status == CheckStatus.Bad) Findings++;
        else if (f.Status == CheckStatus.Warn) Warnings++;

        string tag = f.Status switch
        {
            CheckStatus.Ok => "OK",
            CheckStatus.Warn => "WARN",
            _ => "BAD"
        };
        Emit(new()
        {
            ["type"] = "check",
            ["section"] = _section,
            ["status"] = tag.ToLowerInvariant(),
            ["label"] = f.Label,
            ["detail"] = f.Detail
        });

        string label = f.Label.PadRight(LabelWidth);
        Log($"  [{tag,-4}] {label} {f.Detail}");
        if (Quiet && f.Status == CheckStatus.Ok) return;

        ConsoleColor colour = f.Status switch
        {
            CheckStatus.Ok => ConsoleColor.Green,
            CheckStatus.Warn => ConsoleColor.Yellow,
            _ => ConsoleColor.Red
        };
        _lastBlank = false;
        Write($"  [{tag,-4}] ", colour);
        WriteLine($"{label} {f.Detail}", null);
    }

    public void Checks(IEnumerable<Finding> findings)
    {
        foreach (Finding f in findings) Check(f);
    }

    /// <summary>Something the user should know that is not a verdict on the device.</summary>
    public void Warn(string message)
    {
        Warnings++;
        Emit(new() { ["type"] = "warn", ["section"] = _section, ["message"] = message });
        Out("  [!] " + message, ConsoleColor.Yellow, important: true);
    }

    /// <summary>A section that could not be read. Raises the exit code to 1.</summary>
    public void Fail(string message, Exception? cause = null)
    {
        Failures++;
        Emit(new() { ["type"] = "error", ["section"] = _section, ["message"] = message });
        Out("  [x] " + message, ConsoleColor.Red, important: true);
        if (Verbose && cause is not null)
            Out(cause.ToString(), ConsoleColor.DarkGray, important: true);
    }

    // --------------------------------------------------------------- result

    /// <summary>The last thing written. Returns the exit code.</summary>
    public int Result(string action, IDictionary<string, object?> data)
    {
        int code = Failures > 0 ? ExitCode.Error
                 : Findings > 0 ? ExitCode.Findings
                 : ExitCode.Success;
        _finished = true;

        Emit(ResultLine(action, code, Findings, Warnings, data));

        string warnings = Warnings > 0 ? $", {Format.Plural(Warnings, "warning")}" : "";
        (string summary, ConsoleColor colour) = code switch
        {
            ExitCode.Success when Warnings == 0 => ($"  [+] {action}: nothing needs attention.", ConsoleColor.Green),
            ExitCode.Success => ($"  [+] {action}: no problems{warnings}.", ConsoleColor.Yellow),
            ExitCode.Findings => ($"  [x] {action}: {Format.Plural(Findings, "problem")}{warnings}.", ConsoleColor.Red),
            _ => ($"  [x] {action}: {Format.Plural(Failures, "section")} could not be read.", ConsoleColor.Red)
        };
        bool important = code != ExitCode.Success;
        Out("", important: important);
        Out(summary, colour, important);
        Log($"exit {code}");
        return code;
    }

    /// <summary>
    /// Reports a fatal error in whichever mode is active and returns its exit
    /// code. Under /Json the stream still opens with a start line and closes
    /// with a result line, however early the error came.
    /// </summary>
    public int Error(Exception ex, string action = "")
    {
        int code = ex is AuthCheckException a ? a.Code : ExitCode.Error;
        if (!_started)
        {
            Emit(StartLine(action));
            _started = true;
        }
        Emit(new() { ["type"] = "error", ["section"] = _section, ["message"] = ex.Message });
        if (!_finished)
        {
            Emit(ResultLine(action, code, Findings, Warnings, new Dictionary<string, object?>()));
            _finished = true;
        }

        Out("", important: true);
        Out("  [x] " + ex.Message, ConsoleColor.Red, important: true);
        if (Verbose && ex is not AuthCheckException)
            Out(ex.ToString(), ConsoleColor.DarkGray, important: true);
        return code;
    }

    // ------------------------------------------------------------- plumbing

    void Emit(Dictionary<string, object?> line) => _json?.WriteLine(JsonText.Object(line));

    void Log(string line) => _log?.WriteLine(line);

    void Out(string line, ConsoleColor? colour = null, bool important = false)
    {
        Log(line);
        if (Quiet && !important) return;
        WriteLine(line, colour);
    }

    void Write(string text, ConsoleColor? colour)
    {
        if (colour is null || !_colour)
        {
            _text.Write(text);
            return;
        }
        ConsoleColor old = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = colour.Value;
            _text.Write(text);
        }
        finally
        {
            Console.ForegroundColor = old;
        }
    }

    void WriteLine(string text, ConsoleColor? colour)
    {
        // Never two blank lines in a row, whatever order sections end in.
        bool blank = text.Length == 0;
        if (blank && _lastBlank) return;
        _lastBlank = blank;
        Write(text, colour);
        _text.WriteLine();
    }

    internal static IEnumerable<string> Wrap(string text, int width)
    {
        var line = new StringBuilder();
        foreach (string word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (line.Length > 0 && line.Length + 1 + word.Length > width)
            {
                yield return line.ToString();
                line.Clear();
            }
            if (line.Length > 0) line.Append(' ');
            line.Append(word);
        }
        if (line.Length > 0) yield return line.ToString();
    }

    public void Dispose()
    {
        _json?.Dispose();
        _log?.Dispose();
    }
}
