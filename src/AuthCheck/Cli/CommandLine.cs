// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

namespace SardaCloud.AuthCheck.Cli;

/// <summary>
/// The command line: <c>/Name</c>, <c>/Name value</c>, <c>/Name:value</c> and
/// <c>/Name=value</c>, matched case-insensitively, with <c>-</c> and
/// <c>--</c> accepted in place of <c>/</c>. Switches are read by name, and
/// whatever is never read is reported by <see cref="RejectUnknown"/> instead
/// of being silently ignored.
/// </summary>
sealed class CommandLine
{
    readonly Dictionary<string, string?> _switches = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _read = new(StringComparer.OrdinalIgnoreCase);
    readonly List<string> _positional = [];

    public bool HelpRequested { get; private set; }

    CommandLine() { }

    /// <summary>
    /// Parses <paramref name="args"/>. Only the switches named in
    /// <paramref name="takesValue"/> consume the next token; every other
    /// switch is a flag, so <c>/Kerberos /Json</c> can never be misread.
    /// </summary>
    public static CommandLine Parse(IReadOnlyList<string> args, IEnumerable<string> takesValue)
    {
        var valued = new HashSet<string>(takesValue, StringComparer.OrdinalIgnoreCase);
        var cl = new CommandLine();

        for (int i = 0; i < args.Count; i++)
        {
            string arg = args[i];
            if (arg.Length == 0) continue;

            if (!IsSwitch(arg))
            {
                cl._positional.Add(arg);
                continue;
            }

            string body = arg.TrimStart('/', '-');
            if (body is "?" ||
                body.Equals("h", StringComparison.OrdinalIgnoreCase) ||
                body.Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                cl.HelpRequested = true;
                continue;
            }

            string name;
            string? value = null;
            int sep = body.IndexOfAny([':', '=']);
            if (sep >= 0)
            {
                name = body[..sep];
                value = body[(sep + 1)..];
            }
            else
            {
                name = body;
                if (valued.Contains(name))
                {
                    if (i + 1 >= args.Count || IsSwitch(args[i + 1]))
                        throw new AuthCheckException($"/{name} needs a value.");
                    value = args[++i];
                }
            }

            if (name.Length == 0)
                throw new AuthCheckException($"'{arg}' is not a switch. Try /? for the list.");
            cl._switches[name] = value;
        }
        return cl;
    }

    /// <summary>True for <c>/x</c>, <c>-x</c> and <c>--x</c>; false for a lone dash or a negative number.</summary>
    static bool IsSwitch(string s) =>
        s.Length > 1 && (s[0] == '/' || (s[0] == '-' && !char.IsDigit(s[1])));

    /// <summary>
    /// Whether /Json was asked for, read from the raw arguments by the same
    /// rules as <see cref="Parse"/>. It lets even a command line that Parse
    /// rejects be answered in JSON. Anything but an explicit false counts.
    /// </summary>
    public static bool WantsJson(IReadOnlyList<string> args)
    {
        bool json = false;
        foreach (string arg in args)
        {
            if (!IsSwitch(arg)) continue;
            string body = arg.TrimStart('/', '-');
            int sep = body.IndexOfAny([':', '=']);
            string name = sep >= 0 ? body[..sep] : body;
            if (!name.Equals("Json", StringComparison.OrdinalIgnoreCase)) continue;
            string? value = sep >= 0 ? body[(sep + 1)..].ToLowerInvariant() : null;
            json = value is not ("false" or "no" or "off" or "0");
        }
        return json;
    }

    /// <summary>True when the switch is present, unless written as <c>/Name:false</c>.</summary>
    public bool Flag(string name)
    {
        if (!_switches.TryGetValue(name, out string? value)) return false;
        _read.Add(name);
        if (value is null) return true;
        return value.ToLowerInvariant() switch
        {
            "true" or "yes" or "on" or "1" => true,
            "false" or "no" or "off" or "0" => false,
            _ => throw new AuthCheckException($"/{name} takes true or false, not '{value}'.")
        };
    }

    /// <summary>The value of a switch that takes one, or null when the switch is absent.</summary>
    public string? Value(string name)
    {
        if (!_switches.TryGetValue(name, out string? value)) return null;
        _read.Add(name);
        if (string.IsNullOrEmpty(value)) throw new AuthCheckException($"/{name} needs a value.");
        return value;
    }

    /// <summary>
    /// The action, given as <c>/Action Name</c>, as a bare <c>/Name</c>, or as
    /// a first word without a slash, and matched against <paramref name="names"/>,
    /// which maps every accepted spelling, aliases included, to its action.
    /// Returns null when none is given; more than one is an error.
    /// </summary>
    public string? Action(IReadOnlyDictionary<string, string> names)
    {
        var found = new List<string>();

        string? given = Value("Action");
        if (given is not null)
        {
            found.Add(names.TryGetValue(given, out string? a) ? a
                : throw new AuthCheckException(
                    $"/Action takes {string.Join(", ", names.Values.Distinct())}, not '{given}'."));
        }

        foreach ((string key, string? value) in _switches)
        {
            if (!names.TryGetValue(key, out string? action)) continue;
            if (value is not null) throw new AuthCheckException($"/{key} does not take a value.");
            _read.Add(key);
            found.Add(action);
        }

        if (_positional.Count > 0 && names.TryGetValue(_positional[0], out string? word))
        {
            found.Add(word);
            _positional.RemoveAt(0);
        }

        var distinct = found.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (distinct.Count > 1)
            throw new AuthCheckException(
                $"Choose one action, not {string.Join(" and ", distinct.Select(d => "/" + d))}.");
        return distinct.Count == 1 ? distinct[0] : null;
    }

    /// <summary>
    /// Call once every switch has been read. Anything left over is a typo and
    /// is reported rather than ignored.
    /// </summary>
    public void RejectUnknown()
    {
        if (_positional.Count > 0)
            throw new AuthCheckException($"Unexpected argument '{_positional[0]}'. Try /? for the list.");

        var unknown = _switches.Keys.Where(k => !_read.Contains(k)).ToList();
        if (unknown.Count == 1)
            throw new AuthCheckException($"Unknown switch /{unknown[0]}. Try /? for the list.");
        if (unknown.Count > 1)
            throw new AuthCheckException(
                $"Unknown switches: {string.Join(", ", unknown.Select(k => "/" + k))}. Try /? for the list.");
    }
}
