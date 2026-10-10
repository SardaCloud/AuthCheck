// Copyright (C) 2026 Sarda Cloud Srl, www.sardacloud.com.
// Licensed under the MIT License. See LICENSE in the repository root.

using SardaCloud.AuthCheck.Cli;
using SardaCloud.AuthCheck.Collectors;
using SardaCloud.AuthCheck.Output;
using SardaCloud.AuthCheck.Reports;

namespace SardaCloud.AuthCheck;

static class Program
{
    static int Main(string[] args)
    {
        // Decided before parsing, so that a command line Parse rejects can
        // still be answered in JSON when JSON was asked for.
        bool json = CommandLine.WantsJson(args);

        CommandLine cl;
        Reporter reporter;
        try
        {
            cl = CommandLine.Parse(args, Usage.TakesValue);
            if (cl.HelpRequested)
            {
                if (json)
                {
                    Usage.Print(Console.Error);
                    Reporter.EmitAlone("Help", ExitCode.Success, null);
                }
                else
                {
                    Usage.Print(Console.Out);
                }
                return ExitCode.Success;
            }
            reporter = new Reporter(cl);
        }
        catch (AuthCheckException ex)
        {
            Console.Error.WriteLine($"  [x] {ex.Message}");
            if (json) Reporter.EmitAlone("", ex.Code, ex.Message);
            return ex.Code;
        }

        using (reporter)
        {
            string action = "";
            try
            {
                if (reporter.LogError is not null) throw new AuthCheckException(reporter.LogError);
                action = cl.Action(Usage.Actions) ?? "Status";
                cl.RejectUnknown();
                return Run(reporter, action);
            }
            catch (Exception ex)
            {
                return reporter.Error(ex, action);
            }
        }
    }

    static int Run(Reporter r, string action)
    {
        DateTimeOffset now = DateTimeOffset.Now;
        bool all = action == "Status";
        r.Banner(action);

        SessionContext context = SessionContext.Read(now);
        ContextReport.Show(r, context);
        Dictionary<string, object?> data = ContextReport.Data(context);

        // The MDM and Kerberos checks are judged against the join state, so it
        // is read up front even when its own section is not shown.
        DeviceState? device = null;
        Exception? deviceError = null;
        if (all || action is "Device" or "Mdm" or "Kerberos")
        {
            try
            {
                device = DeviceCollector.Collect();
            }
            catch (Exception ex) when (ex is not AuthCheckException)
            {
                deviceError = ex;
            }
        }

        if (all || action == "Device")
        {
            r.Section("device", "DEVICE REGISTRATION", "dsregcmd /status");
            if (device is not null)
            {
                DeviceReport.Show(r, device, now);
                data["device"] = DeviceReport.Data(device);
            }
            else if (deviceError is not null)
            {
                r.Fail($"Could not read the join state: {deviceError.Message}", deviceError);
                data["device"] = D.Error(deviceError);
            }

            r.Section("prt", "PRIMARY REFRESH TOKEN AND SINGLE SIGN-ON");
            Read(r, data, "prt", () =>
            {
                CloudKerberosResult cloud = KerberosCollector.QueryCloud();
                PrtReport.Show(r, device, cloud);
                return PrtReport.Data(device, cloud);
            });
        }

        if (all || action == "Mdm")
        {
            r.Section("mdm", "DEVICE MANAGEMENT", "MDM, Intune, Configuration Manager");
            Read(r, data, "mdm", () =>
            {
                MdmState mdm = MdmCollector.Collect();
                MdmReport.Show(r, mdm, device, now);
                return MdmReport.Data(mdm);
            });
        }

        if (all || action == "Kerberos")
        {
            r.Section("kerberos", "KERBEROS TICKETS", "klist");
            Read(r, data, "kerberos", () =>
            {
                KerberosState kerberos = KerberosCollector.Collect();
                KerberosReport.Show(r, kerberos, device, Environment.UserDomainName, now);
                return KerberosReport.Data(kerberos);
            });
        }

        if (all || action == "Credentials")
        {
            r.Section("credentials", "STORED CREDENTIALS", "cmdkey /list");
            Read(r, data, "credentials", () =>
            {
                CredentialState credentials = CredentialCollector.Collect();
                CredentialReport.Show(r, credentials);
                return CredentialReport.Data(credentials);
            });
        }

        return r.Result(action, data);
    }

    /// <summary>
    /// Runs one section. A source that cannot be read is reported and the
    /// other sections still run; the exit code becomes 1.
    /// </summary>
    static void Read(Reporter r, Dictionary<string, object?> data, string key, Func<Dictionary<string, object?>> section)
    {
        try
        {
            data[key] = section();
        }
        catch (Exception ex) when (ex is not AuthCheckException)
        {
            r.Fail($"Could not read this section: {ex.Message}", ex);
            data[key] = D.Error(ex);
        }
    }
}
