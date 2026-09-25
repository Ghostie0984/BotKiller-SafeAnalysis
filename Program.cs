using System.Diagnostics;
using System.Text.Json;
using Microsoft.Win32;

namespace BotKillerSafeAnalysis;

internal static class Program
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";

    private static readonly string[] ScriptHosts =
    {
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    };

    public static int Main(string[] args)
    {
        bool jsonOutput = args.Contains("--json", StringComparer.OrdinalIgnoreCase);
        string? reportPath = GetArgumentValue(args, "--report");

        try
        {
            var report = new SecurityReport();

            report.Processes = GetProcessFindings();
            report.StartupEntries = GetStartupFindings();

            if (jsonOutput)
            {
                var json = JsonSerializer.Serialize(report, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                if (!string.IsNullOrWhiteSpace(reportPath))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(reportPath) ?? ".");
                    File.WriteAllText(reportPath, json);
                    Console.WriteLine($"Saved JSON report to: {reportPath}");
                }
                else
                {
                    Console.WriteLine(json);
                }
            }
            else
            {
                PrintTextReport(report);
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Analysis failed: {ex.Message}");
            return 1;
        }
    }

    private static void PrintTextReport(SecurityReport report)
    {
        Console.WriteLine("BotKiller Safe Analysis Report");
        Console.WriteLine("============================");
        Console.WriteLine("This tool is analysis-only and never terminates processes or deletes files.");
        Console.WriteLine();

        Console.WriteLine($"Suspicious processes: {report.Processes.Count}");
        foreach (var process in report.Processes)
        {
            Console.WriteLine($"- PID {process.Pid}: {process.ProcessName} [{process.Severity}] {process.Path}");
            Console.WriteLine($"  Reasons: {string.Join("; ", process.Reasons)}");
        }

        Console.WriteLine();
        Console.WriteLine($"Suspicious startup entries: {report.StartupEntries.Count}");
        foreach (var entry in report.StartupEntries)
        {
            Console.WriteLine($"- {entry.KeyName} [{entry.Severity}] {entry.ValueName} = {entry.Value}");
            Console.WriteLine($"  Reasons: {string.Join("; ", entry.Reasons)}");
        }

        if (report.Processes.Count == 0 && report.StartupEntries.Count == 0)
        {
            Console.WriteLine("No suspicious activity observed in the current scan.");
        }
    }

    private static List<ProcessFinding> GetProcessFindings()
    {
        var findings = new List<ProcessFinding>();
        var currentProcessPath = Process.GetCurrentProcess().MainModule?.FileName ?? string.Empty;
        var commonApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var dotNetPath = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? systemRoot, "Windows\\Microsoft.NET");

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == 0)
                    continue;

                var processPath = process.MainModule?.FileName;
                if (string.IsNullOrWhiteSpace(processPath))
                    continue;

                var reasons = new List<string>();
                var severity = "LOW";

                if (string.Equals(processPath, currentProcessPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (processPath.StartsWith(commonApplicationData, StringComparison.OrdinalIgnoreCase))
                {
                    reasons.Add("Executable lives under CommonApplicationData");
                    severity = "HIGH";
                }

                if (processPath.StartsWith(userProfile, StringComparison.OrdinalIgnoreCase))
                {
                    reasons.Add("Executable lives under user profile");
                    severity = "MEDIUM";
                }

                if (processPath.StartsWith(dotNetPath, StringComparison.OrdinalIgnoreCase))
                {
                    reasons.Add("Executable lives under .NET framework directory");
                    severity = "MEDIUM";
                }

                if (ScriptHosts.Contains(Path.GetFileName(processPath), StringComparer.OrdinalIgnoreCase))
                {
                    reasons.Add("Script host process detected");
                    severity = severity == "HIGH" ? "HIGH" : "MEDIUM";
                }

                if (process.MainWindowHandle == IntPtr.Zero && process.SessionId >= 0)
                {
                    reasons.Add("Process does not have a visible window");
                    severity = severity == "HIGH" ? "HIGH" : "MEDIUM";
                }

                if (reasons.Count > 0)
                {
                    findings.Add(new ProcessFinding
                    {
                        Pid = process.Id,
                        ProcessName = process.ProcessName,
                        Path = processPath,
                        Severity = severity,
                        Reasons = reasons
                    });
                }
            }
            catch
            {
                // Intentionally ignore protected or inaccessible processes.
            }
            finally
            {
                try
                {
                    process.Dispose();
                }
                catch
                {
                    // Safe best effort cleanup.
                }
            }
        }

        return findings
            .OrderByDescending(f => GetSeverityWeight(f.Severity))
            .ThenBy(f => f.ProcessName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<StartupFinding> GetStartupFindings()
    {
        var findings = new List<StartupFinding>();
        var lookupKeys = new[]
        {
            RunKey,
            RunOnceKey
        };

        foreach (var keyPath in lookupKeys)
        {
            try
            {
                using var hive = Registry.CurrentUser.OpenSubKey(keyPath, false);
                if (hive == null)
                {
                    continue;
                }

                foreach (var valueName in hive.GetValueNames())
                {
                    var value = hive.GetValue(valueName, null);
                    if (value is null)
                    {
                        continue;
                    }

                    var text = value.ToString();
                    if (string.IsNullOrWhiteSpace(text))
                    {
                        continue;
                    }

                    var reasons = new List<string>();
                    var severity = "LOW";

                    if (text.Contains("wscript", StringComparison.OrdinalIgnoreCase) ||
                        text.Contains("cscript", StringComparison.OrdinalIgnoreCase) ||
                        text.Contains("mshta", StringComparison.OrdinalIgnoreCase))
                    {
                        reasons.Add("Startup entry points to a script host");
                        severity = "HIGH";
                    }

                    if (text.Contains(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), StringComparison.OrdinalIgnoreCase) ||
                        text.Contains(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), StringComparison.OrdinalIgnoreCase))
                    {
                        reasons.Add("Startup entry points to a user or common app-data path");
                        severity = severity == "HIGH" ? "HIGH" : "MEDIUM";
                    }

                    if (reasons.Count > 0)
                    {
                        findings.Add(new StartupFinding
                        {
                            KeyName = keyPath,
                            ValueName = valueName,
                            Value = text,
                            Severity = severity,
                            Reasons = reasons
                        });
                    }
                }
            }
            catch
            {
                // Ignore inaccessible registry locations.
            }
        }

        return findings
            .OrderByDescending(f => GetSeverityWeight(f.Severity))
            .ThenBy(f => f.ValueName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static int GetSeverityWeight(string severity)
    {
        return severity.ToUpperInvariant() switch
        {
            "HIGH" => 3,
            "MEDIUM" => 2,
            "LOW" => 1,
            _ => 0
        };
    }

    private static string? GetArgumentValue(IReadOnlyList<string> args, string name)
    {
        for (var i = 0; i < args.Count; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count)
            {
                return args[i + 1];
            }
        }

        return null;
    }
}

internal sealed class SecurityReport
{
    public List<ProcessFinding> Processes { get; set; } = new();
    public List<StartupFinding> StartupEntries { get; set; } = new();
}

internal sealed class ProcessFinding
{
    public int Pid { get; set; }
    public string ProcessName { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Severity { get; set; } = "LOW";
    public List<string> Reasons { get; set; } = new();
}

internal sealed class StartupFinding
{
    public string KeyName { get; set; } = string.Empty;
    public string ValueName { get; set; } = string.Empty;
    public string Value { get; set; } = string.Empty;
    public string Severity { get; set; } = "LOW";
    public List<string> Reasons { get; set; } = new();
}
