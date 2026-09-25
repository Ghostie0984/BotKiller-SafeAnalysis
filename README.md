# BotKiller Safe Analysis

This repository contains a harmless, analysis-only security tool inspired by the original BotKiller concept. It does not kill processes, delete files, or modify the Windows registry.

## What this tool does

- Scans running processes
- Flags potentially suspicious executables using basic heuristics
- Reviews Run and RunOnce startup entries
- Prints a human-readable report
- Optionally saves JSON output for review

## Important notes

- This tool is designed for educational or incident-response analysis only.
- It intentionally avoids any destructive behavior.
- Use it in a controlled environment and validate all findings manually.

## Build

```bash
dotnet build
```

## Run

```bash
dotnet run --project BotKillerSafeAnalysis.csproj
```

JSON output:

```bash
dotnet run --project BotKillerSafeAnalysis.csproj -- --json --report report.json
```

## Example output

```text
BotKiller Safe Analysis Report
============================
This tool is analysis-only and never terminates processes or deletes files.

Suspicious processes: 2
- PID 4321: wscript.exe [HIGH] C:\Users\User\AppData\Local\Temp\payload.exe
  Reasons: Executable lives under user profile; Script host process detected

Suspicious startup entries: 1
- Software\Microsoft\Windows\CurrentVersion\Run [HIGH] MyApp = C:\Users\User\AppData\Local\Temp\payload.exe
  Reasons: Startup entry points to a user or common app-data path; Startup entry points to a script host
```

## Safety guarantee

This companion project is intentionally non-destructive and is not intended to be used as malware removal software.

If you want a version that performs deeper, stricter detection in a lab-only environment, I can also provide a read-only "forensics" variant with:

- hash-based checks
- PE signature validation
- whitelists
- CSV exports
- threat scoring

without adding any destructive actions.
