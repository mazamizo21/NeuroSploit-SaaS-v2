# timestomp Toolcard

## Overview
- Summary: Meterpreter built-in command for modifying MACE (Modified, Accessed, Created, Entry Modified) timestamps on Windows NTFS files. Modifies the `$STANDARD_INFORMATION` MFT attribute to make dropped files blend with legitimate system files. Part of the `priv` extension, available in all Windows Meterpreter sessions. On Linux, equivalent functionality via `touch` and `debugfs`. Tag MITRE: T1070.006 (Timestomp).

## Advanced Techniques
- Use `-f` to clone MACE from a legitimate reference file — **always preferred over setting arbitrary dates.**
- Reference files with old, stable timestamps: `C:\Windows\System32\svchost.exe`, `kernel32.dll`, `ntdll.dll`, `cmd.exe`, `notepad.exe`.
- Use `-r` for recursive timestomping of entire directories (dropped tool folders).
- Combine with file masquerading (T1036) — rename `implant.exe` to `svchost.exe` AND clone its timestamps.
- On NTFS, `$FILE_NAME` (FN) attribute is kernel-controlled. No userspace tool modifies it. Forensic tools (MFTECmd, X-Ways, Autopsy) detect SI vs FN mismatch as timestomping proof.
- Linux equivalent: `touch -r /bin/ls /tmp/implant` copies atime/mtime from reference. ctime cannot be set without clock manipulation or debugfs.
- PowerShell alternative (no Meterpreter needed): `(Get-Item C:\file.exe).CreationTime = $ref.CreationTime`

## Safe Defaults
- **Never use `-b` (blank)** — zero timestamps are the #1 forensic indicator of timestomping. EnCase, Autopsy, and Plaso all flag this immediately.
- **Don't set dates older than OS install** — a file from 2019 on a 2023 Windows install is a red flag.
- **Match the neighborhood** — timestamps should look like other files in the same directory, not random system files.
- **Fix directory timestamps** — adding files to a directory updates its mtime. Timestomp the directory too.
- Scope rules: only modify timestamps on files YOU dropped. Never modify timestamps on legitimate system files.

## Evidence Outputs
- outputs: evidence_timestomp.json

```powershell
# Before timestomping — capture original state
$file = Get-Item C:\target\implant.exe
@{
    technique = "T1070.006"
    file_path = $file.FullName
    original_created = $file.CreationTime.ToString("o")
    original_modified = $file.LastWriteTime.ToString("o")
    original_accessed = $file.LastAccessTime.ToString("o")
    reference_file = "C:\Windows\System32\svchost.exe"
    method = "meterpreter_timestomp"
    fn_attribute_modified = $false
} | ConvertTo-Json | Out-File C:\temp\.evidence_timestomp.json -Encoding UTF8
```

## Key Commands

### Meterpreter (Windows)
```
# View current MACE values
meterpreter > timestomp C:\\implant.exe -v

# Set all four timestamps at once (format: MM/DD/YYYY HH:MM:SS, UTC)
meterpreter > timestomp C:\\implant.exe -z "01/15/2023 10:30:00"

# Set individual timestamps
meterpreter > timestomp C:\\implant.exe -m "01/15/2023 10:30:00"   # Modified (last written)
meterpreter > timestomp C:\\implant.exe -a "01/15/2023 10:30:00"   # Accessed
meterpreter > timestomp C:\\implant.exe -c "01/15/2023 10:30:00"   # Created
meterpreter > timestomp C:\\implant.exe -e "01/15/2023 10:30:00"   # MFT entry modified

# Clone from reference file (BEST practice)
meterpreter > timestomp C:\\implant.exe -f C:\\Windows\\System32\\svchost.exe

# Recursive — all files in directory
meterpreter > timestomp C:\\ProgramData\\tools\\ -r -z "03/14/2019 08:00:00"

# Blank timestamps (⚠️ avoid on real engagements)
meterpreter > timestomp C:\\implant.exe -b
```

### All Flags
| Flag | Purpose |
|------|---------|
| `-v` | View current MACE values |
| `-m` | Set "last written" (modified) time |
| `-a` | Set "last accessed" time |
| `-c` | Set "creation" time |
| `-e` | Set "MFT entry modified" time |
| `-z` | Set all four MACE timestamps at once |
| `-f` | Copy MACE from another file (reference) |
| `-b` | Blank all timestamps (sets to epoch — ⚠️ detectable) |
| `-r` | Recursive (apply to all files in directory) |
| `-h` | Help banner |

### PowerShell (No Meterpreter)
```powershell
# Set timestamps directly
(Get-Item C:\implant.exe).CreationTime   = "01/15/2023 10:30:00"
(Get-Item C:\implant.exe).LastWriteTime  = "01/15/2023 10:30:00"
(Get-Item C:\implant.exe).LastAccessTime = "01/15/2023 10:30:00"

# Clone from reference
$ref = Get-Item C:\Windows\System32\cmd.exe
$t = Get-Item C:\implant.exe
'CreationTime','LastWriteTime','LastAccessTime' | % { $t.$_ = $ref.$_ }
```

### Linux (touch)
```bash
# Clone from reference (best)
touch -r /usr/bin/ls /tmp/implant

# Set specific timestamp
touch -t 202301151030.00 /tmp/implant          # YYYYMMDDhhmm.ss
touch -d "2023-01-15 10:30:00" /tmp/implant    # human-readable

# Bulk — match all files in directory
find /tmp/tools/ -type f -exec touch -r /bin/ls {} \;
```

### Cobalt Strike
```
beacon> timestomp C:\implant.exe C:\Windows\System32\svchost.exe
```

## References
- https://attack.mitre.org/techniques/T1070/006/
- https://www.offsec.com/metasploit-unleashed/timestomp/
- https://docs.metasploit.com/
