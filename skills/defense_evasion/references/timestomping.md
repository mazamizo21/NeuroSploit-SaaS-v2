# Timestomping — File Timestamp Manipulation

Tag MITRE: T1070.006 (Timestomp)

## File Timestamp Types

### Linux (via `stat`)
| Timestamp | Abbreviation | Updated When | Userspace Modifiable? |
|-----------|-------------|--------------|----------------------|
| Access time | `atime` | File read (cat, less, open) | ✅ `touch -a` |
| Modify time | `mtime` | File content changed | ✅ `touch -m` |
| Change time | `ctime` | Inode metadata changed (chmod, chown, rename) | ❌ Only via clock manipulation or debugfs |
| Birth time | `crtime` | File creation (ext4 only) | ❌ Only via debugfs |

### Windows NTFS (via MFT)
| MFT Attribute | Timestamps Stored | Userspace Modifiable? |
|---------------|-------------------|----------------------|
| `$STANDARD_INFORMATION` (SI) | Created, Modified, Accessed, MFT Entry Modified | ✅ PowerShell, timestomp |
| `$FILE_NAME` (FN) | Created, Modified, Accessed, MFT Entry Modified | ❌ Kernel-only updates |

> **⚠️ FORENSIC DETECTION:** If SI timestamps are older than FN timestamps, timestomping is confirmed. No userspace tool can modify $FILE_NAME. Advanced forensic tools (MFTECmd, Autopsy, X-Ways) always check both.

## Evidence Capture — Before Timestomping

```bash
# Linux: Record original timestamps for evidence.json
stat /target/path/malicious_file > /tmp/.ts_evidence_before.txt

# Windows (PowerShell):
$file = Get-Item C:\target\malicious.exe
@{
    technique = "T1070.006"
    file = $file.FullName
    original_created = $file.CreationTime.ToString("o")
    original_modified = $file.LastWriteTime.ToString("o")
    original_accessed = $file.LastAccessTime.ToString("o")
} | ConvertTo-Json | Out-File C:\temp\.ts_evidence_before.json
```

## Linux Timestomping

### touch Command
```bash
# Copy timestamps from a reference file (BEST technique — blend in)
touch -r /usr/bin/ls /tmp/implant
touch -r /usr/bin/python3 /tmp/backdoor.py

# Set specific timestamp
touch -t 202301151030.00 /tmp/implant               # YYYYMMDDhhmm.ss
touch -d "2023-01-15 10:30:00" /tmp/implant          # human-readable
touch -d "2023-01-15T10:30:00" /tmp/implant          # ISO 8601

# Set only access time
touch -a -t 202301151030.00 /tmp/implant

# Set only modification time
touch -m -t 202301151030.00 /tmp/implant
```

> **⚠️ SAFETY: `touch` modifies atime/mtime but ALWAYS updates ctime to NOW. A forensic examiner seeing mtime=2023 but ctime=2024 knows you timestomped.**

### Bulk timestomping (directory of tools)
```bash
# Survey target directory first — what do real timestamps look like?
ls -la --time=ctime /target/dir/
stat /target/dir/*

# Match all dropped files to a legitimate reference
find /tmp/tools/ -type f -exec touch -r /bin/ls {} \;

# Fix directory timestamp too (adding files updates dir mtime)
touch -r /usr/share /tmp/tools/
```

### Modifying ctime (Change Time) — Clock Manipulation
```bash
# Method 1: Temporarily change system clock (requires root)
timedatectl set-ntp no
timedatectl set-time "2023-01-15 10:30:00"
touch /tmp/implant                        # ctime now matches the fake clock
chmod 644 /tmp/implant                    # ctime updated to fake time too
timedatectl set-ntp yes                   # RESTORE NTP immediately

# Method 2: date command
date -s "2023-01-15 10:30:00"
touch /tmp/implant
# Restore via NTP
ntpdate pool.ntp.org || date -s "$(curl -s http://worldtimeapi.org/api/ip | jq -r .datetime)"
```

> **⚠️ SAFETY: Changing system clock affects ALL processes and logs. Do this FAST and restore immediately. Causes visible time discontinuities in logs.**

### debugfs — Modify ext4 Birth Time (crtime)
```bash
# Get device and inode
df /tmp/implant                           # device: e.g., /dev/sda1
stat -c '%i' /tmp/implant                 # inode number

# Modify all timestamps including crtime (REQUIRES unmounted or -w on mounted — risky)
debugfs -w -R 'set_inode_field <INODE> crtime 202301151030' /dev/sda1
debugfs -w -R 'set_inode_field <INODE> ctime 202301151030' /dev/sda1
debugfs -w -R 'set_inode_field <INODE> mtime 202301151030' /dev/sda1
debugfs -w -R 'set_inode_field <INODE> atime 202301151030' /dev/sda1
```

### Python — os.utime() (atime + mtime only)
```python
import os, time
target_time = time.mktime(time.strptime("2023-01-15 10:30:00", "%Y-%m-%d %H:%M:%S"))
os.utime("/tmp/implant", (target_time, target_time))  # (atime, mtime)

# Copy timestamps from reference file
ref = os.stat("/usr/bin/ls")
os.utime("/tmp/implant", (ref.st_atime, ref.st_mtime))
```

## Windows Timestomping

### Metasploit Meterpreter timestomp
```
# View current MACE values
meterpreter > timestomp C:\\implant.exe -v
Modified      : 2024-02-11 20:30:00
Accessed      : 2024-02-11 20:31:00
Created       : 2024-02-11 20:30:00
Entry Modified: 2024-02-11 20:30:00

# Set individual timestamps (format: MM/DD/YYYY HH:MM:SS)
meterpreter > timestomp C:\\implant.exe -m "01/15/2023 10:30:00"    # modified
meterpreter > timestomp C:\\implant.exe -a "01/15/2023 10:30:00"    # accessed
meterpreter > timestomp C:\\implant.exe -c "01/15/2023 10:30:00"    # created
meterpreter > timestomp C:\\implant.exe -e "01/15/2023 10:30:00"    # MFT entry modified

# Set ALL four MACE values at once
meterpreter > timestomp C:\\implant.exe -z "01/15/2023 10:30:00"

# Copy timestamps from legitimate file (BEST approach)
meterpreter > timestomp C:\\implant.exe -f C:\\Windows\\System32\\svchost.exe

# Blank all timestamps (shows blanks in EnCase)
meterpreter > timestomp C:\\implant.exe -b

# Recursive — entire directory
meterpreter > timestomp C:\\ProgramData\\tools\\ -r -z "01/15/2023 10:30:00"
```

> **⚠️ SAFETY: NEVER use `-b` (blank) on a real engagement. Zero/blank timestamps are the first thing forensics tools flag. Always use `-f` with a reference file.**

### PowerShell
```powershell
# Set timestamps directly
(Get-Item C:\implant.exe).CreationTime   = "01/15/2023 10:30:00"
(Get-Item C:\implant.exe).LastWriteTime  = "01/15/2023 10:30:00"
(Get-Item C:\implant.exe).LastAccessTime = "01/15/2023 10:30:00"

# Copy timestamps from legitimate reference file
$ref = Get-Item C:\Windows\System32\cmd.exe
$target = Get-Item C:\implant.exe
$target.CreationTime   = $ref.CreationTime
$target.LastWriteTime  = $ref.LastWriteTime
$target.LastAccessTime = $ref.LastAccessTime

# One-liner: clone timestamps from reference
$r = gi C:\Windows\System32\cmd.exe; $t = gi C:\implant.exe; 'CreationTime','LastWriteTime','LastAccessTime' | % { $t.$_ = $r.$_ }

# Set on a directory
(Get-Item C:\ProgramData\tools).CreationTime = "01/15/2023 10:30:00"
```

### Cobalt Strike
```
beacon> timestomp C:\implant.exe C:\Windows\System32\svchost.exe
# Copies MACE from svchost.exe to implant.exe
```

## Strategy: Blending In

1. **Survey first:** Check what timestamps exist in the target directory
   ```bash
   ls -la /target/dir/ | head -20
   stat /target/dir/legitimate_file.txt
   ```

2. **Use reference files from the same directory** — not system files from a different folder

3. **Good reference files (Windows):** These have old, stable timestamps:
   - `C:\Windows\System32\cmd.exe`
   - `C:\Windows\System32\svchost.exe`
   - `C:\Windows\System32\kernel32.dll`
   - `C:\Windows\System32\ntdll.dll`
   - `C:\Windows\notepad.exe`

4. **Don't use obviously fake dates** — a file dated 1970 or 2050 in a 2024 directory is suspicious

5. **Match the OS install date range** — files older than the OS install are a forensic red flag

6. **Remember directory timestamps change** when you add files inside them — fix the directory mtime too

## Evidence Capture — After Timestomping

```bash
# Linux
cat > /tmp/.evidence_timestomp.json << EOF
{
  "technique": "T1070.006",
  "technique_name": "Timestomp",
  "files_modified": ["/tmp/implant"],
  "reference_file": "/usr/bin/ls",
  "method": "touch -r",
  "original_mtime": "2024-02-11 20:30:00",
  "new_mtime": "2023-01-15 10:30:00",
  "ctime_updated": true,
  "notes": "ctime reflects real modification time — detectable by forensics"
}
EOF
```

```powershell
# Windows
@{
    technique = "T1070.006"
    technique_name = "Timestomp"
    files_modified = @("C:\implant.exe")
    reference_file = "C:\Windows\System32\svchost.exe"
    method = "meterpreter_timestomp_-f"
    fn_attribute_modified = $false
    notes = "SI timestamps cloned from svchost. FN attribute NOT modified — detectable via MFT analysis."
} | ConvertTo-Json | Out-File C:\temp\.evidence_timestomp.json -Encoding UTF8
```

## Detection Summary

| What Defenders Check | Linux | Windows |
|---------------------|-------|---------|
| mtime vs ctime mismatch | ✅ `stat` shows both | N/A (no ctime equivalent) |
| SI vs FN timestamp mismatch | N/A | ✅ MFTECmd, Autopsy |
| Timestamps older than OS install | ✅ compare vs `/` crtime | ✅ compare vs Windows install date |
| USN Journal real timestamps | N/A | ✅ `$UsnJrnl:$J` has real creation record |
| Log correlation | ✅ auth.log timestamps vs file timestamps | ✅ Event 4688 vs file creation time |
