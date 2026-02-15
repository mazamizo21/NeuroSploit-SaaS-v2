---
name: defense-evasion
description: Comprehensive defense evasion for post-exploitation. Evade detection, manipulate logs, obfuscate payloads, clean artifacts, and bypass security controls. Evidence-only assessment when not authorized.
---

# Defense Evasion & Cleanup Skill

## Overview
Comprehensive defense evasion for post-exploitation. When `allow_defense_evasion=true`, actively evade detection, manipulate logs, obfuscate payloads, and clean artifacts. When disabled, perform evidence-only assessment of evasion risks and gaps.

## Scope Rules
1. Only operate on explicitly authorized systems.
2. Check `allow_defense_evasion` flag before ANY active evasion technique.
3. If disabled → evidence-only validation (document risks, no changes).
4. If enabled → use minimal, reversible actions. Document everything for cleanup.
5. **NEVER** brick the target — no kernel mods, no wiping system-critical logs wholesale.
6. ALWAYS maintain a cleanup log of every change made.

## Decision Tree: When to Use What

```
Target compromised → Check allow_defense_evasion
├── FALSE → Evidence-only mode
│   ├── Enumerate security controls (AV, EDR, SIEM, logging)
│   ├── Document logging gaps and blind spots
│   ├── Assess tamper protection status
│   └── Output: defense_controls.json, findings.json
└── TRUE → Active evasion enabled
    ├── Just got initial access?
    │   ├── Clean exploit traces → references/artifact_cleanup.md
    │   └── Timestomp dropped files → references/timestomping.md
    ├── Need to run tools on target?
    │   ├── Obfuscate payloads → references/payload_obfuscation.md
    │   └── Disable/redirect logs FIRST → Phase 2 below
    ├── AV/EDR blocking execution?
    │   ├── Process injection → references/process_injection.md
    │   └── LOLBins / AMSI bypass → references/av_edr_bypass.md
    ├── Need covert C2 channel?
    │   └── DNS/ICMP tunneling → references/network_evasion_techniques.md
    └── Finishing engagement?
        └── Full cleanup checklist → Phase 6 below
```

## Methodology

### Phase 1: Reconnaissance of Defenses (Always First — Both Modes)
1. Identify installed security tools: AV, EDR, SIEM agents, auditd, syslog
2. Check logging configuration and coverage gaps
3. Map detection capabilities to planned actions
4. Identify blind spots and safe operating windows
5. Check tamper protection (references/tamper_protection.md)
6. Output `defense_controls.json` with complete coverage map

**Evidence-only mode stops here** — document gaps in `findings.json` and exit.

### Phase 2: Log Manipulation (T1070) — Evasion Mode Only
Before performing sensitive actions, reduce logging:
1. Identify active log sources (references/log_clearing_linux.md or references/log_clearing_windows.md)
2. Selectively disable or redirect logs for your activity window
3. After actions: clean specific log entries related to your activity
4. Restore logging to original state
5. Log every change to `cleanup_log.json` with reversal commands

**Key principle:** Selective editing > full wipe (full wipe is itself an indicator)

### Phase 3: Payload Preparation (T1027, T1140) — Evasion Mode Only
Before transferring tools to target:
1. Obfuscate payloads (references/payload_obfuscation.md)
2. Test against target's AV if possible (staging environment)
3. Use encoded/encrypted transfer (base64, XOR, AES)
4. Timestomp delivered files immediately (references/timestomping.md)

### Phase 4: Execution Evasion (T1055, T1218) — Evasion Mode Only
When executing on target:
1. Use process injection to live in legitimate processes (references/process_injection.md)
2. Use LOLBins for execution when possible (references/av_edr_bypass.md)
3. Avoid writing to disk — fileless execution preferred
4. If AV/EDR blocks: use bypass techniques (references/av_edr_bypass.md)

### Phase 5: Network Evasion (T1572, T1071) — Evasion Mode Only
For C2 and data transfer:
1. Use encrypted channels (HTTPS, mTLS, WireGuard)
2. Blend with normal traffic (port 443, legitimate-looking domains)
3. If firewall blocks standard ports: DNS/ICMP tunneling (references/network_evasion_techniques.md)
4. Implement jitter and randomized callbacks

### Phase 6: Artifact Cleanup (T1070.004) — Evasion Mode Only
After completing objectives:
1. Follow full cleanup checklist (references/artifact_cleanup.md)
2. Remove all dropped tools, payloads, webshells
3. Clear command history on all accessed systems
4. Remove persistence mechanisms (if engagement complete)
5. Clean log entries of your specific activity
6. Verify cleanup — second pass to confirm indicators are gone
7. Finalize `cleanup_log.json` with every change and its reversal

## OPSEC Ratings Per Technique

| Technique | OPSEC | Detection Risk |
|-----------|-------|----------------|
| Defense recon (enumerate controls) | 🟢 Quiet | Normal admin commands, minimal logs |
| Timestomping | 🟢 Quiet | Changes file metadata only, hard to detect |
| LOLBin execution | 🟢 Quiet | Uses legitimate system binaries |
| Process argument spoofing | 🟢 Quiet | Hides real arguments from logging |
| Log selective editing | 🟡 Moderate | Gap detection possible by SIEM correlation |
| Payload obfuscation | 🟡 Moderate | May trigger heuristic AV scanning |
| AMSI bypass | 🟡 Moderate | Some bypasses are signatured by now |
| Process injection | 🟡 Moderate | Modern EDR detects common injection patterns |
| Full log wipe | 🔴 Loud | Event 1102 (Security log cleared) is a strong indicator |
| Disabling AV/EDR | 🔴 Loud | Tamper protection alerts, service stop events |
| Kernel-level evasion | 🔴 Loud | Driver loading events, crash risk |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| AMSI bypass | Bypass signatured | Use reflection-based bypass, or obfuscate the bypass string itself |
| Process injection | EDR blocks injection | Try different technique: early bird, process hollowing, thread hijack |
| LOLBin blocked | AppLocker/WDAC blocks | Try different LOLBin (mshta → rundll32 → regsvr32), or find bypass DLL |
| Log manipulation | Tamper protection on | Focus on selective editing of accessible logs, avoid protected log sources |
| Payload blocked by AV | Signature match | Re-obfuscate: different encoder, custom XOR, compile from source |
| DNS tunnel blocked | DNS monitoring active | Switch to HTTPS beacon, use legitimate cloud services for C2 |

## Technique Chaining Playbooks

### Stealthy Post-Exploitation Setup
```
1. Enumerate defenses 🟢 (AV, EDR, SIEM, logging config)
2. Identify blind spots 🟢 (which logs are collected, retention)
3. Selectively reduce logging 🟡 (disable specific audit policies)
4. Timestomp any dropped files 🟢 (match surrounding files)
5. Execute tools via LOLBins 🟢 (no binary upload needed)
   └── LOLBins blocked? → Process injection into legitimate process 🟡
6. Post-action: clean specific log entries 🟡
7. Restore logging to original state 🟡
```

### AV/EDR Bypass Chain
```
1. Identify AV/EDR product 🟢 (tasklist, registry, WMI)
2. Test AMSI bypass 🟡 (for PowerShell execution)
3. Obfuscate payload 🟡 (custom encoding, no known signatures)
4. LOLBin delivery 🟢 (certutil, bitsadmin, or mshta)
5. Fileless execution 🟡 (in-memory only, no disk write)
   └── Still blocked? → Process injection into trusted process 🟡
```

## Examples
See [examples/amsi-bypass.md](examples/amsi-bypass.md) for AMSI bypass techniques and output.
See [examples/log-manipulation.md](examples/log-manipulation.md) for selective log editing.
See [examples/lolbin-execution.md](examples/lolbin-execution.md) for LOLBin payload delivery.

---

## Deep Dives
Load references on-demand when encountering specific scenarios:
1. Log clearing (Linux): `references/log_clearing_linux.md`
2. Log clearing (Windows): `references/log_clearing_windows.md`
3. Timestomping: `references/timestomping.md`
4. Process injection: `references/process_injection.md`
5. AV/EDR bypass: `references/av_edr_bypass.md`
6. Artifact cleanup: `references/artifact_cleanup.md`
7. Payload obfuscation: `references/payload_obfuscation.md`
8. Network evasion: `references/network_evasion_techniques.md`
9. Logging gaps (assessment): `references/logging_gaps.md`
10. EDR/AV status (assessment): `references/edr_av_status.md`
11. Tamper protection: `references/tamper_protection.md`
12. Explicit-only actions: `references/explicit_only_actions.md`

## Evidence Collection
1. `defense_controls.json` — security tools inventory and coverage map
2. `cleanup_log.json` — every change made and its reversal command
3. `evasion_techniques.json` — techniques used and results
4. `indicators_cleared.json` — what was cleaned and verification status
5. `evidence.json` — raw command outputs and supporting data
6. `findings.json` — evasion risks, gaps, and remediation guidance

## Success Criteria
- If evidence-only: security controls inventoried, logging gaps documented, risks assessed
- If active evasion: actions performed without triggering alerts
- All artifacts cleaned (verify with second pass)
- Cleanup log complete with reversal steps for every change
- No lasting impact on target system stability
