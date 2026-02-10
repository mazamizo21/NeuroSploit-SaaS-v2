# Windows Defense Evasion Playbook (Authorized Only)

## Intent
This playbook documents *detection and validation* of defensive controls and logging, not bypass.

## Safe Checks
1. Validate Defender/EDR status and configuration with read-only queries.
2. Confirm logging coverage for security events and PowerShell script block logging.
3. Review firewall profiles and endpoint isolation settings.

## Evidence Capture
- Security control status summary (Defender, EDR, firewall).
- Logging configuration evidence (policy presence, enabled/disabled).

## Explicit-Only Actions
- Do not attempt to disable controls, tamper with logs, or bypass detections unless explicitly authorized.
