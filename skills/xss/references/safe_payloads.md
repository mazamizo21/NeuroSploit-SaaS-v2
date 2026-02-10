# Safe XSS Payloads

## Goals
- Use minimal, non-destructive payloads for proof of execution.
- Avoid data exfiltration or session theft without explicit authorization.

## Safe Patterns
- Basic proof: `<svg onload=alert(1)>`
- DOM-based checks with harmless markers

## Avoid
- Cookie or token exfiltration
- Keylogging or phishing content

## Evidence Checklist
- Payload used (redacted if needed)
- Screenshot or response evidence

