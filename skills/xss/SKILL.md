# Cross-Site Scripting (XSS) Skill

## Overview
Service-first methodology for validating XSS with safe, non-destructive payloads and clear evidence.

## Scope Rules
1. Only operate on explicitly in-scope applications and parameters.
2. External targets: exploitation beyond proof-of-execution requires explicit authorization (external_exploit=explicit_only).
3. Use non-destructive payloads only; do not exfiltrate data.
4. Stored XSS tests require explicit authorization and minimal impact.

## Methodology

### 1. Detection
- Identify reflected, stored, and DOM-based injection points.
- Confirm sink context and encoding requirements.

### 2. Safe Proof of Execution
- Use minimal payloads to prove execution.
- Capture response evidence and screenshots.

### 3. CSP and Mitigations
- Capture CSP headers and execution blockers.
- Note mitigations for remediation guidance.

### 4. Explicit-Only Advanced Actions
- Credential capture, session theft, or browser exploitation requires explicit authorization.

## Deep Dives
Load references when needed:
1. XSS types and sinks: `references/types_and_sinks.md`
2. Safe payloads: `references/safe_payloads.md`
3. Context and encoding: `references/context_encoding.md`
4. CSP validation: `references/csp_validation.md`
5. Explicit-only advanced actions: `references/explicit_only_advanced.md`

## Evidence Collection
1. `evidence.json` with parameter, context, and payload evidence (parse dalfox JSON if used).
2. `findings.json` with validated impact and redacted proof.

## Evidence Consolidation
Use `parse_dalfox_json.py` to convert dalfox JSON/JSONL output into `evidence.json`.

## Success Criteria
- XSS vulnerability confirmed with safe payloads.
- Context and mitigation factors documented.
- Evidence captured without data exfiltration.
