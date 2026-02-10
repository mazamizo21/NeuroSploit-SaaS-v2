# Windows Persistence Playbook (Authorized Only)

## Intent
Validate persistence exposure and detection coverage without deploying persistence.

## Safe Checks
1. Enumerate startup locations and scheduled tasks.
2. Review services set to auto-start and registry run keys.
3. Capture autorun entries with timestamps and publishers.

## Evidence Capture
- Startup entries, scheduled tasks, and service configurations.
- Any unsigned or unexpected autoruns.

## Explicit-Only Actions
- Do not install persistence mechanisms without explicit authorization.
