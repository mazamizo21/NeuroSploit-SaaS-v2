# Kerberos + ADCS Validation

## Kerberos Checks (Authorized)
- Confirm Kerberos is in use and identify KDCs.
- Note pre-auth configuration and delegation flags.
- Log findings without attempting ticket forging or persistence.

## ADCS Checks (Authorized)
- Identify ADCS presence and certificate templates.
- Flag templates with risky enrollment or client auth settings.
- Capture template names and permissions for reporting.

## Capture
- Summarize Kerberos configuration in `ad_summary.json`.
- Record template findings in `findings.json` with evidence links.
