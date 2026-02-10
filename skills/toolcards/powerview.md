# powerview Toolcard

## Overview
- Summary: PowerView is a PowerShell tool from PowerSploit for gaining network situational awareness in Windows domains by enumerating AD objects and relationships.

## Advanced Techniques
- Use scoped queries to limit enumeration to approved domains, OUs, or hosts.
- Favor read-only enumeration and capture only required attributes.

## Safe Defaults
- Do not run on external targets without explicit authorization.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: ldap_objects.json, findings.json (as applicable)

## References
- https://powersploit.readthedocs.io/en/latest/Recon/
- https://powersploit.readthedocs.io/en/stable/Recon/README/
