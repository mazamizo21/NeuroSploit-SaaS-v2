# rubeus Toolcard

## Overview
- Summary: Rubeus is a C# toolset for interacting with Kerberos and testing authentication behaviors in Windows environments.

## Advanced Techniques
- Use only authorized accounts or keytabs for ticket validation.
- Record ticket lifetimes and policy behaviors for evidence.

## Safe Defaults
- Avoid ticket attacks or roasting without explicit authorization.
- Do not persist tickets beyond the engagement window.

## Evidence Outputs
- outputs: kerberos_tickets.json, evidence.json (as applicable)

## References
- https://www.kali.org/tools/rubeus/
