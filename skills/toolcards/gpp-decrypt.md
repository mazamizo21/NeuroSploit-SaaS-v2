# gpp-decrypt Toolcard

## Overview
- Summary: gpp-decrypt decrypts Group Policy Preferences (GPP) password data.

## Advanced Techniques
- Use only on explicitly scoped policy files.
- Treat recovered credentials as high sensitivity and rotate promptly.

## Safe Defaults
- Require explicit authorization for external targets (external_exploit=explicit_only).
- Do not reuse recovered credentials outside approved scope.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/t0thkr1s/gpp-decrypt
