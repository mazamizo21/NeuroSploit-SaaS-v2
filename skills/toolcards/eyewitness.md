# eyewitness Toolcard

## Overview
- Summary: EyeWitness is designed to take screenshots of websites and provide server header information, with optional default-credential checks.

## Advanced Techniques
- Use curated target lists to keep captures scoped.
- Correlate screenshots with findings for visual evidence.

## Safe Defaults
- Require explicit authorization for any credential checks (external_exploit=explicit_only).
- Rate limits: conservative concurrency on external targets.

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/RedSiege/EyeWitness
- https://offsec.tools/tool/eyewitness
