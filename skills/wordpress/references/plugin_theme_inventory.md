# Plugin and Theme Inventory

## Goals
- Identify plugins and themes safely.
- Note vulnerable or outdated components.

## Safe Checks
- `wpscan --enumerate vp,vt,tt --plugins-detection passive`
- Avoid aggressive enumeration on external targets.

## Evidence Checklist
- Plugin list with versions (if available)
- Theme name and version
- Vulnerability notes (no exploitation)

