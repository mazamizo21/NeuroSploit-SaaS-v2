# secretsdump.py Toolcard

## Overview
- Summary: secretsdump is an Impacket script for extracting credential material from Windows targets and is packaged in Kali as `impacket-secretsdump`.

## Advanced Techniques
- Use only when explicit authorization covers credential extraction.
- Limit collection to the minimum scope required for validation.

## Safe Defaults
- Avoid running on external targets without explicit authorization.
- Do not store extracted material outside approved evidence handling.

## Evidence Outputs
- outputs: creds.json, evidence.json (as applicable)

## References
- https://www.kali.org/tools/impacket/
