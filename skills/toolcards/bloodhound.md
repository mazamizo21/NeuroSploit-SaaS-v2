# bloodhound Toolcard

## Overview
- Summary: BloodHound Community Edition (CE) is a web application that uses graph theory to analyze Active Directory relationships and attack paths for both red and blue teams.

## Advanced Techniques
- Use CE-compatible ingestors (SharpHound, bloodhound-ce-python, azurehound) and keep collection methods scoped to the engagement.
- Separate collection from analysis and load only the approved datasets.

## Safe Defaults
- Treat collected AD data as sensitive and restrict access.
- Limit collection to approved OUs, domains, and time windows.

## Evidence Outputs
- outputs: bloodhound collection JSON/ZIP, graph exports (as applicable)

## References
- https://www.kali.org/tools/bloodhound/
- https://www.kali.org/blog/kali-linux-2025-2-release/
