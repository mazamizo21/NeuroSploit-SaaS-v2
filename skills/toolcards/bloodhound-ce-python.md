# bloodhound-ce-python Toolcard

## Overview
- Summary: bloodhound-ce-python is the Python ingestor for BloodHound Community Edition, built on Impacket, and is not compatible with legacy BloodHound.

## Advanced Techniques
- Use only CE-compatible ingestors and keep collection scope minimal.
- Separate collection from analysis and load only approved datasets.

## Safe Defaults
- Treat collected AD data as sensitive and restrict access.
- Limit collection to approved OUs, domains, and time windows.

## Evidence Outputs
- outputs: bloodhound collection JSON/ZIP

## References
- https://www.kali.org/tools/bloodhound-ce-python/
