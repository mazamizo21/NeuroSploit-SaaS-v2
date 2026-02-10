# Null Session and Guest Access

## Goal
Determine whether null sessions or guest access expose shares or metadata.

## Safe Checks
- `smbclient -L //target -N`
- Avoid listing files unless explicitly authorized.

## What to Record
1. Share list visibility without credentials.
2. Guest access indications.
3. Access denied responses for sensitive shares.
4. Server OS and domain hints if exposed.

## Evidence Checklist
1. Raw `smbclient` output.
2. Parsed JSON summary of shares and access.
3. Error lines showing access restrictions.
