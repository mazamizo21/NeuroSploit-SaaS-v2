# Security Groups and NACLs

## Goals
- Identify overly permissive inbound rules and public exposure.
- Flag open management ports and unrestricted sources.

## Notes
- Record rule IDs, ports, and source CIDRs.
- Avoid changes to SGs/NACLs without explicit authorization.

## Evidence
- Summarize network posture in `cloud_network.json`.
- Document high-risk rules in `findings.json`.
