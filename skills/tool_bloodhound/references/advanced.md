# Advanced Techniques

## Ingest Discipline
- Use the BloodHound CE ingest flow to upload SharpHound ZIP outputs; keep ingestion tied to the exact collection window for auditability.
- Separate collection from analysis so you can re-run queries without re-collecting.

## Path Analysis
- Start with shortest-path queries to high-value groups and verify edge data sources before moving to execution.
- Prioritize edges that map to the execution tooling available in your engagement (e.g., RDP/WinRM/SMB).

## Evidence
- Record the exact node/edge chain (with timestamps and collector name) for each validated path.
