# Forensics Skill

## Overview
Host and artifact triage for post-exploitation validation and incident-style evidence review. Focus on preservation and reporting, not destructive actions.

## Scope Rules
1. Analyze only artifacts collected within authorized scope.
2. Preserve timestamps and avoid modifying evidence.
3. Prefer read-only mounts and copies.

## Methodology

### 1. Evidence Inventory
- Record sources, hashes, and collection context.
- Identify disk images, memory dumps, and key files.

### 2. Disk Triage
- Parse file systems, recover deleted files, and identify sensitive artifacts.
- Extract metadata for reporting.

### 3. Memory Triage
- Identify processes, network connections, and injected artifacts.
- Extract credentials only when authorized.

### 4. Artifact Extraction
- Carve archives, logs, and config files.
- Prioritize authentication material and secrets.

## Evidence Collection
1. `artifact_inventory.json` with source list and hashes.
2. `file_metadata.json` with notable files and timestamps.
3. `memory_findings.json` if memory analysis is performed.
4. `evidence.json` with raw tool outputs.
5. `findings.json` with risks and sensitive data exposure.
6. `terminal_sessions/*.log` when interactive sessions are opened (for audit trail).

## Evidence Consolidation
Summarize triage outputs into `artifact_inventory.json` and `file_metadata.json`.

## Success Criteria
- Evidence sources hashed and tracked.
- High-value artifacts identified and documented.
- Findings include clear provenance and evidence links.

## Tool References
- ../toolcards/autopsy.md
- ../toolcards/sleuthkit.md
- ../toolcards/volatility.md
- ../toolcards/binwalk.md
- ../toolcards/foremost.md
- ../toolcards/scalpel.md
- ../toolcards/photorec.md
- ../toolcards/testdisk.md
- ../toolcards/exiftool.md
