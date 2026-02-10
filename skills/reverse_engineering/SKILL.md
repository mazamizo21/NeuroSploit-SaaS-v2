# Reverse Engineering Skill

## Overview
Static and limited dynamic analysis to understand binaries and extract indicators. Focus on safe, controlled analysis.

## Scope Rules
1. Analyze only artifacts collected in scope.
2. Use isolated environments for dynamic analysis.
3. Do not execute unknown binaries on production hosts.

## Methodology

### 1. Initial Triage
- Identify file type, hashes, and embedded strings.
- Capture imports, exports, and obvious indicators.

### 2. Static Analysis
- Disassemble and inspect control flow.
- Map key functions and suspicious routines.

### 3. Decompilation
- Use decompilers to recover higher-level logic.
- Record evidence of credential handling or network targets.

### 4. Controlled Dynamic Analysis (Optional)
- Execute in an isolated sandbox if required and authorized.
- Capture network behavior and artifacts.

## Evidence Collection
1. `binary_metadata.json` with hashes and file info.
2. `strings.json` with notable strings/IOCs.
3. `iocs.json` with indicators (domains, IPs, paths).
4. `evidence.json` with tool outputs.
5. `findings.json` with analyst notes and risks.

## Evidence Consolidation
Summarize triage and static analysis results into `binary_metadata.json` and `iocs.json`.

## Success Criteria
- Binary characteristics and indicators documented.
- Suspicious behaviors summarized with evidence.

## Tool References
- ../toolcards/ghidra.md
- ../toolcards/radare2.md
- ../toolcards/objdump.md
- ../toolcards/strings.md
- ../toolcards/python3.md
