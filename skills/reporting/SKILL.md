# Reporting Skill

## Overview
Generate a clear, actionable report with evidence and remediation.

## Methodology

### 1. Summarize Findings
- Prioritize by severity
- Include reproducible evidence

### 2. Remediation Guidance
- Provide concise, actionable fixes

### 3. Executive Summary
- Business risk and impact

## Reporting Automation
- Use `scripts/assemble_report.py` to auto-populate a report from `findings.json` and evidence files.
- Template (markdown): `assets/report-template.md`
- Template (json): `assets/report-template.json`
- The script writes `report.md` and appends a `generated_report` section into `report.json`.

## Evidence Bundling
- Use `scripts/merge_bundles.py` to combine multiple service evidence bundles into a single reporting bundle.

## Findings Normalization
- Use `scripts/normalize_findings.py` to normalize findings from multiple sources before reporting.
- Use `scripts/summarize_findings.py` to generate severity/category summaries.

## Bundle Validation
- Use `scripts/validate_bundle.py` to validate evidence bundles before report generation.

## Report Readiness
- Use `scripts/check_report_readiness.py` to ensure `report.json` and `report.md` exist.

## Schema Checks
- Use `scripts/check_schema.py` to verify normalized findings contain required fields.
- Use `scripts/check_evidence_manifest.py` to verify bundle summaries match evidence keys.

## Report Gate
- Use `scripts/gate_report.py` to gate report generation based on readiness and validation checks.
- Use `scripts/summary_rollup.py` to roll up summaries across services.

## Schema Outputs
- Use `scripts/emit_schema.py` to emit the normalized findings schema.
- Use `scripts/emit_bundle_schema.py` to emit the evidence bundle schema.

## Artifact Collection
- Use `scripts/collect_artifacts.py` to collect report artifacts into an export directory.

## Export Packaging
- Use `scripts/hash_artifacts.py` to generate SHA256 checksums for exported artifacts.
- Use `scripts/package_export.py` to package the export directory into a tar.gz archive.
- Use `scripts/verify_checksums.py` to verify checksums before distribution.
- Use `scripts/write_manifest.py` and `scripts/validate_manifest.py` for export integrity validation.

## Export Audit
- Use `scripts/audit_log.py` to append audit log entries for export actions.
- Use `scripts/write_export_metadata.py` to capture export metadata.

## Deep Dives
Load references when needed:
1. Report structure: `references/report_structure.md`
2. Findings normalization: `references/normalization.md`

## Evidence Collection
1. `report.md` and `report.json` outputs.
2. `findings.json` normalized with severity and categories.
3. `evidence.json` with evidence bundle references.

## Evidence Consolidation
1. Use `merge_bundles.py` to combine service evidence into a reporting bundle.
2. Use `normalize_findings.py` to prepare findings for report generation.

## Success Criteria
- Clear report produced with remediation steps
