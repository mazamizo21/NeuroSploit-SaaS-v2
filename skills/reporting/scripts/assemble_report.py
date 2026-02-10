#!/usr/bin/env python3
"""Assemble a markdown report from structured evidence outputs."""

import argparse
import json
import os
from datetime import datetime
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def _slug(value: str) -> str:
    return (value or "").strip()


def _collect_evidence_index(evidence_dir: str) -> List[Dict[str, Any]]:
    if not evidence_dir or not os.path.isdir(evidence_dir):
        return []
    entries = []
    for name in sorted(os.listdir(evidence_dir)):
        path = os.path.join(evidence_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        entries.append({"file": name, "size_bytes": size})
    return entries


def _normalize_findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        findings = data.get("findings")
        if isinstance(findings, list):
            return findings
    if isinstance(data, list):
        return data
    return []


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _build_findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No findings recorded."
    lines = ["| Severity | Title | Target |", "| --- | --- | --- |"]
    for finding in findings:
        severity = _slug(finding.get("severity", "info")).capitalize()
        title = _slug(finding.get("title", "Finding"))
        target = _slug(finding.get("target", "-"))
        lines.append(f"| {severity} | {title} | {target} |")
    return "\n".join(lines)


def _build_findings_detail(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "No detailed findings available."
    blocks = []
    for idx, finding in enumerate(findings, start=1):
        title = _slug(finding.get("title", f"Finding {idx}"))
        severity = _slug(finding.get("severity", "info")).capitalize()
        target = _slug(finding.get("target", "-"))
        description = _slug(finding.get("description", ""))
        evidence = _slug(finding.get("evidence", ""))
        remediation = _slug(finding.get("remediation", ""))
        references = finding.get("references") or []
        if isinstance(references, list):
            refs_text = "\n".join(f"- {r}" for r in references if r)
        else:
            refs_text = _slug(references)

        block = [f"### {title}", f"- Severity: {severity}", f"- Target: {target}"]
        if description:
            block.append(f"- Description: {description}")
        if evidence:
            block.append(f"- Evidence: {evidence}")
        if remediation:
            block.append(f"- Remediation: {remediation}")
        if refs_text:
            block.append("- References:\n" + refs_text)
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


def _build_evidence_index(entries: List[Dict[str, Any]]) -> str:
    if not entries:
        return "No evidence files recorded."
    lines = []
    for entry in entries:
        lines.append(f"- {entry.get('file')} ({entry.get('size_bytes', 0)} bytes)")
    return "\n".join(lines)


def _render_template(template: str, values: Dict[str, str]) -> str:
    content = template
    for key, value in values.items():
        content = content.replace(f"{{{{{key}}}}}", value)
    return content


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble report artifacts from evidence outputs")
    parser.add_argument("--input-dir", default=os.getenv("OUTPUT_DIR", "."))
    parser.add_argument("--output-md", default=None)
    parser.add_argument("--output-json", default=None)
    parser.add_argument("--template", default=None)
    args = parser.parse_args()

    input_dir = args.input_dir
    findings_path = os.path.join(input_dir, "findings.json")
    report_path = os.path.join(input_dir, "report.json")

    findings_data = _load_json(findings_path) or {}
    report_data = _load_json(report_path) or {}

    findings = _normalize_findings(findings_data) or _normalize_findings(report_data)
    counts = _severity_counts(findings)

    target = findings_data.get("target") or report_data.get("target") or "-"
    objective = findings_data.get("objective") or report_data.get("objective") or "-"
    timestamp = datetime.utcnow().isoformat() + "Z"

    exec_summary = (
        f"Findings: {sum(counts.values())} total "
        f"(Critical {counts['critical']}, High {counts['high']}, "
        f"Medium {counts['medium']}, Low {counts['low']}, Info {counts['info']})."
    )

    evidence_entries = _collect_evidence_index(os.path.join(input_dir, "evidence"))

    findings_table = _build_findings_table(findings)
    findings_detail = _build_findings_detail(findings)
    evidence_index = _build_evidence_index(evidence_entries)

    template_path = args.template or os.path.join(os.path.dirname(__file__), "..", "assets", "report-template.md")
    template = None
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as handle:
            template = handle.read()

    values = {
        "REPORT_TITLE": "TazoSploit Security Report",
        "TARGET": str(target),
        "OBJECTIVE": str(objective),
        "TIMESTAMP": timestamp,
        "EXEC_SUMMARY": exec_summary,
        "FINDINGS_TABLE": findings_table,
        "FINDINGS_DETAIL": findings_detail,
        "EVIDENCE_INDEX": evidence_index,
        "APPENDIX": "Appendix reserved for additional data.",
    }

    rendered = _render_template(template, values) if template else "\n".join([
        f"# {values['REPORT_TITLE']}",
        "",
        "## Engagement Summary",
        f"- Target: {values['TARGET']}",
        f"- Objective: {values['OBJECTIVE']}",
        f"- Generated: {values['TIMESTAMP']}",
        "",
        "## Executive Summary",
        values["EXEC_SUMMARY"],
        "",
        "## Findings Overview",
        values["FINDINGS_TABLE"],
        "",
        "## Detailed Findings",
        values["FINDINGS_DETAIL"],
        "",
        "## Evidence Index",
        values["EVIDENCE_INDEX"],
        "",
        "## Appendix",
        values["APPENDIX"],
    ])

    output_md = args.output_md or os.path.join(input_dir, "report.md")
    with open(output_md, "w", encoding="utf-8") as handle:
        handle.write(rendered)

    generated_report = {
        "report_title": values["REPORT_TITLE"],
        "target": target,
        "objective": objective,
        "generated_at": timestamp,
        "summary": exec_summary,
        "findings": findings,
        "evidence_index": evidence_entries,
    }

    output_json = args.output_json or report_path
    if report_data:
        report_data["generated_report"] = generated_report
        with open(output_json, "w", encoding="utf-8") as handle:
            json.dump(report_data, handle, indent=2)
    else:
        with open(output_json, "w", encoding="utf-8") as handle:
            json.dump(generated_report, handle, indent=2)

    print(f"[+] Wrote report markdown to {output_md}")
    print(f"[+] Wrote report JSON to {output_json}")


if __name__ == "__main__":
    main()
