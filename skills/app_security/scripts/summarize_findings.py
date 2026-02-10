#!/usr/bin/env python3
"""Summarize app security findings into counts by severity and category."""

import argparse
import json
from typing import Dict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Findings JSON")
    parser.add_argument("--out", required=True, help="Summary JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    findings = data.get("findings", []) if isinstance(data, dict) else []
    severity_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for finding in findings:
        severity = finding.get("severity", "unknown")
        category = finding.get("category", "app_security")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category_counts[category] = category_counts.get(category, 0) + 1

    output = {
        "total": len(findings),
        "by_severity": severity_counts,
        "by_category": category_counts,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
