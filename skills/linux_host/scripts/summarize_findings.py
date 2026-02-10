#!/usr/bin/env python3
"""Summarize normalized findings into counts by severity."""

import argparse
import json
from typing import Dict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Normalized findings JSON")
    parser.add_argument("--out", required=True, help="Summary JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    counts: Dict[str, int] = {}
    findings = data.get("findings", []) if isinstance(data, dict) else []
    for finding in findings:
        severity = finding.get("severity", "unknown")
        counts[severity] = counts.get(severity, 0) + 1

    output = {
        "total": len(findings),
        "by_severity": counts,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
