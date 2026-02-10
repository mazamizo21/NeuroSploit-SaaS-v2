#!/usr/bin/env python3
"""Validate evidence bundle summary entries align with evidence keys."""

import argparse
import json
from typing import Dict, Any, List


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Bundle JSON file")
    parser.add_argument("--out", required=True, help="Manifest validation JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data: Dict[str, Any] = json.load(f)

    summary = data.get("summary", [])
    evidence = data.get("evidence", {})

    errors: List[str] = []
    for entry in summary:
        if not isinstance(entry, dict):
            errors.append("Summary entry is not a dict")
            continue
        file_name = entry.get("file")
        if file_name and file_name not in evidence:
            errors.append(f"Summary file missing in evidence: {file_name}")

    output = {
        "ok": len(errors) == 0,
        "errors": errors,
        "summary_count": len(summary),
        "evidence_count": len(evidence) if isinstance(evidence, dict) else 0,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
