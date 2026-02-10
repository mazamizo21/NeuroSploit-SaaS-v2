#!/usr/bin/env python3
"""Convert nuclei JSONL output to a simplified findings JSON."""

import argparse
import json
from typing import List, Dict, Any


def parse_line(line: str) -> Dict[str, Any]:
    data = json.loads(line)
    info = data.get("info", {})
    return {
        "template_id": data.get("template-id"),
        "name": info.get("name"),
        "severity": info.get("severity"),
        "host": data.get("host"),
        "matched_at": data.get("matched-at"),
        "type": data.get("type"),
        "extracted_results": data.get("extracted-results"),
        "description": info.get("description"),
        "reference": info.get("reference"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to nuclei JSONL output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    findings: List[Dict[str, Any]] = []
    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(parse_line(line))
            except json.JSONDecodeError:
                continue

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"findings": findings, "count": len(findings)}, f, indent=2)


if __name__ == "__main__":
    main()
