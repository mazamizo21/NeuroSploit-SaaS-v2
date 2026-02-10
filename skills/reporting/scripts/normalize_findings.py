#!/usr/bin/env python3
"""Normalize findings from multiple sources into a common schema."""

import argparse
import json
from typing import Any, Dict, List

DEFAULT_CATEGORY = "general"


def to_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": raw.get("title") or raw.get("name") or "Finding",
        "severity": raw.get("severity", "medium"),
        "description": raw.get("description") or raw.get("details") or "",
        "evidence": raw.get("evidence") or raw.get("output") or "",
        "category": raw.get("category", DEFAULT_CATEGORY),
        "target": raw.get("target"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", nargs="+", required=True, help="Input JSON files")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    normalized: List[Dict[str, Any]] = []
    for path in args.inputs:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        findings = []
        if isinstance(data, dict):
            findings = data.get("findings", [])
        elif isinstance(data, list):
            findings = data

        for item in findings:
            if isinstance(item, dict):
                normalized.append(to_finding(item))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"findings": normalized, "count": len(normalized)}, f, indent=2)


if __name__ == "__main__":
    main()
