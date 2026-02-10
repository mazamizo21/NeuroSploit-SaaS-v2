#!/usr/bin/env python3
"""Normalize Linux findings into a common schema."""

import argparse
import json
from typing import Any, Dict, List


def to_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": raw.get("title") or raw.get("name") or "Linux finding",
        "severity": raw.get("severity", "medium"),
        "description": raw.get("description") or raw.get("details") or "",
        "evidence": raw.get("evidence") or raw.get("output") or "",
        "category": raw.get("category", "linux_host"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input findings JSON")
    parser.add_argument("--out", required=True, help="Output normalized JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    findings_raw = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(findings_raw, list):
        findings_raw = []

    normalized = [to_finding(item) for item in findings_raw if isinstance(item, dict)]

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"findings": normalized, "count": len(normalized)}, f, indent=2)


if __name__ == "__main__":
    main()
