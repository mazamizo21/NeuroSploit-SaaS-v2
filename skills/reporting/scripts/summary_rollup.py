#!/usr/bin/env python3
"""Roll up multiple findings summaries into a single report summary."""

import argparse
import json
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def merge_counts(base: Dict[str, int], add: Dict[str, int]) -> Dict[str, int]:
    for key, value in add.items():
        base[key] = base.get(key, 0) + int(value)
    return base


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", nargs="+", required=True, help="Summary JSON files")
    parser.add_argument("--out", required=True, help="Output rollup JSON")
    args = parser.parse_args()

    total = 0
    severity_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}

    for path in args.inputs:
        data = load_json(path)
        total += int(data.get("total", 0))
        severity_counts = merge_counts(severity_counts, data.get("by_severity", {}) or {})
        category_counts = merge_counts(category_counts, data.get("by_category", {}) or {})

    output = {
        "total": total,
        "by_severity": severity_counts,
        "by_category": category_counts,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
