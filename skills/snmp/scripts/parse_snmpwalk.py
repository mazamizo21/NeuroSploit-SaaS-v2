#!/usr/bin/env python3
"""Parse snmpwalk output into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_walk(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        left, right = line.split("=", 1)
        oid = left.strip()
        value = right.strip()
        rows.append({"oid": oid, "value": value})
    return rows


def summarize(rows: List[Dict[str, str]]) -> Dict[str, object]:
    return {
        "count": len(rows),
        "sample": rows[:20],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to snmpwalk output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    rows = parse_walk(raw)
    output = {"rows": rows, "summary": summarize(rows)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
