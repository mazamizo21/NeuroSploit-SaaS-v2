#!/usr/bin/env python3
"""Normalize persistence notes into a structured JSON inventory."""

import argparse
import json
from typing import List, Dict


def parse_lines(lines: List[str]) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        entry = {
            "category": parts[0] if len(parts) > 0 else "",
            "path": parts[1] if len(parts) > 1 else "",
            "details": parts[2] if len(parts) > 2 else "",
        }
        entries.append(entry)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize persistence notes into JSON inventory")
    parser.add_argument("--input", required=True, help="Path to notes file (category|path|details per line)")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        entries = parse_lines(f.readlines())

    payload = {"entries": entries, "count": len(entries)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


if __name__ == "__main__":
    main()
