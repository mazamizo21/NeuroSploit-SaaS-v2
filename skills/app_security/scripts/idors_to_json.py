#!/usr/bin/env python3
"""Convert a simple IDOR test log into JSON evidence."""

import argparse
import json
from typing import List, Dict


def parse_lines(text: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            entries.append({"raw": line})
            continue
        entries.append({
            "endpoint": parts[0].strip(),
            "status": parts[1].strip(),
            "notes": parts[2].strip(),
        })
    return entries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to IDOR log")
    parser.add_argument("--out", required=True, help="Output JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    entries = parse_lines(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"idors": entries, "count": len(entries)}, f, indent=2)


if __name__ == "__main__":
    main()
