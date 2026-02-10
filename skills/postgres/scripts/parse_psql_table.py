#!/usr/bin/env python3
"""Parse psql table output into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_table(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    lines = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]
    if not lines:
        return rows

    header_line = None
    separator_index = None
    for idx, line in enumerate(lines):
        if line.startswith("-") and header_line is not None:
            separator_index = idx
            break
        if "|" in line and header_line is None:
            header_line = line
            continue

    if header_line is None or separator_index is None:
        return rows

    headers = [h.strip() for h in header_line.split("|")]
    for line in lines[separator_index + 1 :]:
        if line.startswith("("):
            break
        if "|" not in line:
            continue
        values = [v.strip() for v in line.split("|")]
        if len(values) != len(headers):
            continue
        rows.append(dict(zip(headers, values)))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to psql output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    rows = parse_table(raw)
    output = {"rows": rows, "count": len(rows)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
