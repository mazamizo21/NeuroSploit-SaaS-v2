#!/usr/bin/env python3
"""Parse MySQL SHOW command output into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_table(text: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    lines = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]
    if not lines:
        return rows
    if lines[0].startswith("+") and lines[1].startswith("|"):
        headers = [h.strip() for h in lines[1].strip("|").split("|")]
        for line in lines[3:]:
            if line.startswith("+"):
                continue
            values = [v.strip() for v in line.strip("|").split("|")]
            if len(values) != len(headers):
                continue
            rows.append(dict(zip(headers, values)))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to MySQL output")
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
