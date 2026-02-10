#!/usr/bin/env python3
"""Parse dig output into structured JSON records."""

import argparse
import json
from typing import Dict, List


def parse_records(text: str) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        parts = [p for p in line.split() if p]
        if len(parts) < 5:
            continue
        name, ttl, rrclass, rrtype = parts[0:4]
        value = " ".join(parts[4:])
        records.append(
            {
                "name": name,
                "ttl": ttl,
                "class": rrclass,
                "type": rrtype,
                "value": value,
            }
        )
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to dig output file")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    records = parse_records(raw)
    output = {
        "count": len(records),
        "records": records,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

