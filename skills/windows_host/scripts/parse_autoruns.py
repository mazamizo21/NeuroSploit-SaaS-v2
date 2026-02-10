#!/usr/bin/env python3
"""Parse autoruns CSV output into JSON."""

import argparse
import csv
import json
from typing import List, Dict


def parse_csv(path: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            entries.append({k: v for k, v in row.items()})
    return entries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to autoruns CSV")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    entries = parse_csv(args.input)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"autoruns": entries, "count": len(entries)}, f, indent=2)


if __name__ == "__main__":
    main()
