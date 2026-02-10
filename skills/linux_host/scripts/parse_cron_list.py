#!/usr/bin/env python3
"""Parse crontab -l output into JSON."""

import argparse
import json
from typing import List


def parse_cron(text: str) -> List[str]:
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line)
    return entries


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to crontab output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    entries = parse_cron(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"cron_entries": entries, "count": len(entries)}, f, indent=2)


if __name__ == "__main__":
    main()
