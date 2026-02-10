#!/usr/bin/env python3
"""Parse sudo -l output into JSON."""

import argparse
import json
from typing import List


def parse_sudo(text: str) -> List[str]:
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        lines.append(line)
    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to sudo -l output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    entries = parse_sudo(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"sudo_entries": entries, "count": len(entries)}, f, indent=2)


if __name__ == "__main__":
    main()
