#!/usr/bin/env python3
"""Parse auditctl -s output into JSON."""

import argparse
import json
from typing import Dict


def parse_auditctl(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if " " in line:
            key, value = line.split(" ", 1)
            data[key.strip()] = value.strip()
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to auditctl -s output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    output = parse_auditctl(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
