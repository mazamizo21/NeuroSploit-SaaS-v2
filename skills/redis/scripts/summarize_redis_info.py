#!/usr/bin/env python3
"""Summarize redis-cli INFO output into structured JSON."""

import argparse
import json
from typing import Dict


def parse_info(text: str) -> Dict[str, Dict[str, str]]:
    sections: Dict[str, Dict[str, str]] = {}
    current = "default"
    sections[current] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            current = line.lstrip("#").strip().lower().replace(" ", "_")
            sections[current] = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            sections[current][key] = value
    return sections


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to redis INFO output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    sections = parse_info(raw)
    output = {"sections": sections}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
