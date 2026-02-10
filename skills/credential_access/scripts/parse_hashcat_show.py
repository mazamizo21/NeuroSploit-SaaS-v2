#!/usr/bin/env python3
"""Parse hashcat --show output into structured JSON evidence."""

import argparse
import json
from typing import Dict, List


def redact_plaintext(value: str) -> str:
    value = value.strip()
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}***{value[-2:]}"


def parse_show(text: str) -> Dict[str, object]:
    entries: List[Dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        hash_value, plain = line.split(":", 1)
        entries.append(
            {
                "hash": hash_value,
                "plaintext_redacted": redact_plaintext(plain),
                "plaintext_length": str(len(plain)),
            }
        )
    return {
        "count": len(entries),
        "samples": entries[:25],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to hashcat --show output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_show(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
