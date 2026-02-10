#!/usr/bin/env python3
"""Parse ufw or firewall-cmd output into JSON."""

import argparse
import json
from typing import Dict


def parse_ufw(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
        elif line.lower().startswith("status"):
            data["Status"] = line.split(":", 1)[-1].strip()
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to firewall output")
    parser.add_argument("--out", required=True, help="Output JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    output = parse_ufw(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
