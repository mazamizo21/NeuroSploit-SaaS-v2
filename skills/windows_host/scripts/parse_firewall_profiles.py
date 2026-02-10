#!/usr/bin/env python3
"""Parse PowerShell Get-NetFirewallProfile output into JSON."""

import argparse
import json
from typing import Dict


def parse_profiles(text: str) -> Dict[str, Dict[str, str]]:
    profiles: Dict[str, Dict[str, str]] = {}
    current = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Name") and ":" in line:
            _, value = line.split(":", 1)
            current = value.strip()
            profiles[current] = {}
            continue
        if current and ":" in line:
            key, value = line.split(":", 1)
            profiles[current][key.strip()] = value.strip()
    return profiles


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to firewall profile output")
    parser.add_argument("--out", required=True, help="Output JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    output = parse_profiles(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
