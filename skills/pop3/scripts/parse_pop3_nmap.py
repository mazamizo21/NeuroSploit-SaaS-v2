#!/usr/bin/env python3
"""Parse Nmap POP3 script output into structured JSON."""

import argparse
import json
from typing import Dict, List, Any


def parse_nmap(text: str) -> Dict[str, Any]:
    capabilities: List[str] = []
    auth_mechanisms: List[str] = []
    stls = False
    in_section = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "pop3-capabilities" in line:
            in_section = True
            continue
        if not line.startswith("|") and not line.startswith("|_"):
            continue
        cleaned = line.lstrip("|_").strip()
        if not cleaned:
            continue
        if in_section:
            upper = cleaned.upper()
            capabilities.append(cleaned)
            if upper.startswith("SASL "):
                parts = cleaned.split(" ", 1)[1].split()
                auth_mechanisms.extend(parts)
            if upper == "STLS":
                stls = True

    return {
        "capabilities": capabilities,
        "auth_mechanisms": sorted(set(auth_mechanisms)),
        "stls": stls,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to Nmap output file (-oN)")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_nmap(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
