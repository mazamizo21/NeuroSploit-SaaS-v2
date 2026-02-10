#!/usr/bin/env python3
"""Parse Nmap IMAP script output into structured JSON."""

import argparse
import json
from typing import Dict, List, Any


def parse_nmap(text: str) -> Dict[str, Any]:
    capabilities: List[str] = []
    auth_mechanisms: List[str] = []
    starttls = False
    login_disabled = False
    in_section = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "imap-capabilities" in line:
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
            if "AUTH=" in upper:
                parts = [p for p in cleaned.split() if p.upper().startswith("AUTH=")]
                for part in parts:
                    auth_mechanisms.append(part.split("=", 1)[1])
            if "STARTTLS" in upper:
                starttls = True
            if "LOGINDISABLED" in upper:
                login_disabled = True

    return {
        "capabilities": capabilities,
        "auth_mechanisms": sorted(set(auth_mechanisms)),
        "starttls": starttls,
        "login_disabled": login_disabled,
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
