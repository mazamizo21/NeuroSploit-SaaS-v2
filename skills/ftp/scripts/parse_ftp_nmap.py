#!/usr/bin/env python3
"""Parse Nmap FTP script output into structured JSON."""

import argparse
import json
from typing import Dict, Any, List


def parse_nmap(text: str) -> Dict[str, Any]:
    banner = ""
    anonymous = False
    anon_dirs: List[str] = []
    system = ""
    current_section = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "ftp-anon" in line:
            current_section = "anon"
            continue
        if "ftp-syst" in line or "ftp-banner" in line:
            current_section = "syst"
            continue
        if not line.startswith("|") and not line.startswith("|_"):
            continue
        cleaned = line.lstrip("|_").strip()
        if not cleaned:
            continue
        if current_section == "anon":
            if "Anonymous FTP login allowed" in cleaned:
                anonymous = True
            if cleaned.startswith("drwx") or cleaned.startswith("-rw") or cleaned.startswith("d"):
                anon_dirs.append(cleaned)
        elif current_section == "syst":
            if not banner:
                banner = cleaned
            if cleaned.lower().startswith("system:"):
                system = cleaned.split(":", 1)[1].strip()

    return {
        "banner": banner,
        "system": system,
        "anonymous_login": anonymous,
        "anonymous_listing": anon_dirs[:50],
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
