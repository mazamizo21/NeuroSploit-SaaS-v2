#!/usr/bin/env python3
"""Parse Nmap RDP script output into structured JSON."""

import argparse
import json
from typing import Dict, Any, List


def _set_field(target: Dict[str, Any], key: str, value: str) -> None:
    if key in target:
        existing = target[key]
        if isinstance(existing, list):
            existing.append(value)
        else:
            target[key] = [existing, value]
    else:
        target[key] = value


def parse_nmap(text: str) -> Dict[str, Any]:
    ntlm_info: Dict[str, Any] = {}
    encryption: Dict[str, Any] = {}
    current_section = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "rdp-ntlm-info" in line:
            current_section = "ntlm"
            continue
        if "rdp-enum-encryption" in line:
            current_section = "encryption"
            continue
        if not line.startswith("|") and not line.startswith("|_"):
            continue
        cleaned = line.lstrip("|_").strip()
        if not cleaned:
            continue
        if ":" in cleaned:
            key, value = cleaned.split(":", 1)
            key = key.strip()
            value = value.strip()
            if current_section == "ntlm":
                _set_field(ntlm_info, key, value)
            elif current_section == "encryption":
                _set_field(encryption, key, value)
        elif current_section == "encryption":
            # Capture non key/value lines as notes
            _set_field(encryption, "notes", cleaned)

    return {
        "ntlm_info": ntlm_info,
        "encryption": encryption,
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

