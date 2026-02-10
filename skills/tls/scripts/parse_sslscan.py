#!/usr/bin/env python3
"""Parse sslscan output into structured JSON."""

import argparse
import json
import re
from typing import Dict, List, Any


CIPHER_RE = re.compile(r"^(Accepted|Preferred)\s+(\S+)\s+(\d+)\s+bits\s+(.+)$")


def parse_sslscan(text: str) -> Dict[str, Any]:
    protocols = set()
    ciphers: List[Dict[str, str]] = []
    cert_info: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = CIPHER_RE.match(line)
        if match:
            status, protocol, bits, cipher = match.groups()
            protocols.add(protocol)
            ciphers.append(
                {
                    "status": status,
                    "protocol": protocol,
                    "bits": bits,
                    "cipher": cipher,
                }
            )
            continue
        if line.lower().startswith("subject:"):
            cert_info["subject"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("issuer:"):
            cert_info["issuer"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("not valid before:"):
            cert_info["not_before"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("not valid after:"):
            cert_info["not_after"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("signature algorithm:"):
            cert_info["signature_algorithm"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("key strength:"):
            cert_info["key_strength"] = line.split(":", 1)[1].strip()

    return {
        "protocols": sorted(protocols),
        "ciphers": ciphers,
        "certificate": cert_info,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to sslscan output file")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_sslscan(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
