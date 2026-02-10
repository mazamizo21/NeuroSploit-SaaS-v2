#!/usr/bin/env python3
"""Parse Nmap grepable output (-oG) into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_grepable(text: str) -> List[Dict[str, object]]:
    results: List[Dict[str, object]] = []
    for line in text.splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split("\t")
        host_part = parts[0]
        host_tokens = host_part.split()
        if len(host_tokens) < 2:
            continue
        host = host_tokens[1]
        ports_info = ""
        for part in parts:
            if part.startswith("Ports:"):
                ports_info = part[len("Ports:"):].strip()
                break
        ports = []
        if ports_info:
            for entry in ports_info.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                fields = entry.split("/")
                if len(fields) < 5:
                    continue
                port, state, proto, _, service = fields[:5]
                ports.append(
                    {
                        "port": port,
                        "state": state,
                        "proto": proto,
                        "service": service,
                    }
                )
        results.append({"host": host, "ports": ports})
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to Nmap grepable output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = {"hosts": parse_grepable(raw)}
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
