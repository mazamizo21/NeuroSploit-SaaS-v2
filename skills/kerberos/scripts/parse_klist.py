#!/usr/bin/env python3
"""Parse klist output into a structured JSON summary."""

import argparse
import json
from typing import List, Dict


def parse_klist(text: str) -> Dict[str, object]:
    ticket_cache = ""
    default_principal = ""
    tickets: List[Dict[str, str]] = []
    in_table = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            in_table = False
            continue
        if line.lower().startswith("ticket cache:"):
            ticket_cache = line.split(":", 1)[1].strip()
            continue
        if line.lower().startswith("default principal:"):
            default_principal = line.split(":", 1)[1].strip()
            continue
        if line.lower().startswith("valid starting"):
            in_table = True
            continue
        if in_table:
            parts = line.split()
            if len(parts) < 5:
                continue
            start = " ".join(parts[0:2])
            expires = " ".join(parts[2:4])
            service = " ".join(parts[4:])
            tickets.append(
                {
                    "valid_starting": start,
                    "expires": expires,
                    "service_principal": service,
                }
            )

    return {
        "ticket_cache": ticket_cache,
        "default_principal": default_principal,
        "tickets": tickets,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to klist output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_klist(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

