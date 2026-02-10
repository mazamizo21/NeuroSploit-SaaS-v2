#!/usr/bin/env python3
"""Parse smbclient -L output into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_output(text: str) -> Dict[str, object]:
    shares: List[Dict[str, str]] = []
    errors: List[str] = []
    auth_status = "unknown"

    lines = [line.rstrip("\r\n") for line in text.splitlines()]
    in_table = False
    for line in lines:
        low = line.lower()
        if "anonymous login successful" in low or "session setup ok" in low:
            auth_status = "success"
        if "nt_status_" in low or "access denied" in low:
            errors.append(line.strip())
            if auth_status == "unknown":
                auth_status = "failed"
        if line.strip().startswith("Sharename"):
            in_table = True
            continue
        if in_table:
            if not line.strip():
                in_table = False
                continue
            if line.strip().startswith("----"):
                continue
            parts = [p for p in line.split(" ") if p]
            if len(parts) >= 2:
                name = parts[0]
                share_type = parts[1]
                comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                shares.append({"name": name, "type": share_type, "comment": comment})

    return {
        "auth_status": auth_status,
        "shares": shares,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to smbclient output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_output(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
