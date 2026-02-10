#!/usr/bin/env python3
"""Parse ike-scan output into structured JSON."""

import argparse
import json
import re
from typing import Dict, Any, List


TARGET_RE = re.compile(r"^(?P<host>[0-9a-fA-F\.:]+|[A-Za-z0-9_.-]+)\s+")


def parse_output(text: str) -> Dict[str, Any]:
    results: Dict[str, Dict[str, Any]] = {}
    current_host = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = TARGET_RE.match(line)
        if match:
            current_host = match.group("host")
            entry = results.setdefault(current_host, {"modes": [], "vendor_ids": [], "notes": []})
            upper = line.upper()
            if "AGGRESSIVE MODE" in upper:
                entry["modes"].append("aggressive")
            if "MAIN MODE" in upper:
                entry["modes"].append("main")
            if "IKEV2" in upper:
                entry["modes"].append("ikev2")
            entry["notes"].append(line)
            continue
        if current_host:
            entry = results[current_host]
            upper = line.upper()
            if "VID=" in upper or "VENDOR ID" in upper:
                entry["vendor_ids"].append(line)
            if "AGGRESSIVE MODE" in upper and "aggressive" not in entry["modes"]:
                entry["modes"].append("aggressive")
            if "MAIN MODE" in upper and "main" not in entry["modes"]:
                entry["modes"].append("main")
            if "IKEV2" in upper and "ikev2" not in entry["modes"]:
                entry["modes"].append("ikev2")
            entry["notes"].append(line)

    return {"targets": results}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to ike-scan output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_output(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

