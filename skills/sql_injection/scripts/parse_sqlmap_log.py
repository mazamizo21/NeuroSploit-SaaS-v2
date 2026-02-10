#!/usr/bin/env python3
"""Parse sqlmap log output into structured JSON."""

import argparse
import json
import re
from typing import Dict, List


DBMS_RE = re.compile(r"back-end DBMS(?: is|:)\s*(.+)", re.IGNORECASE)
PARAM_RE = re.compile(r"parameter '(.+?)' is vulnerable", re.IGNORECASE)
TYPE_RE = re.compile(r"^Type:\s*(.+)$", re.IGNORECASE)
TITLE_RE = re.compile(r"^Title:\s*(.+)$", re.IGNORECASE)
PAYLOAD_RE = re.compile(r"^Payload:\s*(.+)$", re.IGNORECASE)


def parse_log(text: str) -> Dict[str, object]:
    dbms = ""
    parameters: List[str] = []
    techniques: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        dbms_match = DBMS_RE.search(line)
        if dbms_match:
            dbms = dbms_match.group(1).strip()
        param_match = PARAM_RE.search(line)
        if param_match:
            parameters.append(param_match.group(1).strip())
        type_match = TYPE_RE.match(line)
        if type_match:
            if current:
                techniques.append(current)
                current = {}
            current["type"] = type_match.group(1).strip()
            continue
        title_match = TITLE_RE.match(line)
        if title_match and current:
            current["title"] = title_match.group(1).strip()
            continue
        payload_match = PAYLOAD_RE.match(line)
        if payload_match and current:
            current["payload"] = payload_match.group(1).strip()

    if current:
        techniques.append(current)

    return {
        "dbms": dbms,
        "parameters": sorted(set(parameters)),
        "techniques": techniques,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to sqlmap log output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_log(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
