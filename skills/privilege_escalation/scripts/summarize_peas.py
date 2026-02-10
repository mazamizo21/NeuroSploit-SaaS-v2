#!/usr/bin/env python3
"""Summarize LinPEAS/WinPEAS output into structured JSON highlights."""

import argparse
import json
import re
from typing import Dict, List


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def summarize(text: str) -> Dict[str, object]:
    highlights: List[str] = []
    counts = {"info": 0, "warn": 0, "crit": 0}
    for raw_line in text.splitlines():
        line = strip_ansi(raw_line).strip()
        if not line:
            continue
        if "[!]" in line or "VULN" in line or "CVE-" in line:
            counts["crit"] += 1
            highlights.append(line)
        elif "[+]" in line:
            counts["warn"] += 1
            highlights.append(line)
        elif "[*]" in line:
            counts["info"] += 1
    return {
        "counts": counts,
        "highlights": highlights[:50],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to PEAS output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = summarize(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
