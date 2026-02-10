#!/usr/bin/env python3
"""Parse auditpol output into structured JSON."""

import argparse
import json
import re
from typing import Dict, List, Optional


def parse_auditpol(text: str) -> Dict[str, List[Dict[str, str]]]:
    entries: List[Dict[str, str]] = []
    current_category: Optional[str] = None

    for line in text.splitlines():
        raw = line.rstrip()
        if not raw.strip():
            continue
        if "System audit policy" in raw or "Category/Subcategory" in raw:
            continue
        # Category line (no leading spaces)
        if not raw.startswith(" "):
            current_category = raw.strip()
            continue
        # Subcategory line
        match = re.split(r"\s{2,}", raw.strip())
        if len(match) >= 2:
            subcategory = match[0].strip()
            setting = match[1].strip()
            entries.append({
                "category": current_category or "Unknown",
                "subcategory": subcategory,
                "setting": setting,
            })

    return {
        "entries": entries,
        "total": len(entries),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to auditpol output text")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    output = parse_auditpol(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
