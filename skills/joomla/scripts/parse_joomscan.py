#!/usr/bin/env python3
"""Parse Joomscan output into structured JSON evidence."""

import argparse
import json
import re
from typing import Dict, List


VERSION_RE = re.compile(r"joomla\\s+version\\s*[:=]\\s*([0-9.]+)", re.IGNORECASE)
COMP_RE = re.compile(r"component\\s*[:=]\\s*([a-zA-Z0-9_-]+)", re.IGNORECASE)


def parse_output(text: str) -> Dict[str, object]:
    version = ""
    components: List[str] = []
    notes: List[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = VERSION_RE.search(line)
        if match and not version:
            version = match.group(1)
        comp_match = COMP_RE.search(line)
        if comp_match:
            components.append(comp_match.group(1))
        if line.startswith("[+]") or line.startswith("[!]"):
            notes.append(line)

    return {
        "version": version,
        "components": sorted(set(components)),
        "notes": notes[:50],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to joomscan output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_output(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
