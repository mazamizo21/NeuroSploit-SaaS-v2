#!/usr/bin/env python3
"""Parse Droopescan output into structured JSON evidence."""

import argparse
import json
import re
from typing import Dict, List


VERSION_RE = re.compile(r"version\\s*[:=]\\s*([0-9.]+)", re.IGNORECASE)


def parse_output(text: str) -> Dict[str, object]:
    version = ""
    modules: List[str] = []
    notes: List[str] = []
    in_modules = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            in_modules = False
            continue
        if "plugins found" in line.lower() or "modules found" in line.lower():
            in_modules = True
            continue
        match = VERSION_RE.search(line)
        if match and not version:
            version = match.group(1)
        if in_modules and line.startswith("-"):
            module = line.lstrip("-").strip()
            if module:
                modules.append(module)
        if line.startswith("[+]") or line.startswith("[!]"):
            notes.append(line)

    return {
        "version": version,
        "modules": sorted(set(modules)),
        "notes": notes[:50],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to droopescan output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_output(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
