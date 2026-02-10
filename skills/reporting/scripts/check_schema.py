#!/usr/bin/env python3
"""Check that normalized findings match the expected schema."""

import argparse
import json
from typing import List, Dict

REQUIRED_FIELDS = ["title", "severity", "description", "category"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Normalized findings JSON")
    parser.add_argument("--out", required=True, help="Schema check JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    findings = data.get("findings", []) if isinstance(data, dict) else []
    missing: List[Dict[str, List[str]]] = []

    for idx, finding in enumerate(findings):
        missing_fields = [field for field in REQUIRED_FIELDS if field not in finding or finding[field] in (None, "")]
        if missing_fields:
            missing.append({"index": idx, "missing": missing_fields})

    output = {
        "ok": len(missing) == 0,
        "missing": missing,
        "checked": len(findings),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
