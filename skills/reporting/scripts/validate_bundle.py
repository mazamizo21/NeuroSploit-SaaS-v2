#!/usr/bin/env python3
"""Validate evidence bundles for required fields and basic shape."""

import argparse
import json
from typing import Dict, Any, List

REQUIRED_KEYS = ["summary", "evidence"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Bundle JSON file")
    parser.add_argument("--out", required=True, help="Validation report JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data: Dict[str, Any] = json.load(f)

    errors: List[str] = []
    for key in REQUIRED_KEYS:
        if key not in data:
            errors.append(f"Missing key: {key}")

    summary_ok = isinstance(data.get("summary"), list)
    evidence_ok = isinstance(data.get("evidence"), dict)

    if not summary_ok:
        errors.append("summary must be a list")
    if not evidence_ok:
        errors.append("evidence must be a dict")

    output = {
        "ok": len(errors) == 0,
        "errors": errors,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
