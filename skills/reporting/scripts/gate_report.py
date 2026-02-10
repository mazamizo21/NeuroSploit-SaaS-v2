#!/usr/bin/env python3
"""Gate report generation based on readiness and validation checks."""

import argparse
import json
from typing import Dict, Any, List


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--readiness", required=True, help="Readiness JSON")
    parser.add_argument("--bundle", required=True, help="Bundle validation JSON")
    parser.add_argument("--schema", required=True, help="Schema check JSON")
    parser.add_argument("--manifest", required=True, help="Manifest check JSON")
    parser.add_argument("--out", required=True, help="Gate output JSON")
    args = parser.parse_args()

    readiness = load_json(args.readiness)
    bundle = load_json(args.bundle)
    schema = load_json(args.schema)
    manifest = load_json(args.manifest)

    errors: List[str] = []
    if not readiness.get("ok"):
        errors.append("Report readiness failed")
    if not bundle.get("ok"):
        errors.append("Bundle validation failed")
    if not schema.get("ok"):
        errors.append("Schema validation failed")
    if not manifest.get("ok"):
        errors.append("Manifest validation failed")

    output = {
        "ok": len(errors) == 0,
        "errors": errors,
        "inputs": {
            "readiness": readiness,
            "bundle": bundle,
            "schema": schema,
            "manifest": manifest,
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
