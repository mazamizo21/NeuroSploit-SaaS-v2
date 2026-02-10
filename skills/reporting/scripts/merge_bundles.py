#!/usr/bin/env python3
"""Merge multiple evidence bundles into a single reporting bundle."""

import argparse
import json
from typing import Dict, Any


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", nargs="+", required=True, help="Input bundle JSON files")
    parser.add_argument("--out", required=True, help="Output merged bundle")
    args = parser.parse_args()

    merged: Dict[str, Any] = {"bundles": [], "summary": []}

    for path in args.inputs:
        data = load_json(path)
        merged["bundles"].append({"source": path, "data": data})
        if isinstance(data, dict) and "summary" in data:
            merged["summary"].append({"source": path, "summary": data.get("summary")})

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)


if __name__ == "__main__":
    main()
