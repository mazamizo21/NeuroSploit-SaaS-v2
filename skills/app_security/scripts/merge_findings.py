#!/usr/bin/env python3
"""Merge multiple JSON evidence files into a unified findings document."""

import argparse
import json
from typing import List


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", nargs="+", required=True, help="Input JSON files")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    merged: List[dict] = []
    for path in args.inputs:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
            merged.append({"source": path, "data": data})

    output = {"evidence": merged}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
