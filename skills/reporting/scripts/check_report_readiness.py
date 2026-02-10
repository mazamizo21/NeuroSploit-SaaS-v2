#!/usr/bin/env python3
"""Check report readiness by verifying required artifacts exist."""

import argparse
import json
import os
from typing import List

REQUIRED_FILES = [
    "report.json",
    "report.md",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Output directory")
    parser.add_argument("--out", required=True, help="Readiness report JSON")
    args = parser.parse_args()

    missing: List[str] = []
    for name in REQUIRED_FILES:
        path = os.path.join(args.dir, name)
        if not os.path.isfile(path):
            missing.append(name)

    output = {
        "ok": len(missing) == 0,
        "missing": missing,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
