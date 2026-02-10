#!/usr/bin/env python3
"""Collect standard report artifacts into a directory for export."""

import argparse
import os
import shutil
from typing import List

ARTIFACTS = [
    "report.json",
    "report.md",
    "findings.json",
    "findings_summary.json",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Source output directory")
    parser.add_argument("--out", required=True, help="Destination directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    copied: List[str] = []
    missing: List[str] = []

    for name in ARTIFACTS:
        src = os.path.join(args.dir, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(args.out, name))
            copied.append(name)
        else:
            missing.append(name)

    with open(os.path.join(args.out, "artifact_manifest.txt"), "w", encoding="utf-8") as f:
        f.write("Copied:\n")
        for item in copied:
            f.write(f"- {item}\n")
        f.write("\nMissing:\n")
        for item in missing:
            f.write(f"- {item}\n")


if __name__ == "__main__":
    main()
