#!/usr/bin/env python3
"""Validate exported artifacts against a manifest."""

import argparse
import json
import os
from typing import List


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Artifacts directory")
    parser.add_argument("--manifest", required=True, help="Manifest JSON")
    parser.add_argument("--out", required=True, help="Validation JSON")
    args = parser.parse_args()

    with open(args.manifest, "r", encoding="utf-8", errors="ignore") as f:
        manifest = json.load(f)

    missing: List[str] = []
    mismatched: List[str] = []

    for entry in manifest.get("files", []):
        rel = entry.get("file")
        size = entry.get("bytes")
        if not rel:
            continue
        path = os.path.join(args.dir, rel)
        if not os.path.isfile(path):
            missing.append(rel)
            continue
        if size is not None and os.path.getsize(path) != size:
            mismatched.append(rel)

    output = {
        "ok": len(missing) == 0 and len(mismatched) == 0,
        "missing": missing,
        "size_mismatched": mismatched,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
