#!/usr/bin/env python3
"""Write a JSON manifest for exported artifacts."""

import argparse
import json
import os
from typing import List, Dict


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Artifacts directory")
    parser.add_argument("--out", required=True, help="Manifest JSON output")
    args = parser.parse_args()

    files: List[Dict[str, str]] = []
    for root, _, filenames in os.walk(args.dir):
        for name in filenames:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, args.dir)
            size = os.path.getsize(path)
            files.append({"file": rel, "bytes": size})

    manifest = {
        "root": os.path.basename(args.dir),
        "files": sorted(files, key=lambda x: x["file"]),
        "count": len(files),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


if __name__ == "__main__":
    main()
