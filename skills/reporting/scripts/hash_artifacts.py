#!/usr/bin/env python3
"""Generate SHA256 hashes for artifacts in a directory."""

import argparse
import hashlib
import os
from typing import List


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Artifacts directory")
    parser.add_argument("--out", required=True, help="Output checksum file")
    args = parser.parse_args()

    entries: List[str] = []
    for root, _, files in os.walk(args.dir):
        for name in files:
            path = os.path.join(root, name)
            rel = os.path.relpath(path, args.dir)
            entries.append(f"{sha256_file(path)}  {rel}")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(entries)))


if __name__ == "__main__":
    main()
