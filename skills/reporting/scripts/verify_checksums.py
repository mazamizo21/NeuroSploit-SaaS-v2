#!/usr/bin/env python3
"""Verify SHA256 checksums for artifacts in a directory."""

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
    parser.add_argument("--checksums", required=True, help="Checksums file")
    parser.add_argument("--out", required=True, help="Output verification JSON")
    args = parser.parse_args()

    expected = {}
    with open(args.checksums, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("  ", 1)
            if len(parts) == 2:
                expected[parts[1]] = parts[0]

    mismatches: List[str] = []
    for rel, digest in expected.items():
        path = os.path.join(args.dir, rel)
        if not os.path.isfile(path):
            mismatches.append(f"missing:{rel}")
            continue
        if sha256_file(path) != digest:
            mismatches.append(f"mismatch:{rel}")

    output = {
        "ok": len(mismatches) == 0,
        "mismatches": mismatches,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(json.dumps(output, indent=2))


if __name__ == "__main__":
    import json
    main()
