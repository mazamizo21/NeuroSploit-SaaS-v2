#!/usr/bin/env python3
"""Package exported artifacts into a tar.gz archive."""

import argparse
import tarfile
import os


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True, help="Export directory")
    parser.add_argument("--out", required=True, help="Output tar.gz file")
    args = parser.parse_args()

    with tarfile.open(args.out, "w:gz") as tar:
        tar.add(args.dir, arcname=os.path.basename(args.dir))


if __name__ == "__main__":
    main()
