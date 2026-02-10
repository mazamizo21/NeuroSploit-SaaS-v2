#!/usr/bin/env python3
"""Package Windows host evidence JSON files into a single bundle with index."""

import argparse
import json
import os
from typing import Dict, Any


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", nargs="+", required=True, help="Input JSON files")
    parser.add_argument("--out", required=True, help="Output JSON bundle")
    args = parser.parse_args()

    bundle: Dict[str, Any] = {"summary": [], "evidence": {}}

    for path in args.inputs:
        name = os.path.basename(path)
        data = load_json(path)
        bundle["evidence"][name] = data
        bundle["summary"].append({"file": name, "keys": list(data.keys()) if isinstance(data, dict) else None})

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


if __name__ == "__main__":
    main()
