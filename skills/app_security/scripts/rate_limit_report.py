#!/usr/bin/env python3
"""Extract rate limit evidence from headers JSON produced by headers_to_json."""

import argparse
import json
from typing import Dict, List

RATE_LIMIT_KEYS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
]


def extract(headers: Dict[str, List[str]]) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = {}
    for key in RATE_LIMIT_KEYS:
        if key in headers:
            found[key] = headers[key]
    return found


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to headers JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    headers = data.get("raw_headers", {})
    rate_limits = extract(headers)

    output = {
        "rate_limit_headers": rate_limits,
        "present": bool(rate_limits),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
