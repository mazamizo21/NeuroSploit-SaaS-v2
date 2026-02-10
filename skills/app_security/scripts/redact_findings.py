#!/usr/bin/env python3
"""Redact sensitive values from findings JSON."""

import argparse
import json
import re
from typing import Any

SENSITIVE_PATTERNS = [
    re.compile(r"(?i)apikey\s*[:=]\s*[A-Za-z0-9\-_]{8,}"),
    re.compile(r"(?i)secret\s*[:=]\s*[A-Za-z0-9\-_]{8,}"),
    re.compile(r"(?i)token\s*[:=]\s*[A-Za-z0-9\-_]{8,}"),
]


def redact_value(value: str) -> str:
    redacted = value
    for pattern in SENSITIVE_PATTERNS:
        redacted = pattern.sub("REDACTED", redacted)
    return redacted


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return redact_value(obj)
    return obj


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Findings JSON file")
    parser.add_argument("--out", required=True, help="Redacted output JSON")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    redacted = redact(data)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(redacted, f, indent=2)


if __name__ == "__main__":
    main()
