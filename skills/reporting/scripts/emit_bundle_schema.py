#!/usr/bin/env python3
"""Emit the evidence bundle schema as JSON."""

import argparse
import json

SCHEMA = {
    "type": "object",
    "required": ["summary", "evidence"],
    "properties": {
        "summary": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "keys": {"type": ["array", "null"]},
                },
            },
        },
        "evidence": {"type": "object"},
    },
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="Output schema JSON")
    args = parser.parse_args()

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(SCHEMA, f, indent=2)


if __name__ == "__main__":
    main()
