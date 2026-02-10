#!/usr/bin/env python3
"""Emit the normalized findings schema as JSON for downstream validation."""

import argparse
import json

SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["title", "severity", "description", "category"],
                "properties": {
                    "title": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                    "category": {"type": "string"},
                    "target": {"type": ["string", "null"]},
                },
            },
        },
        "count": {"type": "number"},
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
