#!/usr/bin/env python3
"""Append an audit log entry for report export actions."""

import argparse
import json
import os
from datetime import datetime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True, help="Action name")
    parser.add_argument("--actor", required=True, help="Actor identifier")
    parser.add_argument("--details", help="Additional details JSON")
    parser.add_argument("--out", required=True, help="Audit log file")
    args = parser.parse_args()

    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": args.action,
        "actor": args.actor,
    }

    if args.details:
        try:
            entry["details"] = json.loads(args.details)
        except json.JSONDecodeError:
            entry["details"] = {"raw": args.details}

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    with open(args.out, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    main()
