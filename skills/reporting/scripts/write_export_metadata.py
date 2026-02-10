#!/usr/bin/env python3
"""Write export metadata for report bundles."""

import argparse
import json
from datetime import datetime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True, help="Job ID")
    parser.add_argument("--actor", required=True, help="Actor")
    parser.add_argument("--out", required=True, help="Metadata JSON")
    parser.add_argument("--notes", help="Optional notes")
    args = parser.parse_args()

    metadata = {
        "job_id": args.job,
        "actor": args.actor,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "notes": args.notes,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)


if __name__ == "__main__":
    main()
