#!/usr/bin/env python3
"""Parse schtasks /query /fo LIST /v output into JSON."""

import argparse
import json
from typing import List, Dict


def parse_tasks(text: str) -> List[Dict[str, str]]:
    tasks: List[Dict[str, str]] = []
    current: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            if current:
                tasks.append(current)
                current = {}
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = value.strip()
    if current:
        tasks.append(current)
    return tasks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to schtasks output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    tasks = parse_tasks(text)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"tasks": tasks, "count": len(tasks)}, f, indent=2)


if __name__ == "__main__":
    main()
