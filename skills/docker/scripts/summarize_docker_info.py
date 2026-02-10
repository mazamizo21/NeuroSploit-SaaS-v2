#!/usr/bin/env python3
"""Summarize docker info and ps outputs into structured JSON."""

import argparse
import json
from typing import Dict, List


def parse_kv_lines(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for raw_line in text.splitlines():
        if ":" not in raw_line:
            continue
        key, value = raw_line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key and value:
            data[key] = value
    return data


def parse_ps(text: str) -> List[Dict[str, str]]:
    lines = [line.rstrip("\r\n") for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return []
    header = [h.strip().lower().replace(" ", "_") for h in lines[0].split()]
    rows: List[Dict[str, str]] = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < len(header):
            continue
        data = dict(zip(header, parts[: len(header)]))
        rows.append(data)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--info", required=True, help="Path to docker info output")
    parser.add_argument("--ps", required=True, help="Path to docker ps output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.info, "r", encoding="utf-8", errors="ignore") as f:
        info_raw = f.read()
    with open(args.ps, "r", encoding="utf-8", errors="ignore") as f:
        ps_raw = f.read()

    output = {
        "info": parse_kv_lines(info_raw),
        "containers": parse_ps(ps_raw),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
