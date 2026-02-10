#!/usr/bin/env python3
"""Summarize httpx JSONL output into endpoint evidence."""

import argparse
import json
from typing import Any, Dict, List


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    items.append(item)
            except json.JSONDecodeError:
                continue
    return items


def summarize(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    endpoints: List[Dict[str, Any]] = []
    status_counts: Dict[str, int] = {}
    tech = set()
    for item in items:
        url = item.get("url") or item.get("input") or item.get("host")
        if not url:
            continue
        status = item.get("status-code") or item.get("status_code")
        if status is not None:
            status_counts[str(status)] = status_counts.get(str(status), 0) + 1
        for entry in item.get("tech", []) if isinstance(item.get("tech"), list) else []:
            tech.add(entry)
        server = item.get("webserver")
        if server:
            tech.add(server)
        endpoints.append(
            {
                "url": url,
                "status": status,
                "title": item.get("title"),
                "ip": item.get("host") or item.get("ip"),
                "tech": item.get("tech"),
                "webserver": item.get("webserver"),
            }
        )
    return {
        "endpoint_count": len(endpoints),
        "status_counts": status_counts,
        "sample_tech": sorted(tech)[:20],
        "endpoints": endpoints,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to httpx JSONL output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    items = load_jsonl(args.input)
    output = summarize(items)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
