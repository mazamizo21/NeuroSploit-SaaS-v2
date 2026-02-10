#!/usr/bin/env python3
"""Summarize API gateway discovery outputs into a unified inventory."""

import argparse
import json
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_httpx(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    targets = [item.get("url") for item in data if isinstance(item, dict) and item.get("url")]
    return {"count": len(targets), "sample_targets": targets[:20]}


def summarize_nuclei(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    tags = set()
    for item in data:
        info = item.get("info") if isinstance(item, dict) else {}
        for tag in info.get("tags", []) if isinstance(info, dict) else []:
            tags.add(tag)
    return {"count": len(data), "tags": sorted(tags)[:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpx", default="", help="Path to httpx JSONL output")
    parser.add_argument("--nuclei", default="", help="Path to nuclei JSON/JSONL output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    httpx = _load_json(args.httpx) if args.httpx else []
    nuclei = _load_json(args.nuclei) if args.nuclei else []

    output = {
        "httpx": summarize_httpx(httpx),
        "nuclei": summarize_nuclei(nuclei),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
