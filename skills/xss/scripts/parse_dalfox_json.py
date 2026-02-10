#!/usr/bin/env python3
"""Parse dalfox JSON/JSONL output into structured JSON evidence."""

import argparse
import json
from typing import Any, Dict, List


def load_items(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    if raw.startswith("{"):
        data = json.loads(raw)
        return [data] if isinstance(data, dict) else []
    items: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            items.append(obj)
    return items


def summarize(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    params = set()
    payloads = []
    urls = set()
    types = set()
    for item in items:
        param = item.get("param") or item.get("parameter")
        if param:
            params.add(param)
        payload = item.get("payload")
        if payload:
            payloads.append(payload)
        url = item.get("url") or item.get("target")
        if url:
            urls.add(url)
        xtype = item.get("type") or item.get("category")
        if xtype:
            types.add(xtype)
    return {
        "count": len(items),
        "parameters": sorted(params),
        "types": sorted(types),
        "sample_payloads": payloads[:10],
        "targets": sorted(urls)[:10],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to dalfox JSON/JSONL output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    items = load_items(args.input)
    output = {"summary": summarize(items), "findings": items}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
