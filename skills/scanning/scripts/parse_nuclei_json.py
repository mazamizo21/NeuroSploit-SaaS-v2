#!/usr/bin/env python3
"""Parse nuclei JSON/JSONL output into structured JSON evidence."""

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
    severity_counts: Dict[str, int] = {}
    templates: Dict[str, int] = {}
    targets = set()
    for item in items:
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = info.get("severity") or item.get("severity") or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        template = item.get("template-id") or item.get("template") or info.get("name")
        if template:
            templates[str(template)] = templates.get(str(template), 0) + 1
        target = item.get("matched-at") or item.get("host")
        if target:
            targets.add(target)
    return {
        "total": len(items),
        "severity_counts": severity_counts,
        "top_templates": sorted(templates, key=templates.get, reverse=True)[:10],
        "targets": sorted(targets)[:20],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to nuclei JSON/JSONL output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    items = load_items(args.input)
    output = {"summary": summarize(items), "findings": items}

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
