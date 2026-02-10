#!/usr/bin/env python3
"""Summarize CI/CD discovery outputs (httpx, nuclei, gitleaks) into a single report."""

import argparse
import json
from typing import Any, Dict, List


def _load_json_or_jsonl(path: str) -> List[Any]:
    if not path:
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read().strip()
    if not raw:
        return []
    if raw.startswith("{") or raw.startswith("["):
        try:
            data = json.loads(raw)
            return data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            pass
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def summarize_httpx(items: List[Any]) -> Dict[str, Any]:
    hosts = set()
    tech = set()
    status_counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        url = item.get("url") or item.get("host") or item.get("input")
        if url:
            hosts.add(url)
        status = item.get("status-code") or item.get("status_code")
        if status is not None:
            status_counts[str(status)] = status_counts.get(str(status), 0) + 1
        for entry in item.get("tech", []) if isinstance(item.get("tech"), list) else []:
            tech.add(entry)
        server = item.get("webserver")
        if server:
            tech.add(server)
    return {
        "targets": len(hosts),
        "status_counts": status_counts,
        "sample_tech": sorted(tech)[:20],
    }


def summarize_nuclei(items: List[Any]) -> Dict[str, Any]:
    severity_counts: Dict[str, int] = {}
    template_counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = info.get("severity") or item.get("severity") or "unknown"
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        template = item.get("template-id") or item.get("template") or info.get("name")
        if template:
            template_counts[str(template)] = template_counts.get(str(template), 0) + 1
    return {
        "total": sum(severity_counts.values()),
        "severity_counts": severity_counts,
        "top_templates": sorted(template_counts, key=template_counts.get, reverse=True)[:10],
    }


def summarize_gitleaks(items: List[Any]) -> Dict[str, Any]:
    rule_counts: Dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("Rule") or "unknown"
        rule_counts[rule] = rule_counts.get(rule, 0) + 1
    return {
        "total": sum(rule_counts.values()),
        "rule_counts": rule_counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--httpx", default="", help="Path to httpx JSON or JSONL output")
    parser.add_argument("--nuclei", default="", help="Path to nuclei JSONL output")
    parser.add_argument("--gitleaks", default="", help="Path to gitleaks JSON output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    httpx_items = _load_json_or_jsonl(args.httpx)
    nuclei_items = _load_json_or_jsonl(args.nuclei)
    gitleaks_items = _load_json_or_jsonl(args.gitleaks)

    output = {
        "httpx": summarize_httpx(httpx_items),
        "nuclei": summarize_nuclei(nuclei_items),
        "gitleaks": summarize_gitleaks(gitleaks_items),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

