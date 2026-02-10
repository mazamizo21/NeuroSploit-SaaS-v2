#!/usr/bin/env python3
"""Parse WPScan JSON output into a concise inventory summary."""

import argparse
import json
from typing import Any, Dict, List


def summarize_version(version: Any) -> Dict[str, Any]:
    if not isinstance(version, dict):
        return {}
    return {
        "number": version.get("number"),
        "status": version.get("status"),
        "confidence": version.get("confidence"),
    }


def summarize_theme(theme: Any) -> Dict[str, Any]:
    if not isinstance(theme, dict):
        return {}
    return {
        "slug": theme.get("slug") or theme.get("name"),
        "version": summarize_version(theme.get("version")),
        "vulnerabilities": theme.get("vulnerabilities") or [],
    }


def summarize_plugins(plugins: Any) -> Dict[str, Any]:
    if not isinstance(plugins, dict):
        return {}
    items: List[Dict[str, Any]] = []
    vulnerable = []
    for slug, data in plugins.items():
        if not isinstance(data, dict):
            continue
        entry = {
            "slug": slug,
            "version": summarize_version(data.get("version")),
            "vulnerabilities": data.get("vulnerabilities") or [],
        }
        items.append(entry)
        if entry["vulnerabilities"]:
            vulnerable.append(slug)
    return {
        "count": len(items),
        "plugins": items[:50],
        "vulnerable_plugins": vulnerable[:50],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to WPScan JSON output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    output = {
        "core": summarize_version(data.get("version")),
        "main_theme": summarize_theme(data.get("main_theme")),
        "plugins": summarize_plugins(data.get("plugins")),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
