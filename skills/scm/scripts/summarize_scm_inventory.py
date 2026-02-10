#!/usr/bin/env python3
"""Summarize SCM discovery outputs into a concise inventory report."""

import argparse
import json
from typing import Any, Dict, List


def _load_json_or_list(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_repos(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get("name") for item in data if isinstance(item, dict) and item.get("name")]
    return {"count": len(data), "sample_repos": names[:20]}


def summarize_users(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get("login") or item.get("username") for item in data if isinstance(item, dict)]
    return {"count": len(data), "sample_users": [n for n in names if n][:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repos", default="", help="Path to SCM repos JSON")
    parser.add_argument("--users", default="", help="Path to SCM users JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    repos = _load_json_or_list(args.repos)
    users = _load_json_or_list(args.users)

    output = {
        "repos": summarize_repos(repos),
        "users": summarize_users(users),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
