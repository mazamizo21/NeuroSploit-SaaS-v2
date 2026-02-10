#!/usr/bin/env python3
"""Summarize kubectl JSON outputs into a single inventory report."""

import argparse
import json
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_items(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    items = data.get("items") or []
    names = []
    for item in items:
        if not isinstance(item, dict):
            continue
        meta = item.get("metadata") or {}
        name = meta.get("name")
        if name:
            names.append(name)
    return {"count": len(items), "sample_names": names[:20]}


def summarize_bindings(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    items = data.get("items") or []
    subjects = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for subj in item.get("subjects") or []:
            if isinstance(subj, dict) and subj.get("name"):
                subjects.append(subj.get("name"))
    return {"count": len(items), "sample_subjects": subjects[:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespaces", default="", help="Path to namespaces JSON")
    parser.add_argument("--nodes", default="", help="Path to nodes JSON")
    parser.add_argument("--services", default="", help="Path to services JSON")
    parser.add_argument("--ingresses", default="", help="Path to ingresses JSON")
    parser.add_argument("--clusterrolebindings", default="", help="Path to clusterrolebindings JSON")
    parser.add_argument("--networkpolicies", default="", help="Path to networkpolicies JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output = {
        "namespaces": summarize_items(_load_json(args.namespaces)),
        "nodes": summarize_items(_load_json(args.nodes)),
        "services": summarize_items(_load_json(args.services)),
        "ingresses": summarize_items(_load_json(args.ingresses)),
        "clusterrolebindings": summarize_bindings(_load_json(args.clusterrolebindings)),
        "networkpolicies": summarize_items(_load_json(args.networkpolicies)),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
