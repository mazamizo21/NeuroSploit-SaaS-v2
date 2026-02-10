#!/usr/bin/env python3
"""Diff two JSON policy documents and emit a summary."""

import argparse
import json
import sys
from typing import Any, Dict, List

KEY_CANDIDATES = ["Sid", "sid", "id", "name", "key", "identifier"]


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def to_id_map(items: List[Dict[str, Any]]):
    for key in KEY_CANDIDATES:
        if all(isinstance(i, dict) and key in i for i in items):
            return key, {str(i.get(key)): i for i in items}
    return None, None


def add_change(changes: Dict[str, list], kind: str, path: str, before: Any, after: Any):
    changes[kind].append({"path": path, "before": before, "after": after})


def diff_values(before: Any, after: Any, path: str, changes: Dict[str, list]):
    if type(before) != type(after):
        add_change(changes, "changed", path, before, after)
        return

    if isinstance(before, dict):
        before_keys = set(before.keys())
        after_keys = set(after.keys())
        for k in sorted(before_keys - after_keys):
            add_change(changes, "removed", f"{path}.{k}" if path else k, before[k], None)
        for k in sorted(after_keys - before_keys):
            add_change(changes, "added", f"{path}.{k}" if path else k, None, after[k])
        for k in sorted(before_keys & after_keys):
            next_path = f"{path}.{k}" if path else k
            diff_values(before[k], after[k], next_path, changes)
        return

    if isinstance(before, list):
        # Prefer keyed comparison for lists of dicts with a stable key
        if before and after and all(isinstance(i, dict) for i in before + after):
            key, before_map = to_id_map(before)
            _, after_map = to_id_map(after)
            if key and before_map is not None and after_map is not None:
                before_keys = set(before_map.keys())
                after_keys = set(after_map.keys())
                for k in sorted(before_keys - after_keys):
                    add_change(changes, "removed", f"{path}[{key}={k}]", before_map[k], None)
                for k in sorted(after_keys - before_keys):
                    add_change(changes, "added", f"{path}[{key}={k}]", None, after_map[k])
                for k in sorted(before_keys & after_keys):
                    diff_values(before_map[k], after_map[k], f"{path}[{key}={k}]", changes)
                return

        # Compare scalar lists as sets
        if all(not isinstance(i, (dict, list)) for i in before + after):
            before_set = set(before)
            after_set = set(after)
            for v in sorted(before_set - after_set):
                add_change(changes, "removed", f"{path}[]", v, None)
            for v in sorted(after_set - before_set):
                add_change(changes, "added", f"{path}[]", None, v)
            return

        # Fallback: index-based comparison
        max_len = max(len(before), len(after))
        for i in range(max_len):
            idx_path = f"{path}[{i}]"
            if i >= len(before):
                add_change(changes, "added", idx_path, None, after[i])
            elif i >= len(after):
                add_change(changes, "removed", idx_path, before[i], None)
            else:
                diff_values(before[i], after[i], idx_path, changes)
        return

    if before != after:
        add_change(changes, "changed", path, before, after)


def main():
    parser = argparse.ArgumentParser(description="Diff two JSON policy documents")
    parser.add_argument("--before", required=True, help="Path to before policy JSON")
    parser.add_argument("--after", required=True, help="Path to after policy JSON")
    parser.add_argument("--out", help="Write diff output to a JSON file")
    args = parser.parse_args()

    before = load_json(args.before)
    after = load_json(args.after)

    changes = {"added": [], "removed": [], "changed": []}
    diff_values(before, after, "", changes)

    output = json.dumps(changes, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write(f"policy_diff error: {exc}\n")
        sys.exit(1)
