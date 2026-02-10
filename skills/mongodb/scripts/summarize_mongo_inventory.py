#!/usr/bin/env python3
"""Summarize MongoDB shell JSON outputs into a single inventory report."""

import argparse
import json
from typing import Any, Dict


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_build_info(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    return {
        "version": data.get("version"),
        "gitVersion": data.get("gitVersion"),
        "storageEngines": data.get("storageEngines"),
    }


def summarize_databases(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    dbs = data.get("databases") or []
    names = [db.get("name") for db in dbs if isinstance(db, dict) and db.get("name")]
    return {"count": len(dbs), "sample_databases": names[:20]}


def summarize_users(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    users = data.get("users") or []
    names = [u.get("user") for u in users if isinstance(u, dict) and u.get("user")]
    return {"count": len(users), "sample_users": names[:20]}


def summarize_roles(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    roles = data.get("roles") or []
    names = [r.get("role") for r in roles if isinstance(r, dict) and r.get("role")]
    return {"count": len(roles), "sample_roles": names[:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-info", default="", help="Path to buildInfo JSON")
    parser.add_argument("--databases", default="", help="Path to listDatabases JSON")
    parser.add_argument("--users", default="", help="Path to getUsers JSON")
    parser.add_argument("--roles", default="", help="Path to getRoles JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output = {
        "build_info": summarize_build_info(_load_json(args.build_info)),
        "databases": summarize_databases(_load_json(args.databases)),
        "users": summarize_users(_load_json(args.users)),
        "roles": summarize_roles(_load_json(args.roles)),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
