#!/usr/bin/env python3
"""Summarize Azure CLI JSON outputs into a single inventory summary."""

import argparse
import json
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_account_show(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    return {
        "tenant_id": data.get("tenantId"),
        "subscription_id": data.get("id"),
        "subscription_name": data.get("name"),
        "user": (data.get("user") or {}).get("name"),
    }


def summarize_account_list(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get("name") for item in data if isinstance(item, dict) and item.get("name")]
    return {"count": len(data), "sample_subscriptions": names[:20]}


def summarize_resources(data: Any, key: str) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get(key) for item in data if isinstance(item, dict) and item.get(key)]
    return {"count": len(data), "sample_names": names[:20]}


def summarize_role_assignments(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    roles: List[str] = []
    for item in data:
        if isinstance(item, dict) and item.get("roleDefinitionName"):
            roles.append(item["roleDefinitionName"])
    return {"count": len(data), "sample_roles": sorted(set(roles))[:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--account-show", default="", help="Path to az account show JSON")
    parser.add_argument("--account-list", default="", help="Path to az account list JSON")
    parser.add_argument("--storage-accounts", default="", help="Path to az storage account list JSON")
    parser.add_argument("--keyvaults", default="", help="Path to az keyvault list JSON")
    parser.add_argument("--vms", default="", help="Path to az vm list JSON")
    parser.add_argument("--role-assignments", default="", help="Path to az role assignment list JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output = {
        "account": summarize_account_show(_load_json(args.account_show)),
        "subscriptions": summarize_account_list(_load_json(args.account_list)),
        "storage_accounts": summarize_resources(_load_json(args.storage_accounts), "name"),
        "keyvaults": summarize_resources(_load_json(args.keyvaults), "name"),
        "vms": summarize_resources(_load_json(args.vms), "name"),
        "role_assignments": summarize_role_assignments(_load_json(args.role_assignments)),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

