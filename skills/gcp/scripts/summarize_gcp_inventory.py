#!/usr/bin/env python3
"""Summarize GCP CLI JSON outputs into a single inventory summary."""

import argparse
import json
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_projects(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    ids = [item.get("projectId") for item in data if isinstance(item, dict) and item.get("projectId")]
    return {"count": len(data), "sample_projects": ids[:20]}


def summarize_service_accounts(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    emails = [item.get("email") for item in data if isinstance(item, dict) and item.get("email")]
    return {"count": len(data), "sample_accounts": emails[:20]}


def summarize_instances(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get("name") for item in data if isinstance(item, dict) and item.get("name")]
    external_ips = 0
    for item in data:
        if not isinstance(item, dict):
            continue
        nics = item.get("networkInterfaces") or []
        for nic in nics:
            for cfg in nic.get("accessConfigs", []) if isinstance(nic, dict) else []:
                if cfg.get("natIP"):
                    external_ips += 1
                    break
    return {"count": len(data), "sample_instances": names[:20], "external_ip_count": external_ips}


def summarize_buckets(data: Any) -> Dict[str, Any]:
    if not isinstance(data, list):
        return {}
    names = [item.get("name") for item in data if isinstance(item, dict) and item.get("name")]
    return {"count": len(data), "sample_buckets": names[:20]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--projects", default="", help="Path to gcloud projects list JSON")
    parser.add_argument("--service-accounts", default="", help="Path to gcloud iam service-accounts list JSON")
    parser.add_argument("--instances", default="", help="Path to gcloud compute instances list JSON")
    parser.add_argument("--buckets", default="", help="Path to gcloud storage buckets list JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output = {
        "projects": summarize_projects(_load_json(args.projects)),
        "service_accounts": summarize_service_accounts(_load_json(args.service_accounts)),
        "instances": summarize_instances(_load_json(args.instances)),
        "buckets": summarize_buckets(_load_json(args.buckets)),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

