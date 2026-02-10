#!/usr/bin/env python3
"""Summarize AWS CLI JSON outputs into a single inventory summary."""

import argparse
import json
from typing import Any, Dict, List, Optional


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_caller(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    return {
        "account": data.get("Account"),
        "user_id": data.get("UserId"),
        "arn": data.get("Arn"),
    }


def summarize_account_summary(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    summary = data.get("SummaryMap") or {}
    if not isinstance(summary, dict):
        summary = {}
    keys = [
        "Users",
        "Groups",
        "Roles",
        "Policies",
        "MFADevices",
        "AccountMFAEnabled",
    ]
    return {k: summary.get(k) for k in keys if k in summary}


def summarize_buckets(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    buckets = data.get("Buckets") or []
    names = []
    for bucket in buckets:
        if isinstance(bucket, dict) and bucket.get("Name"):
            names.append(bucket["Name"])
    return {"count": len(names), "sample_buckets": names[:20]}


def summarize_security_groups(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    groups = data.get("SecurityGroups") or []
    open_rules = 0
    for group in groups:
        if not isinstance(group, dict):
            continue
        perms = group.get("IpPermissions") or []
        for perm in perms:
            if not isinstance(perm, dict):
                continue
            ranges = perm.get("IpRanges") or []
            for rng in ranges:
                if isinstance(rng, dict) and rng.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                    open_rules += 1
                    break
    return {"count": len(groups), "open_inbound_rules": open_rules}


def summarize_instances(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    reservations = data.get("Reservations") or []
    instance_count = 0
    public_ips = 0
    for res in reservations:
        if not isinstance(res, dict):
            continue
        instances = res.get("Instances") or []
        for inst in instances:
            instance_count += 1
            if inst.get("PublicIpAddress"):
                public_ips += 1
    return {"count": instance_count, "public_ip_count": public_ips}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--caller", default="", help="Path to sts get-caller-identity JSON")
    parser.add_argument("--account", default="", help="Path to iam get-account-summary JSON")
    parser.add_argument("--buckets", default="", help="Path to s3api list-buckets JSON")
    parser.add_argument("--security-groups", default="", help="Path to describe-security-groups JSON")
    parser.add_argument("--instances", default="", help="Path to describe-instances JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output = {
        "caller": summarize_caller(_load_json(args.caller)),
        "account_summary": summarize_account_summary(_load_json(args.account)),
        "buckets": summarize_buckets(_load_json(args.buckets)),
        "security_groups": summarize_security_groups(_load_json(args.security_groups)),
        "instances": summarize_instances(_load_json(args.instances)),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

