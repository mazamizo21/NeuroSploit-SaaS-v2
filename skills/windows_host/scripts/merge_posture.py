#!/usr/bin/env python3
"""Merge Windows host evidence JSON files into a single posture summary."""

import argparse
import json
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", help="Windows host inventory JSON")
    parser.add_argument("--defender", help="Defender status JSON")
    parser.add_argument("--firewall", help="Firewall profiles JSON")
    parser.add_argument("--audit", help="Audit policy JSON")
    parser.add_argument("--tasks", help="Scheduled tasks JSON")
    parser.add_argument("--autoruns", help="Autoruns JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output: Dict[str, Any] = {
        "inventory": load_json(args.inventory) if args.inventory else None,
        "defender": load_json(args.defender) if args.defender else None,
        "firewall_profiles": load_json(args.firewall) if args.firewall else None,
        "audit_policy": load_json(args.audit) if args.audit else None,
        "scheduled_tasks": load_json(args.tasks) if args.tasks else None,
        "autoruns": load_json(args.autoruns) if args.autoruns else None,
    }

    # Add lightweight counts to help downstream reporting
    if output.get("scheduled_tasks") and "count" in output["scheduled_tasks"]:
        output["scheduled_tasks_count"] = output["scheduled_tasks"]["count"]
    if output.get("autoruns") and "count" in output["autoruns"]:
        output["autoruns_count"] = output["autoruns"]["count"]
    if output.get("audit_policy") and "total" in output["audit_policy"]:
        output["audit_policy_count"] = output["audit_policy"]["total"]

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
