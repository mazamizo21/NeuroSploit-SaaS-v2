#!/usr/bin/env python3
"""Merge Linux host evidence JSON files into a single posture summary."""

import argparse
import json
from typing import Dict, Any


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", help="Linux host inventory JSON")
    parser.add_argument("--firewall", help="Firewall status JSON")
    parser.add_argument("--auditd", help="Auditd status JSON")
    parser.add_argument("--sshd", help="SSHD effective config JSON")
    parser.add_argument("--sudoers", help="Sudoers JSON")
    parser.add_argument("--cron", help="Cron entries JSON")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    output: Dict[str, Any] = {
        "inventory": load_json(args.inventory) if args.inventory else None,
        "firewall_status": load_json(args.firewall) if args.firewall else None,
        "auditd_status": load_json(args.auditd) if args.auditd else None,
        "sshd_effective": load_json(args.sshd) if args.sshd else None,
        "sudoers": load_json(args.sudoers) if args.sudoers else None,
        "cron": load_json(args.cron) if args.cron else None,
    }

    if output.get("sudoers") and "count" in output["sudoers"]:
        output["sudoers_count"] = output["sudoers"]["count"]
    if output.get("cron") and "count" in output["cron"]:
        output["cron_count"] = output["cron"]["count"]

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
