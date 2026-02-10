#!/usr/bin/env python3
"""Parse Windows systeminfo/whoami outputs into a structured JSON summary."""

import argparse
import json
import re
from typing import Dict, List, Optional


def parse_systeminfo(text: str) -> Dict[str, str]:
    data: Dict[str, str] = {}
    hotfixes: List[str] = []
    lines = [line.rstrip() for line in text.splitlines()]
    in_hotfixes = False
    for line in lines:
        if not line.strip():
            continue
        if re.match(r"^Hotfix\(s\):", line):
            in_hotfixes = True
            # Capture count if present
            parts = line.split(":", 1)
            if len(parts) == 2:
                data["hotfix_count"] = parts[1].strip()
            continue
        if in_hotfixes:
            if ":" in line and line.lstrip().startswith("["):
                _, value = line.split(":", 1)
                val = value.strip()
                if val:
                    hotfixes.append(val)
                continue
            # End hotfix section if a new key appears
            if re.match(r"^[A-Za-z].*:", line):
                in_hotfixes = False
            else:
                continue
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()

    if hotfixes:
        data["hotfixes"] = hotfixes
    return data


def parse_whoami(text: str) -> Optional[str]:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--systeminfo", required=True, help="Path to systeminfo.txt")
    parser.add_argument("--whoami", help="Path to whoami.txt")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.systeminfo, "r", encoding="utf-8", errors="ignore") as f:
        sysinfo_text = f.read()

    sysinfo = parse_systeminfo(sysinfo_text)
    username = None
    if args.whoami:
        with open(args.whoami, "r", encoding="utf-8", errors="ignore") as f:
            username = parse_whoami(f.read())

    output = {
        "os_name": sysinfo.get("OS Name"),
        "os_version": sysinfo.get("OS Version"),
        "system_type": sysinfo.get("System Type"),
        "system_model": sysinfo.get("System Model"),
        "manufacturer": sysinfo.get("System Manufacturer"),
        "domain": sysinfo.get("Domain"),
        "timezone": sysinfo.get("Time Zone"),
        "hotfix_count": sysinfo.get("hotfix_count"),
        "hotfixes": sysinfo.get("hotfixes", []),
        "username": username,
        "raw": sysinfo,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
