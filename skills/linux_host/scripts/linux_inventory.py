#!/usr/bin/env python3
"""Parse basic Linux host inventory outputs into JSON."""

import argparse
import json
from typing import Dict, Optional


def read_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().strip()


def parse_lsb(text: Optional[str]) -> Dict[str, str]:
    data: Dict[str, str] = {}
    if not text:
        return data
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--uname", required=True, help="Path to uname.txt")
    parser.add_argument("--lsb", help="Path to lsb_release.txt")
    parser.add_argument("--id", help="Path to id.txt")
    parser.add_argument("--sudo", help="Path to sudo.txt")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    uname_out = read_file(args.uname)
    lsb_out = read_file(args.lsb)
    id_out = read_file(args.id)
    sudo_out = read_file(args.sudo)

    lsb = parse_lsb(lsb_out)

    output = {
        "kernel": uname_out,
        "distribution": lsb.get("Distributor ID"),
        "release": lsb.get("Release"),
        "codename": lsb.get("Codename"),
        "description": lsb.get("Description"),
        "user_identity": id_out,
        "sudo_privileges": sudo_out,
        "raw": {
            "lsb_release": lsb,
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
