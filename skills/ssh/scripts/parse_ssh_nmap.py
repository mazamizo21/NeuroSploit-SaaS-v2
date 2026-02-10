#!/usr/bin/env python3
"""Parse Nmap SSH script output into structured JSON."""

import argparse
import json
from typing import Dict, List, Any


def parse_nmap(text: str) -> Dict[str, Any]:
    algos: Dict[str, List[str]] = {}
    auth_methods: List[str] = []
    auth_required = None
    current_algo_key = None
    current_section = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "ssh2-enum-algos" in line:
            current_section = "algos"
            current_algo_key = None
            continue
        if "ssh-auth-methods" in line:
            current_section = "auth"
            current_algo_key = None
            continue
        if not line.startswith("|") and not line.startswith("|_"):
            continue
        cleaned = line.lstrip("|_").strip()
        if not cleaned:
            continue
        if current_section == "algos":
            if cleaned.endswith(":") and not cleaned.startswith("-"):
                current_algo_key = cleaned[:-1].strip()
                algos.setdefault(current_algo_key, [])
                continue
            if cleaned.startswith("kex_algorithms") or cleaned.startswith("server_host_key_algorithms"):
                parts = cleaned.split(":", 1)
                current_algo_key = parts[0].strip()
                algos.setdefault(current_algo_key, [])
                continue
            if cleaned.startswith("-") or cleaned.startswith("*"):
                value = cleaned.lstrip("-* ").strip()
                if current_algo_key:
                    algos[current_algo_key].append(value)
            else:
                if current_algo_key:
                    algos[current_algo_key].append(cleaned)
        elif current_section == "auth":
            low = cleaned.lower()
            if "supported authentication methods" in low:
                continue
            if "authentication required" in low:
                if ":" in cleaned:
                    auth_required = cleaned.split(":", 1)[1].strip()
                continue
            if cleaned:
                auth_methods.append(cleaned)

    return {
        "algorithms": algos,
        "auth_methods": auth_methods,
        "auth_required": auth_required,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to Nmap output file (-oN)")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = parse_nmap(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
