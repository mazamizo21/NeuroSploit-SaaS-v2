#!/usr/bin/env python3
"""Summarize lateral movement logs by extracting hosts and outcomes."""

import argparse
import json
import re
from typing import Dict, List


IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]{1,253}\b")


def summarize(text: str) -> Dict[str, object]:
    hosts = set()
    ips = set()
    successes = 0
    failures = 0
    for line in text.splitlines():
        low = line.lower()
        for ip in IP_RE.findall(line):
            ips.add(ip)
        for host in HOST_RE.findall(line):
            if "." in host and not host.endswith("."):
                hosts.add(host)
        if "success" in low or "authenticated" in low:
            successes += 1
        if "failed" in low or "denied" in low:
            failures += 1
    return {
        "hosts": sorted(hosts)[:50],
        "ips": sorted(ips)[:50],
        "success_events": successes,
        "failure_events": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to movement log output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    output = summarize(raw)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
