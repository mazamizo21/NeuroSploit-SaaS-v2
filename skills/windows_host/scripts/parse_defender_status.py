#!/usr/bin/env python3
"""Parse Defender status JSON into a concise summary."""

import argparse
import json
from typing import Any, Dict

KEYS = [
    "AMServiceEnabled",
    "AntispywareEnabled",
    "AntivirusEnabled",
    "BehaviorMonitorEnabled",
    "RealTimeProtectionEnabled",
    "IsTamperProtected",
    "NISEnabled",
    "OnAccessProtectionEnabled",
    "QuickScanAge",
    "FullScanAge",
    "EngineVersion",
    "AntivirusSignatureVersion",
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to Defender JSON (Get-MpComputerStatus | ConvertTo-Json)")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        data: Dict[str, Any] = json.load(f)

    summary = {key: data.get(key) for key in KEYS if key in data}
    summary["raw_keys"] = sorted(list(data.keys()))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


if __name__ == "__main__":
    main()
