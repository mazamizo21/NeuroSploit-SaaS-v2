#!/usr/bin/env python3
"""Parse airodump-ng CSV output into a structured JSON inventory."""

import argparse
import csv
import json
from typing import Dict, List, Tuple


def _split_sections(lines: List[str]) -> Tuple[List[str], List[str]]:
    try:
        blank_index = lines.index("")
    except ValueError:
        return lines, []
    return lines[:blank_index], lines[blank_index + 1 :]


def parse_airodump_csv(path: str) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    access_points: List[Dict[str, str]] = []
    stations: List[Dict[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    ap_lines, station_lines = _split_sections(lines)
    if not ap_lines:
        return access_points, stations

    reader = csv.reader(ap_lines)
    rows = list(reader)
    if not rows:
        return access_points, stations

    header = [h.strip().lower() for h in rows[0]]
    for row in rows[1:]:
        if not row or len(row) < len(header):
            continue
        record = {header[i]: row[i].strip() for i in range(len(header))}
        access_points.append({
            "bssid": record.get("bssid"),
            "channel": record.get("channel"),
            "privacy": record.get("privacy"),
            "cipher": record.get("cipher"),
            "authentication": record.get("authentication"),
            "power": record.get("power"),
            "ssid": record.get("essid"),
        })

    if station_lines:
        station_reader = csv.reader(station_lines)
        station_rows = list(station_reader)
        if station_rows:
            station_header = [h.strip().lower() for h in station_rows[0]]
            for row in station_rows[1:]:
                if not row or len(row) < len(station_header):
                    continue
                record = {station_header[i]: row[i].strip() for i in range(len(station_header))}
                stations.append({
                    "station_mac": record.get("station mac"),
                    "bssid": record.get("bssid"),
                    "power": record.get("power"),
                    "probed_essids": record.get("probed essids"),
                })

    return access_points, stations


def summarize_access_points(access_points: List[Dict[str, str]]) -> Dict[str, int]:
    summary = {
        "total": 0,
        "open": 0,
        "wep": 0,
        "wpa2": 0,
        "wpa3": 0,
        "wps": 0,
    }
    for ap in access_points:
        summary["total"] += 1
        privacy = (ap.get("privacy") or "").upper()
        if "OPN" in privacy or "OPEN" in privacy:
            summary["open"] += 1
        if "WEP" in privacy:
            summary["wep"] += 1
        if "WPA3" in privacy:
            summary["wpa3"] += 1
        elif "WPA2" in privacy or "WPA" in privacy:
            summary["wpa2"] += 1
        if "WPS" in privacy:
            summary["wps"] += 1
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", required=True, help="Path to airodump CSV")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    aps, stations = parse_airodump_csv(args.csv)
    output = {
        "access_points": aps,
        "stations": stations,
        "summary": summarize_access_points(aps),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
