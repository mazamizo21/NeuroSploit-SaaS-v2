#!/usr/bin/env python3
"""Parse HTTP response headers into a structured JSON summary."""

import argparse
import json
from typing import Dict, List

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]


def parse_headers(text: str) -> Dict[str, List[str]]:
    headers: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if not line or line.lower().startswith("http/"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        headers.setdefault(key, []).append(value)
    return headers


def parse_cookies(headers: Dict[str, List[str]]):
    cookies = []
    for cookie in headers.get("set-cookie", []):
        parts = [p.strip() for p in cookie.split(";")]
        name_value = parts[0] if parts else ""
        flags = {"secure": False, "httponly": False, "samesite": None}
        for part in parts[1:]:
            low = part.lower()
            if low == "secure":
                flags["secure"] = True
            elif low == "httponly":
                flags["httponly"] = True
            elif low.startswith("samesite="):
                flags["samesite"] = part.split("=", 1)[1]
        cookies.append({"cookie": name_value, **flags})
    return cookies


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--headers", required=True, help="Path to raw headers file")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.headers, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    headers = parse_headers(raw)
    security = {k: headers.get(k) for k in SECURITY_HEADERS if k in headers}
    cookies = parse_cookies(headers)

    output = {
        "security_headers": security,
        "cookies": cookies,
        "raw_headers": headers,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
