#!/usr/bin/env python3
"""Parse ldapsearch LDIF output into a structured JSON summary."""

import argparse
import base64
import json
from typing import Dict, List, Any


def _decode_value(value: str) -> str:
    value = value.strip()
    try:
        decoded = base64.b64decode(value).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return value


def parse_ldif(text: str) -> List[Dict[str, List[str]]]:
    entries: List[Dict[str, List[str]]] = []
    current: Dict[str, List[str]] = {}
    last_key = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            if current:
                entries.append(current)
                current = {}
            last_key = None
            continue
        if line.startswith("#"):
            continue
        if line.startswith(" ") and last_key:
            current[last_key][-1] = current[last_key][-1] + line[1:]
            continue
        if "::" in line:
            key, value = line.split("::", 1)
            key = key.strip()
            val = _decode_value(value)
        elif ":" in line:
            key, value = line.split(":", 1)
            key = key.strip()
            val = value.strip()
        else:
            continue
        current.setdefault(key, []).append(val)
        last_key = key

    if current:
        entries.append(current)
    return entries


def summarize_rootdse(entry: Dict[str, List[str]]) -> Dict[str, Any]:
    def first(key: str) -> str:
        vals = entry.get(key, [])
        return vals[0] if vals else ""

    return {
        "default_naming_context": first("defaultNamingContext"),
        "naming_contexts": entry.get("namingContexts", []),
        "supported_ldap_versions": entry.get("supportedLDAPVersion", []),
        "supported_sasl_mechanisms": entry.get("supportedSASLMechanisms", []),
        "supported_controls": entry.get("supportedControl", []),
        "supported_capabilities": entry.get("supportedCapabilities", []),
        "vendor_name": first("vendorName"),
        "vendor_version": first("vendorVersion"),
        "dns_host_name": first("dnsHostName"),
        "server_name": first("serverName"),
        "ldap_service_name": first("ldapServiceName"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ldif", required=True, help="Path to ldapsearch LDIF output")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.ldif, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    entries = parse_ldif(raw)
    rootdse = summarize_rootdse(entries[0]) if entries else {}

    output = {
        "entries_count": len(entries),
        "rootdse": rootdse,
        "raw": entries[0] if entries else {},
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

