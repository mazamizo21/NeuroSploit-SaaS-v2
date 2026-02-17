"""kali-executor/open-interpreter/graph_parsers.py

Sprint 2: Parse tool output into knowledge graph updates.

Design goals:
- Best-effort parsing only (never crash the agent).
- Keep parsers small and independent.
- Fail-open when output is unexpected.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _norm_tool(tool: str) -> str:
    t = str(tool or "").strip().lower()
    if not t:
        return ""
    if "/" in t:
        t = t.split("/")[-1]
    return t


def parse_nmap_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse nmap output and add Host/Service nodes."""

    if not output or not kg:
        return

    try:
        # Split into host blocks to support multi-host scans.
        blocks = re.split(r"^Nmap scan report for ", output, flags=re.M)
        for block in blocks[1:]:
            lines = block.splitlines()
            if not lines:
                continue

            header = lines[0].strip()
            body = "\n".join(lines[1:])

            # Header forms:
            # - "10.0.0.5"
            # - "example.com (10.0.0.5)"
            ip = None
            hostname = None
            m = re.match(r"^(?P<host>\S+)(?:\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\))?$", header)
            if m:
                host = m.group("host")
                ip = m.group("ip") or host
                if m.group("ip"):
                    hostname = host

            if not ip:
                continue

            os_info = None
            os_m = re.search(r"^OS details:\s*(.+)$", body, flags=re.M)
            if os_m:
                os_info = os_m.group(1).strip()[:200]

            try:
                kg.add_host(ip=ip, hostname=hostname, os_info=os_info)
            except Exception:
                pass

            # Typical port line: "80/tcp open http Apache httpd 2.4.41"
            for pm in re.finditer(
                r"^(?P<port>\d+)\/(?P<proto>\w+)\s+open\s+(?P<svc>\S+)(?:\s+(?P<ver>.*))?$",
                body,
                flags=re.M,
            ):
                try:
                    port = int(pm.group("port"))
                    proto = pm.group("proto")
                    svc = pm.group("svc")
                    ver = (pm.group("ver") or "").strip()[:200]
                    kg.add_service(host_ip=ip, port=port, protocol=proto, name=svc, version=ver)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("parse_nmap_failed err=%s", exc)


def parse_nuclei_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse nuclei output and add Vulnerability nodes."""

    if not output or not kg:
        return

    try:
        for raw in output.splitlines():
            line = (raw or "").strip()
            if not line.startswith("["):
                continue

            # Common format:
            # [template-id] [severity] [protocol] URL [matched-at]
            m = re.match(r"^\[(?P<template>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+\[(?P<proto>[^\]]+)\]\s+(?P<url>\S+)", line)
            if not m:
                continue

            template_id = m.group("template").strip()[:120]
            severity = m.group("severity").strip().lower()[:32]
            url = m.group("url").strip()

            parsed = urlparse(url)
            host = parsed.hostname or (str(target or "").strip() or None)
            if not host:
                continue

            port = parsed.port
            if not port:
                if parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80
                else:
                    port = 0

            cve = None
            cve_m = _CVE_RE.search(template_id) or _CVE_RE.search(line)
            if cve_m:
                cve = cve_m.group(0).upper()

            if port > 0:
                try:
                    kg.add_vulnerability(
                        host_ip=host,
                        port=int(port),
                        vuln_type=template_id,
                        cve=cve,
                        severity=severity,
                        details=line[:2000],
                    )
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("parse_nuclei_failed err=%s", exc)


TOOL_PARSERS: Dict[str, Callable[[str, Any, Optional[str]], None]] = {
    "nmap": parse_nmap_output,
    "nuclei": parse_nuclei_output,
}


def auto_parse(tool: str, output: str, kg: Any, target: Optional[str] = None) -> None:
    """Auto-detect tool and parse output into KG."""

    t = _norm_tool(tool)
    if not t or not output or not kg:
        return

    parser = TOOL_PARSERS.get(t)
    if not parser:
        return

    try:
        parser(output, kg, target)
    except Exception as exc:
        logger.debug("kg_auto_parse_failed tool=%s err=%s", t, exc)
