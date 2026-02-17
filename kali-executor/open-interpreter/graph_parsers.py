"""kali-executor/open-interpreter/graph_parsers.py

Parse tool output into knowledge graph updates.

Parsers cover the major pentest tools and create all ten node types:
    Target, Port, Service, Technology, Vulnerability, CVE,
    Exploit, Credential, Endpoint, MitreTechnique

Design goals:
    - Best-effort parsing only (never crash the agent).
    - Keep parsers small and independent.
    - Fail-open when output is unexpected.
    - Generic parsers (credentials, CVEs) run on ALL tool output.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared regex patterns
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# Common technology tokens found in banners / headers / scan output.
# Maps lowercase keyword → (display_name, category).
_TECH_SIGNATURES: Dict[str, Tuple[str, str]] = {
    "apache":       ("Apache",       "web-server"),
    "nginx":        ("nginx",        "web-server"),
    "iis":          ("IIS",          "web-server"),
    "lighttpd":     ("Lighttpd",     "web-server"),
    "caddy":        ("Caddy",        "web-server"),
    "tomcat":       ("Apache Tomcat","app-server"),
    "jetty":        ("Jetty",        "app-server"),
    "php":          ("PHP",          "language"),
    "python":       ("Python",       "language"),
    "node.js":      ("Node.js",      "language"),
    "nodejs":       ("Node.js",      "language"),
    "ruby":         ("Ruby",         "language"),
    "perl":         ("Perl",         "language"),
    "asp.net":      ("ASP.NET",      "framework"),
    "django":       ("Django",       "framework"),
    "flask":        ("Flask",        "framework"),
    "express":      ("Express",      "framework"),
    "rails":        ("Rails",        "framework"),
    "laravel":      ("Laravel",      "framework"),
    "spring":       ("Spring",       "framework"),
    "wordpress":    ("WordPress",    "cms"),
    "joomla":       ("Joomla",       "cms"),
    "drupal":       ("Drupal",       "cms"),
    "magento":      ("Magento",      "cms"),
    "openssh":      ("OpenSSH",      "service"),
    "openssl":      ("OpenSSL",      "crypto"),
    "proftpd":      ("ProFTPD",      "service"),
    "vsftpd":       ("vsftpd",       "service"),
    "mysql":        ("MySQL",        "database"),
    "mariadb":      ("MariaDB",      "database"),
    "postgresql":   ("PostgreSQL",   "database"),
    "mongodb":      ("MongoDB",      "database"),
    "redis":        ("Redis",        "database"),
    "memcached":    ("Memcached",    "database"),
    "elasticsearch":("Elasticsearch","database"),
    "samba":        ("Samba",        "service"),
    "jquery":       ("jQuery",       "library"),
    "bootstrap":    ("Bootstrap",    "library"),
    "react":        ("React",        "library"),
    "angular":      ("Angular",      "framework"),
    "vue":          ("Vue.js",       "framework"),
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK tool → technique mapping
# ---------------------------------------------------------------------------

TOOL_MITRE_MAP: Dict[str, List[Tuple[str, str, str]]] = {
    # (technique_id, technique_name, tactic)
    "nmap":          [("T1046", "Network Service Discovery", "discovery")],
    "masscan":       [("T1046", "Network Service Discovery", "discovery")],
    "nikto":         [("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance")],
    "whatweb":       [("T1592", "Gather Victim Host Information", "reconnaissance")],
    "wappalyzer":    [("T1592", "Gather Victim Host Information", "reconnaissance")],
    "gobuster":      [("T1083", "File and Directory Discovery", "discovery")],
    "ffuf":          [("T1083", "File and Directory Discovery", "discovery")],
    "dirb":          [("T1083", "File and Directory Discovery", "discovery")],
    "dirsearch":     [("T1083", "File and Directory Discovery", "discovery")],
    "feroxbuster":   [("T1083", "File and Directory Discovery", "discovery")],
    "wfuzz":         [("T1083", "File and Directory Discovery", "discovery")],
    "sqlmap":        [("T1190", "Exploit Public-Facing Application", "initial-access")],
    "hydra":         [("T1110", "Brute Force", "credential-access")],
    "medusa":        [("T1110", "Brute Force", "credential-access")],
    "john":          [("T1110.002", "Password Cracking", "credential-access")],
    "hashcat":       [("T1110.002", "Password Cracking", "credential-access")],
    "metasploit":    [("T1203", "Exploitation for Client Execution", "execution")],
    "msfconsole":    [("T1203", "Exploitation for Client Execution", "execution")],
    "wpscan":        [("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance")],
    "nuclei":        [("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance")],
    "searchsploit":  [("T1588.005", "Obtain Capabilities: Exploits", "resource-development")],
    "curl":          [("T1071.001", "Application Layer Protocol: Web", "command-and-control")],
    "wget":          [("T1071.001", "Application Layer Protocol: Web", "command-and-control")],
    "enum4linux":    [("T1087", "Account Discovery", "discovery")],
    "smbclient":     [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement")],
    "crackmapexec":  [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement")],
    "netexec":       [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement")],
    "responder":     [("T1557.001", "LLMNR/NBT-NS Poisoning", "credential-access")],
    "impacket":      [("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement")],
    "mimikatz":      [("T1003", "OS Credential Dumping", "credential-access")],
    "bloodhound":    [("T1087.002", "Domain Account Discovery", "discovery")],
    "certipy":       [("T1649", "Steal or Forge Authentication Certificates", "credential-access")],
    "chisel":        [("T1572", "Protocol Tunneling", "command-and-control")],
    "linpeas":       [("T1083", "File and Directory Discovery", "discovery")],
    "winpeas":       [("T1083", "File and Directory Discovery", "discovery")],
}


def _norm_tool(tool: str) -> str:
    """Normalize a tool name to a lowercase key."""
    t = str(tool or "").strip().lower()
    if not t:
        return ""
    if "/" in t:
        t = t.split("/")[-1]
    return t


def _extract_host_port_from_target(target: Optional[str]) -> Tuple[str, int]:
    """Best-effort extraction of (host, port) from a target string."""
    if not target:
        return ("", 0)
    t = str(target).strip()
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return (host, int(port))
    if t.count(":") == 1:
        left, right = t.split(":", 1)
        if right.isdigit():
            return (left, int(right))
        return (t, 0)
    return (t, 0)


def _extract_techs_from_banner(banner: str) -> List[Tuple[str, Optional[str], str]]:
    """Return list of (display_name, version_or_None, category) from a banner string."""
    if not banner:
        return []
    results = []
    banner_low = banner.lower()
    for keyword, (display, category) in _TECH_SIGNATURES.items():
        if keyword in banner_low:
            # Try to extract version: "Apache/2.4.41" or "PHP/7.4.3"
            ver = None
            pat = re.compile(
                re.escape(keyword) + r"[/ ]+(\d[\d.]+)",
                re.IGNORECASE,
            )
            m = pat.search(banner)
            if m:
                ver = m.group(1)
            results.append((display, ver, category))
    return results


# ===================================================================
# TOOL-SPECIFIC PARSERS
# ===================================================================

def parse_nmap_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse nmap output → Target, Port, Service, Technology nodes."""
    if not output or not kg:
        return

    try:
        blocks = re.split(r"^Nmap scan report for ", output, flags=re.M)
        for block in blocks[1:]:
            lines = block.splitlines()
            if not lines:
                continue

            header = lines[0].strip()
            body = "\n".join(lines[1:])

            # Header: "10.0.0.5" or "example.com (10.0.0.5)"
            ip = None
            hostname = None
            m = re.match(
                r"^(?P<host>\S+)(?:\s+\((?P<ip>\d+\.\d+\.\d+\.\d+)\))?$",
                header,
            )
            if m:
                host_str = m.group("host")
                ip = m.group("ip") or host_str
                if m.group("ip"):
                    hostname = host_str
            if not ip:
                continue

            os_info = None
            os_m = re.search(r"^OS details:\s*(.+)$", body, flags=re.M)
            if os_m:
                os_info = os_m.group(1).strip()[:200]

            try:
                kg.add_target(ip=ip, hostname=hostname, os_info=os_info)
            except Exception:
                pass

            # Port lines: "80/tcp open http Apache httpd 2.4.41"
            for pm in re.finditer(
                r"^(?P<port>\d+)/(?P<proto>\w+)\s+open\s+(?P<svc>\S+)"
                r"(?:\s+(?P<ver>.*))?$",
                body,
                flags=re.M,
            ):
                try:
                    port = int(pm.group("port"))
                    proto = pm.group("proto")
                    svc = pm.group("svc")
                    ver = (pm.group("ver") or "").strip()[:200]

                    kg.add_service(
                        host_ip=ip, port=port, protocol=proto,
                        name=svc, version=ver,
                    )

                    # Extract technologies from version banner
                    for tech_name, tech_ver, tech_cat in _extract_techs_from_banner(ver):
                        try:
                            kg.add_technology(
                                name=tech_name, version=tech_ver,
                                category=tech_cat,
                                target_ip=ip, port=port,
                            )
                        except Exception:
                            pass

                except Exception:
                    continue

            # Also extract techs from service version lines (nmap -sV)
            for sv_m in re.finditer(
                r"^(?P<port>\d+)/\w+\s+open\s+\S+\s+(?P<banner>.+)$",
                body,
                flags=re.M,
            ):
                banner = sv_m.group("banner").strip()
                port_num = int(sv_m.group("port"))
                for tech_name, tech_ver, tech_cat in _extract_techs_from_banner(banner):
                    try:
                        kg.add_technology(
                            name=tech_name, version=tech_ver,
                            category=tech_cat,
                            target_ip=ip, port=port_num,
                        )
                    except Exception:
                        pass

    except Exception as exc:
        logger.debug("parse_nmap_failed err=%s", exc)


def parse_nikto_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse nikto output → Vulnerability, Technology, Endpoint nodes."""
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        # Extract target from nikto header: "+ Target IP:   10.0.0.5"
        ip_m = re.search(r"^\+ Target IP:\s+(\S+)", output, re.M)
        if ip_m:
            host = ip_m.group(1)
        port_m = re.search(r"^\+ Target Port:\s+(\d+)", output, re.M)
        if port_m:
            port = int(port_m.group(1))

        if not host:
            return

        # Server header → Technology
        srv_m = re.search(r"^\+ Server:\s+(.+)$", output, re.M)
        if srv_m:
            server_banner = srv_m.group(1).strip()
            for tech_name, tech_ver, tech_cat in _extract_techs_from_banner(server_banner):
                try:
                    kg.add_technology(
                        name=tech_name, version=tech_ver,
                        category=tech_cat,
                        target_ip=host, port=port,
                    )
                except Exception:
                    pass

        # Nikto finding lines: "+ OSVDB-3092: /admin/: ..."
        # or: "+ /icons/: Directory listing found."
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue

            # OSVDB / vuln lines
            osvdb_m = re.match(
                r"^\+\s+(?:OSVDB-(\d+):\s+)?(/\S*?):\s+(.+)$", line,
            )
            if osvdb_m:
                path = osvdb_m.group(2)
                detail = osvdb_m.group(3).strip()
                osvdb_id = osvdb_m.group(1)

                # Record endpoint
                if path and port:
                    try:
                        kg.add_endpoint(
                            path=path, target_ip=host, port=port,
                        )
                    except Exception:
                        pass

                # Record vulnerability if it looks like one
                if osvdb_id or any(
                    kw in detail.lower()
                    for kw in ("vulnerab", "injection", "xss", "traversal",
                               "disclosure", "bypass", "overflow", "rce",
                               "remote code", "arbitrary", "default")
                ):
                    vuln_type = f"OSVDB-{osvdb_id}" if osvdb_id else detail[:80]
                    sev = "medium"
                    dl = detail.lower()
                    if any(k in dl for k in ("rce", "remote code", "arbitrary", "injection")):
                        sev = "high"
                    elif any(k in dl for k in ("xss", "traversal", "disclosure")):
                        sev = "medium"
                    elif "info" in dl or "default" in dl:
                        sev = "low"

                    cve = None
                    cve_m = _CVE_RE.search(detail)
                    if cve_m:
                        cve = cve_m.group(0).upper()

                    if port:
                        try:
                            kg.add_vulnerability(
                                host_ip=host, port=port,
                                vuln_type=vuln_type, cve=cve,
                                severity=sev, details=detail[:2000],
                            )
                        except Exception:
                            pass

                # Extract techs from detail text
                for tech_name, tech_ver, tech_cat in _extract_techs_from_banner(detail):
                    try:
                        kg.add_technology(
                            name=tech_name, version=tech_ver,
                            category=tech_cat,
                            target_ip=host, port=port,
                        )
                    except Exception:
                        pass

    except Exception as exc:
        logger.debug("parse_nikto_failed err=%s", exc)


def parse_whatweb_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse whatweb output → Technology nodes.

    WhatWeb format:
        http://10.0.0.5 [200 OK] Apache[2.4.41], PHP[7.4.3], ...
    """
    if not output or not kg:
        return

    try:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Extract URL + status
            url_m = re.match(r"^(https?://\S+)\s+\[([^\]]+)\](.*)$", line)
            if not url_m:
                continue

            url = url_m.group(1)
            remainder = url_m.group(3)

            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80

            if not host:
                continue

            # Parse technology tags: Tag[version], Tag, Tag[version]
            for tag_m in re.finditer(
                r"[\s,]+([A-Za-z][\w./-]+?)(?:\[([^\]]*)\])?(?=[\s,]|$)",
                remainder,
            ):
                tag_name = tag_m.group(1).strip()
                tag_ver = (tag_m.group(2) or "").strip() or None
                tag_low = tag_name.lower()

                # Map to known tech if possible
                matched = False
                for keyword, (display, category) in _TECH_SIGNATURES.items():
                    if keyword in tag_low:
                        try:
                            kg.add_technology(
                                name=display, version=tag_ver,
                                category=category,
                                target_ip=host, port=port,
                            )
                        except Exception:
                            pass
                        matched = True
                        break

                # Store unknown tech with generic category
                if not matched and len(tag_name) >= 2:
                    try:
                        kg.add_technology(
                            name=tag_name, version=tag_ver,
                            category="detected",
                            target_ip=host, port=port,
                        )
                    except Exception:
                        pass

    except Exception as exc:
        logger.debug("parse_whatweb_failed err=%s", exc)


def parse_gobuster_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse gobuster / dirb / dirsearch output → Endpoint nodes.

    Formats:
        gobuster: /admin (Status: 200) [Size: 1234]
        dirb:     + http://host/admin (CODE:200|SIZE:1234)
        dirsearch: 200 -  1234B  - /admin
        feroxbuster: 200  GET  1234l  /admin
    """
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            path = None
            status_code = None
            content_len = None

            # gobuster: "/admin (Status: 200) [Size: 1234]"
            gb_m = re.match(
                r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?",
                stripped,
            )
            if gb_m:
                path = gb_m.group(1)
                status_code = int(gb_m.group(2))
                if gb_m.group(3):
                    content_len = int(gb_m.group(3))

            # dirb: "+ http://host/admin (CODE:200|SIZE:1234)"
            if not path:
                dirb_m = re.match(
                    r"^\+\s+https?://[^/]+(/\S*)\s+\(CODE:(\d+)",
                    stripped,
                )
                if dirb_m:
                    path = dirb_m.group(1) or "/"
                    status_code = int(dirb_m.group(2))

            # dirsearch: "200 -  1234B  - /admin"
            if not path:
                ds_m = re.match(
                    r"^(\d{3})\s+[-]\s+\d+\S*\s+[-]\s+(/\S+)",
                    stripped,
                )
                if ds_m:
                    status_code = int(ds_m.group(1))
                    path = ds_m.group(2)

            # feroxbuster: "200  GET  1234l  123w  4567c http://host/admin"
            if not path:
                fb_m = re.match(
                    r"^(\d{3})\s+\w+\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+https?://[^/]+(/\S*)",
                    stripped,
                )
                if fb_m:
                    status_code = int(fb_m.group(1))
                    path = fb_m.group(2) or "/"

            # ffuf: "page  [Status: 200, Size: 1234, ...]"
            if not path:
                ffuf_m = re.match(
                    r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)",
                    stripped,
                )
                if ffuf_m:
                    word = ffuf_m.group(1)
                    path = "/" + word if not word.startswith("/") else word
                    status_code = int(ffuf_m.group(2))
                    content_len = int(ffuf_m.group(3))

            if path and host and port:
                # Skip non-interesting status codes
                if status_code and status_code in (400, 404, 405, 500, 502, 503):
                    continue
                try:
                    kg.add_endpoint(
                        path=path, target_ip=host, port=port,
                        method="GET", status_code=status_code,
                        content_length=content_len,
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("parse_gobuster_failed err=%s", exc)


# Alias: all dir-brute tools use the same parser
parse_dirb_output = parse_gobuster_output
parse_dirsearch_output = parse_gobuster_output
parse_feroxbuster_output = parse_gobuster_output
parse_ffuf_output = parse_gobuster_output
parse_wfuzz_output = parse_gobuster_output


def parse_sqlmap_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse sqlmap output → Vulnerability, Exploit nodes."""
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        if not host:
            # Try to find target from sqlmap output
            tgt_m = re.search(r"testing URL '(https?://\S+)'", output)
            if tgt_m:
                p = urlparse(tgt_m.group(1))
                host = p.hostname or ""
                port = p.port or (443 if p.scheme == "https" else 80)

        if not host:
            return

        # "Parameter: id (GET)" and injection type lines
        sqli_found = False
        for line in output.splitlines():
            stripped = line.strip()

            # "sqlmap identified the following injection point(s)"
            if "injection point" in stripped.lower():
                sqli_found = True

            # "Parameter: id (GET)"
            param_m = re.match(
                r"^Parameter:\s+(\S+)\s+\((\w+)\)", stripped,
            )
            if param_m and sqli_found:
                param_name = param_m.group(1)
                method = param_m.group(2)
                try:
                    kg.add_vulnerability(
                        host_ip=host, port=port,
                        vuln_type=f"SQL Injection ({method} {param_name})",
                        severity="high",
                        details=f"SQLi in parameter {param_name} via {method}",
                    )
                except Exception:
                    pass

            # "Type: boolean-based blind"
            type_m = re.match(r"^\s+Type:\s+(.+)$", stripped)
            if type_m and sqli_found:
                sqli_type = type_m.group(1).strip()
                try:
                    kg.add_vulnerability(
                        host_ip=host, port=port,
                        vuln_type=f"SQL Injection: {sqli_type}",
                        severity="high",
                        details=sqli_type,
                    )
                except Exception:
                    pass

        # Database/table dumps → check for credential patterns
        # "| admin | 5f4dcc3b5aa765d61d8327deb882cf99 |"
        for row_m in re.finditer(
            r"^\|\s+(\S+)\s+\|\s+([a-fA-F0-9]{32,})\s+\|",
            output,
            re.M,
        ):
            username = row_m.group(1)
            hash_val = row_m.group(2)
            if username and len(username) < 60 and not username.startswith("-"):
                try:
                    kg.add_credential(
                        username=username, hash_value=hash_val,
                        source="sqlmap_dump",
                        host_ip=host, service_port=port,
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("parse_sqlmap_failed err=%s", exc)


def parse_hydra_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse hydra / medusa output → Credential nodes.

    Hydra format: [80][http-get] host: 10.0.0.5   login: admin   password: pass123
    """
    if not output or not kg:
        return

    try:
        for line in output.splitlines():
            stripped = line.strip()

            # hydra: "[80][http-get] host: 10.0.0.5   login: admin   password: secret"
            hyd_m = re.match(
                r"^\[(\d+)\]\[\S+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                stripped,
            )
            if hyd_m:
                h_port = int(hyd_m.group(1))
                h_host = hyd_m.group(2)
                h_user = hyd_m.group(3)
                h_pass = hyd_m.group(4)
                try:
                    kg.add_credential(
                        username=h_user, password=h_pass,
                        source="hydra",
                        host_ip=h_host, service_port=h_port,
                    )
                except Exception:
                    pass
                continue

            # medusa: "ACCOUNT FOUND: [http] Host: 10.0.0.5 User: admin Password: pass [SUCCESS]"
            med_m = re.match(
                r"^ACCOUNT FOUND:\s+\[\S+\]\s+Host:\s+(\S+)\s+"
                r"User:\s+(\S+)\s+Password:\s+(\S+)",
                stripped,
            )
            if med_m:
                m_host = med_m.group(1)
                m_user = med_m.group(2)
                m_pass = med_m.group(3)
                h, p = _extract_host_port_from_target(target)
                try:
                    kg.add_credential(
                        username=m_user, password=m_pass,
                        source="medusa",
                        host_ip=m_host or h, service_port=p or 0,
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("parse_hydra_failed err=%s", exc)

# Alias
parse_medusa_output = parse_hydra_output


def parse_wpscan_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse wpscan output → Technology, Vulnerability, Endpoint nodes."""
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        if not host:
            url_m = re.search(r"URL:\s+(https?://\S+)", output)
            if url_m:
                p = urlparse(url_m.group(1))
                host = p.hostname or ""
                port = p.port or (443 if p.scheme == "https" else 80)
        if not host:
            return

        # WordPress version: "[+] WordPress version X.Y.Z"
        wp_m = re.search(r"WordPress version\s+([\d.]+)", output)
        if wp_m:
            try:
                kg.add_technology(
                    name="WordPress", version=wp_m.group(1),
                    category="cms", target_ip=host, port=port,
                )
            except Exception:
                pass

        # Themes/plugins: "[i] Plugin: contact-form-7" or "Name: plugin-name"
        for plug_m in re.finditer(
            r"(?:Plugin|Theme)(?:\sIdentified)?:\s+(\S+)", output, re.I,
        ):
            name = plug_m.group(1).strip().rstrip(",")
            if name and len(name) > 1:
                try:
                    kg.add_technology(
                        name=f"wp-{name}", category="plugin",
                        target_ip=host, port=port,
                    )
                except Exception:
                    pass

        # Vulnerabilities: "| [!] Title: ..."
        for vuln_m in re.finditer(
            r"^\s*\|\s+\[!\]\s+Title:\s+(.+)$", output, re.M,
        ):
            title = vuln_m.group(1).strip()[:200]
            cve = None
            cve_m = _CVE_RE.search(title)
            if cve_m:
                cve = cve_m.group(0).upper()
            try:
                kg.add_vulnerability(
                    host_ip=host, port=port,
                    vuln_type=title, cve=cve,
                    severity="medium",
                    details=title,
                )
            except Exception:
                pass

        # Endpoints found
        for ep_m in re.finditer(r"(https?://\S+)", output):
            try:
                ep_url = ep_m.group(1)
                ep_parsed = urlparse(ep_url)
                if ep_parsed.hostname == host and ep_parsed.path:
                    kg.add_endpoint(
                        path=ep_parsed.path,
                        target_ip=host, port=port,
                    )
            except Exception:
                pass

    except Exception as exc:
        logger.debug("parse_wpscan_failed err=%s", exc)


def parse_nuclei_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse nuclei output → Vulnerability, CVE nodes."""
    if not output or not kg:
        return

    try:
        for raw in output.splitlines():
            line = (raw or "").strip()
            if not line.startswith("["):
                continue

            # [template-id] [severity] [protocol] URL [matched-at]
            m = re.match(
                r"^\[(?P<template>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]"
                r"\s+\[(?P<proto>[^\]]+)\]\s+(?P<url>\S+)",
                line,
            )
            if not m:
                continue

            template_id = m.group("template").strip()[:120]
            severity = m.group("severity").strip().lower()[:32]
            url = m.group("url").strip()

            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                host, _ = _extract_host_port_from_target(target)
            if not host:
                continue

            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80

            cve = None
            cve_m = _CVE_RE.search(template_id) or _CVE_RE.search(line)
            if cve_m:
                cve = cve_m.group(0).upper()

            if port > 0:
                try:
                    kg.add_vulnerability(
                        host_ip=host, port=int(port),
                        vuln_type=template_id, cve=cve,
                        severity=severity, details=line[:2000],
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("parse_nuclei_failed err=%s", exc)


def parse_metasploit_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse msfconsole output → detect session opens, loot, creds."""
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        # Meterpreter / shell session opened
        # "[*] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:41232)"
        for sess_m in re.finditer(
            r"session\s+\d+\s+opened\s+\([\d.]+:\d+\s*->\s*([\d.]+):(\d+)\)",
            output, re.I,
        ):
            s_host = sess_m.group(1)
            s_port = int(sess_m.group(2))
            try:
                kg.add_target(ip=s_host)
            except Exception:
                pass

        # Credential extraction from msf output
        # "[+] 10.0.0.5:445 - admin:password123"
        for cred_m in re.finditer(
            r"^\[\+\]\s+([\d.]+):(\d+)\s+-\s+(\S+):(\S+)",
            output, re.M,
        ):
            c_host = cred_m.group(1)
            c_port = int(cred_m.group(2))
            c_user = cred_m.group(3)
            c_pass = cred_m.group(4)
            try:
                kg.add_credential(
                    username=c_user, password=c_pass,
                    source="metasploit",
                    host_ip=c_host, service_port=c_port,
                )
            except Exception:
                pass

    except Exception as exc:
        logger.debug("parse_metasploit_failed err=%s", exc)


def parse_searchsploit_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse searchsploit output → extract CVE references."""
    if not output or not kg:
        return

    try:
        for cve_m in _CVE_RE.finditer(output):
            try:
                kg.add_cve(cve_id=cve_m.group(0).upper())
            except Exception:
                pass
    except Exception as exc:
        logger.debug("parse_searchsploit_failed err=%s", exc)


def parse_enum4linux_output(output: str, kg: Any, target: Optional[str] = None) -> None:
    """Parse enum4linux output → Target, Technology, Credential nodes."""
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    try:
        # Target IP from output
        ip_m = re.search(r"Target\s*:\s*([\d.]+)", output)
        if ip_m:
            host = ip_m.group(1)

        if not host:
            return

        # OS info
        os_m = re.search(r"OS\s+info.*?:\s*(.+)", output, re.I)
        if os_m:
            try:
                kg.add_target(ip=host, os_info=os_m.group(1).strip()[:200])
            except Exception:
                pass

        # Samba version
        smb_m = re.search(r"Samba\s+([\d.]+)", output)
        if smb_m:
            try:
                kg.add_technology(
                    name="Samba", version=smb_m.group(1),
                    category="service",
                    target_ip=host, port=port or 445,
                )
            except Exception:
                pass

        # User accounts: "user:[username] rid:[0x...]"
        for user_m in re.finditer(r"user:\[([^\]]+)\]", output):
            uname = user_m.group(1).strip()
            if uname and len(uname) < 100:
                try:
                    kg.add_credential(
                        username=uname, source="enum4linux",
                        host_ip=host, service_port=port or 445,
                    )
                except Exception:
                    pass

    except Exception as exc:
        logger.debug("parse_enum4linux_failed err=%s", exc)


# ===================================================================
# GENERIC PARSERS (run on all output)
# ===================================================================

def _parse_generic_credentials(output: str, kg: Any,
                               target: Optional[str] = None) -> None:
    """Best-effort extraction of credentials from any tool output.

    Patterns matched:
        - /etc/passwd lines: root:x:0:0:root:/root:/bin/bash
        - /etc/shadow lines: root:$6$salt$hash:...
        - Generic user:pass in credential dump tables
    """
    if not output or not kg:
        return

    host, port = _extract_host_port_from_target(target)

    # /etc/shadow hashes
    for shadow_m in re.finditer(
        r"^([a-zA-Z0-9._-]+):(\$\w+\$[^\s:]+)", output, re.M,
    ):
        username = shadow_m.group(1)
        hash_val = shadow_m.group(2)
        if username and len(username) < 80:
            try:
                kg.add_credential(
                    username=username, hash_value=hash_val,
                    source="shadow_dump",
                    host_ip=host or None,
                    service_port=port or None,
                )
            except Exception:
                pass

    # /etc/passwd entries with shell
    for passwd_m in re.finditer(
        r"^([a-zA-Z0-9._-]+):x:\d+:\d+:[^:]*:[^:]*:(/\S+)$",
        output, re.M,
    ):
        username = passwd_m.group(1)
        shell = passwd_m.group(2)
        # Only record users with actual login shells
        if shell and not shell.endswith(("nologin", "false", "sync")):
            try:
                kg.add_credential(
                    username=username, source="passwd_file",
                    host_ip=host or None,
                    service_port=port or None,
                )
            except Exception:
                pass


def _parse_generic_cves(output: str, kg: Any) -> None:
    """Extract CVE references from any output and create CVE nodes."""
    if not output or not kg:
        return

    seen = set()
    for cve_m in _CVE_RE.finditer(output):
        cve_id = cve_m.group(0).upper()
        if cve_id not in seen:
            seen.add(cve_id)
            try:
                kg.add_cve(cve_id=cve_id)
            except Exception:
                pass


def record_mitre_for_tool(tool: str, kg: Any) -> None:
    """Record MITRE ATT&CK technique nodes for a given tool name."""
    t = _norm_tool(tool)
    if not t or not kg:
        return

    techniques = TOOL_MITRE_MAP.get(t, [])
    for tech_id, tech_name, tactic in techniques:
        try:
            kg.add_mitre_technique(
                technique_id=tech_id,
                name=tech_name,
                tactic=tactic,
            )
        except Exception:
            pass


# ===================================================================
# TOOL PARSER REGISTRY
# ===================================================================

TOOL_PARSERS: Dict[str, Callable[[str, Any, Optional[str]], None]] = {
    "nmap":         parse_nmap_output,
    "masscan":      parse_nmap_output,       # similar enough format
    "nikto":        parse_nikto_output,
    "whatweb":      parse_whatweb_output,
    "gobuster":     parse_gobuster_output,
    "dirb":         parse_dirb_output,
    "dirsearch":    parse_dirsearch_output,
    "feroxbuster":  parse_feroxbuster_output,
    "ffuf":         parse_ffuf_output,
    "wfuzz":        parse_wfuzz_output,
    "sqlmap":       parse_sqlmap_output,
    "hydra":        parse_hydra_output,
    "medusa":       parse_medusa_output,
    "wpscan":       parse_wpscan_output,
    "nuclei":       parse_nuclei_output,
    "msfconsole":   parse_metasploit_output,
    "metasploit":   parse_metasploit_output,
    "searchsploit": parse_searchsploit_output,
    "enum4linux":   parse_enum4linux_output,
    "enum4linux-ng": parse_enum4linux_output,
}


def auto_parse(tool: str, output: str, kg: Any,
               target: Optional[str] = None) -> None:
    """Auto-detect tool and parse output into the knowledge graph.

    Runs:
        1. MITRE technique recording for the tool.
        2. Tool-specific parser (if registered).
        3. Generic credential extraction (all tools).
        4. Generic CVE extraction (all tools).
    """
    t = _norm_tool(tool)
    if not t or not output or not kg:
        return

    # 1) Record MITRE techniques for this tool
    try:
        record_mitre_for_tool(t, kg)
    except Exception:
        pass

    # 2) Tool-specific parser
    parser = TOOL_PARSERS.get(t)
    if parser:
        try:
            parser(output, kg, target)
        except Exception as exc:
            logger.debug("kg_auto_parse_failed tool=%s err=%s", t, exc)

    # 3) Generic credential extraction (all tools)
    try:
        _parse_generic_credentials(output, kg, target)
    except Exception:
        pass

    # 4) Generic CVE extraction (all tools)
    try:
        _parse_generic_cves(output, kg)
    except Exception:
        pass
