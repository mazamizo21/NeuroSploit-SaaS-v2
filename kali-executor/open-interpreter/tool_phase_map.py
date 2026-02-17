"""kali-executor/open-interpreter/tool_phase_map.py

Sprint 1: Tool -> phase allowlist.

Design goals:
- Hard-block *known* pentest tools outside their allowed phases.
- Fail-open for unknown commands (custom scripts / shell one-liners) to avoid
  breaking the agent runtime.
- Support automatic map enrichment from the skills metadata (`skills/*/tools.yaml`).

Phases used here align with the DynamicAgent internal phase gate:
  RECON -> VULN_DISCOVERY -> EXPLOITATION -> [C2_DEPLOY] -> POST_EXPLOIT
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)


INTERNAL_PHASES: List[str] = [
    "RECON",
    "VULN_DISCOVERY",
    "EXPLOITATION",
    "C2_DEPLOY",
    "POST_EXPLOIT",
]


# Tools we never want phase-gated (core utilities / pseudo-tools).
# If we accidentally gate these, the agent will death-loop.
ALWAYS_ALLOWED_TOOLS: Set[str] = {
    "bash",
    "sh",
    "python",
    "python3",
    "curl",
    "wget",
    "websearch",
    "docslookup",
}


# Curated baseline map for high-impact tools.
# This list is intentionally conservative; skills-derived tools can extend it.
DEFAULT_TOOL_PHASE_MAP: Dict[str, List[str]] = {
    # Recon / scanning tools — also allowed in POST_EXPLOIT to discover new attack surface
    "nmap": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "masscan": ["RECON", "VULN_DISCOVERY"],
    "nikto": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "whatweb": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "nuclei": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "subfinder": ["RECON"],
    "sublist3r": ["RECON"],
    "amass": ["RECON"],
    "assetfinder": ["RECON"],
    "fierce": ["RECON"],
    "dnsrecon": ["RECON"],
    "dnsenum": ["RECON"],
    "dmitry": ["RECON"],
    "theharvester": ["RECON"],
    "recon-ng": ["RECON"],

    # Enumeration tools — allowed through exploitation and post-exploit for deeper discovery
    "gobuster": ["RECON", "VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT"],
    "ffuf": ["RECON", "VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT"],
    "wfuzz": ["RECON", "VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT"],
    "dirb": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "dirsearch": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],
    "feroxbuster": ["RECON", "VULN_DISCOVERY", "POST_EXPLOIT"],

    # CVE correlation / exploit discovery
    "searchsploit": ["RECON", "VULN_DISCOVERY", "EXPLOITATION"],

    # Exploitation tooling
    "sqlmap": ["VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT"],
    "msfconsole": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msfvenom": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msfdb": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msfrpc": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msfrpcd": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msfupdate": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "msf6": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "meterpreter": ["C2_DEPLOY", "POST_EXPLOIT"],
    "hydra": ["VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT"],
    "medusa": ["VULN_DISCOVERY", "EXPLOITATION"],
    "commix": ["VULN_DISCOVERY", "EXPLOITATION"],

    # ── Metasploit Post-Exploitation Modules ──────────────────────
    # These are logical tool names derived from Metasploit module paths.
    # The agent may emit these as tool hints when classifying msfconsole commands.

    # Credential Harvesting (post/windows/gather/*)
    "hashdump": ["POST_EXPLOIT"],
    "smart_hashdump": ["POST_EXPLOIT"],
    "cachedump": ["POST_EXPLOIT"],
    "lsa_secrets": ["POST_EXPLOIT"],
    "mimikatz": ["POST_EXPLOIT"],
    "kiwi": ["POST_EXPLOIT"],
    "credential_collector": ["POST_EXPLOIT"],

    # Privilege Escalation (exploit/windows/local/*, post/multi/recon/*)
    "getsystem": ["POST_EXPLOIT"],
    "local_exploit_suggester": ["POST_EXPLOIT"],
    "bypassuac": ["POST_EXPLOIT"],
    "bypassuac_eventvwr": ["POST_EXPLOIT"],
    "bypassuac_fodhelper": ["POST_EXPLOIT"],
    "bypassuac_comhijack": ["POST_EXPLOIT"],
    "bypassuac_sdclt": ["POST_EXPLOIT"],
    "bypassuac_silentcleanup": ["POST_EXPLOIT"],
    "juicy_potato": ["POST_EXPLOIT"],
    "printspoofer": ["POST_EXPLOIT"],
    "godpotato": ["POST_EXPLOIT"],
    "sweetpotato": ["POST_EXPLOIT"],
    "pwnkit": ["POST_EXPLOIT"],

    # Token Manipulation (incognito)
    "incognito": ["POST_EXPLOIT"],
    "impersonate_token": ["POST_EXPLOIT"],
    "steal_token": ["POST_EXPLOIT"],

    # Pivoting & Tunneling
    "autoroute": ["POST_EXPLOIT"],
    "socks_proxy": ["POST_EXPLOIT"],
    "portfwd": ["POST_EXPLOIT"],
    "proxychains": ["POST_EXPLOIT"],
    "proxychains4": ["POST_EXPLOIT"],

    # Persistence (post/windows/manage/persistence_*, exploit/windows/local/persistence_*)
    "persistence_exe": ["POST_EXPLOIT"],
    "persistence_service": ["POST_EXPLOIT"],
    "schtasks_exec": ["POST_EXPLOIT"],
    "registry_persistence": ["POST_EXPLOIT"],
    "sshkey_persistence": ["POST_EXPLOIT"],
    "enable_rdp": ["POST_EXPLOIT"],

    # Lateral / post-exploit toolchain
    "crackmapexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "netexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "evil-winrm": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-psexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-wmiexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-smbexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-atexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-dcomexec": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-mssqlclient": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-secretsdump": ["POST_EXPLOIT"],
    "impacket-ntlmrelayx": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-getST": ["POST_EXPLOIT"],
    "impacket-getTGT": ["POST_EXPLOIT"],
    "impacket-GetNPUsers": ["EXPLOITATION", "POST_EXPLOIT"],
    "impacket-GetUserSPNs": ["EXPLOITATION", "POST_EXPLOIT"],

    # AD post-exploitation tools
    "bloodhound": ["POST_EXPLOIT"],
    "sharphound": ["POST_EXPLOIT"],
    "rubeus": ["POST_EXPLOIT"],
    "certipy": ["POST_EXPLOIT"],
    "pywhisker": ["POST_EXPLOIT"],
    "ldapdomaindump": ["POST_EXPLOIT"],
    "adidnsdump": ["POST_EXPLOIT"],

    # Windows post-exploitation tools
    "winpeas": ["POST_EXPLOIT"],
    "linpeas": ["POST_EXPLOIT"],
    "seatbelt": ["POST_EXPLOIT"],
    "sharpup": ["POST_EXPLOIT"],
    "powerup": ["POST_EXPLOIT"],
    "powerview": ["POST_EXPLOIT"],
    "pypykatz": ["POST_EXPLOIT"],
    "nanodump": ["POST_EXPLOIT"],
    "procdump": ["POST_EXPLOIT"],

    # Shell access
    "nc": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "netcat": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "socat": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "ssh": ["EXPLOITATION", "POST_EXPLOIT"],
    "scp": ["POST_EXPLOIT"],

    # Empire C2 (post-exploitation)
    "powershell-empire": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "empire": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "starkiller": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],

    # OWASP ZAP (web scanning — recon through exploitation)
    "zap": ["RECON", "VULN_DISCOVERY", "EXPLOITATION"],
    "zaproxy": ["RECON", "VULN_DISCOVERY", "EXPLOITATION"],
    "zap.sh": ["RECON", "VULN_DISCOVERY", "EXPLOITATION"],

    # BeEF (browser exploitation)
    "beef": ["EXPLOITATION", "POST_EXPLOIT"],
    "beef-xss": ["EXPLOITATION", "POST_EXPLOIT"],

    # Sliver C2 (full lifecycle: implant gen → deploy → post-exploit)
    "sliver": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "sliver-client": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "sliver-server": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],

    # Sliver helper scripts (TazoSploit automation wrappers)
    "generate_implant": ["EXPLOITATION", "C2_DEPLOY"],
    "generate_implant.py": ["EXPLOITATION", "C2_DEPLOY"],
    "deliver_payload": ["EXPLOITATION", "C2_DEPLOY"],
    "deliver_payload.py": ["EXPLOITATION", "C2_DEPLOY"],
    "verify_callback": ["C2_DEPLOY", "POST_EXPLOIT"],
    "verify_callback.py": ["C2_DEPLOY", "POST_EXPLOIT"],
    "c2_post_exploit": ["POST_EXPLOIT"],
    "c2_post_exploit.py": ["POST_EXPLOIT"],
    "evasion_pipeline": ["EXPLOITATION", "C2_DEPLOY"],
    "evasion_pipeline.py": ["EXPLOITATION", "C2_DEPLOY"],

    # Evasion toolchain (Donut / ScareCrow / pre-flight)
    "scarecrow": ["EXPLOITATION", "C2_DEPLOY"],
    "donut": ["EXPLOITATION", "C2_DEPLOY"],
    "threatcheck": ["EXPLOITATION", "C2_DEPLOY"],
    "defendercheck": ["EXPLOITATION", "C2_DEPLOY"],

    # BOF/.NET assembly tools (executed through Sliver sessions)
    "sharpdpapi": ["POST_EXPLOIT"],
    "sharpchromium": ["POST_EXPLOIT"],
    "sharpkatz": ["POST_EXPLOIT"],
    "sharppersist": ["POST_EXPLOIT"],
    "adsearch": ["POST_EXPLOIT"],
    "standin": ["POST_EXPLOIT"],
    "sharpgpoabuse": ["POST_EXPLOIT"],
    "sharpbypassuac": ["POST_EXPLOIT"],
    "sharpdllproxy": ["POST_EXPLOIT"],
    "sharpwifi": ["POST_EXPLOIT"],

    # Pivoting / tunneling tools
    "chisel": ["EXPLOITATION", "POST_EXPLOIT"],
    "ligolo": ["POST_EXPLOIT"],
    "ligolo-ng": ["POST_EXPLOIT"],

    # Linux post-exploit enumeration
    "linpeas.sh": ["POST_EXPLOIT"],
    "pspy": ["POST_EXPLOIT"],

    # Mythic C2 (post-exploitation)
    "mythic": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "mythic-cli": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
    "mythic_c2.py": ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"],
}


def normalize_tool_name(name: str) -> str:
    return str(name or "").strip().lower()


def _filter_known_phases(phases: Iterable[str]) -> List[str]:
    allowed_set = {p for p in INTERNAL_PHASES}
    out: List[str] = []
    for p in phases:
        pn = str(p or "").strip().upper()
        if pn in allowed_set and pn not in out:
            out.append(pn)
    # Preserve INTERNAL_PHASES ordering for deterministic outputs.
    out.sort(key=lambda p: INTERNAL_PHASES.index(p) if p in INTERNAL_PHASES else 999)
    return out


def is_tool_allowed(tool_name: str, phase: str, tool_phase_map: Optional[Dict[str, List[str]]] = None,
                     job_phase: str = "") -> bool:
    # FULL job phase = all tools allowed (multi-target needs recon + exploit + post-exploit)
    if str(job_phase or "").strip().upper() == "FULL":
        return True

    tool = normalize_tool_name(tool_name)
    if not tool:
        return True
    if tool in ALWAYS_ALLOWED_TOOLS:
        return True

    phase_norm = str(phase or "").strip().upper()
    mapping = tool_phase_map or DEFAULT_TOOL_PHASE_MAP
    allowed = mapping.get(tool)
    if allowed is None:
        # Unknown tool: fail-open.
        return True
    return phase_norm in {p.upper() for p in allowed}


def get_blocked_reason(tool_name: str, phase: str, tool_phase_map: Optional[Dict[str, List[str]]] = None) -> str:
    tool = normalize_tool_name(tool_name)
    if not tool:
        return ""
    if tool in ALWAYS_ALLOWED_TOOLS:
        return ""

    phase_norm = str(phase or "").strip().upper()
    mapping = tool_phase_map or DEFAULT_TOOL_PHASE_MAP
    allowed = mapping.get(tool)
    if allowed is None:
        return ""
    allowed_norm = _filter_known_phases(allowed)
    if phase_norm in allowed_norm:
        return ""

    return (
        f"⛔ BLOCKED TOOL: '{tool}' is not allowed in phase={phase_norm}. "
        f"Allowed phases: {', '.join(allowed_norm) or '(none)'}. "
        "Pick a different tool/technique appropriate for this phase."
    )


def _skill_phase_to_internal_phases(skill_phase: str) -> List[str]:
    p = str(skill_phase or "").strip().upper()
    if not p:
        return []
    if p == "RECON":
        return ["RECON"]
    if p in ("VULN_SCAN", "VULN_DISCOVERY"):
        return ["RECON", "VULN_DISCOVERY"]
    if p in ("EXPLOIT", "EXPLOITATION"):
        return ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"]
    if p in ("POST_EXPLOIT", "LATERAL"):
        return ["POST_EXPLOIT"]
    if p == "FULL":
        return list(INTERNAL_PHASES)
    if p == "REPORT":
        return ["POST_EXPLOIT"]
    return []


def _category_to_internal_phases(category: str) -> List[str]:
    c = str(category or "").strip().lower()
    if not c:
        return []
    if c in ("recon", "reconnaissance", "dns"):
        return ["RECON"]
    if c in ("scanning", "scan"):
        return ["RECON", "VULN_DISCOVERY"]
    if c in ("exploitation", "exploit", "xss", "sql_injection"):
        return ["EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT"]
    if c in (
        "credential_access",
        "privilege_escalation",
        "lateral_movement",
        "persistence",
        "defense_evasion",
        "discovery",
        "collection",
        "exfiltration",
        "impact",
        "analysis",
        "reporting",
    ):
        return ["POST_EXPLOIT"]
    return []


def build_tool_phase_map_from_skills(skills_dir: str) -> Dict[str, List[str]]:
    """Best-effort tool->phase map derived from skills metadata.

    We scan immediate child directories for `skill.yaml` and/or `tools.yaml`.

    The derived map is used to *extend* DEFAULT_TOOL_PHASE_MAP; curated overrides
    remain authoritative.
    """

    if not skills_dir:
        return {}
    if not os.path.isdir(skills_dir):
        return {}

    try:
        import yaml  # type: ignore
    except Exception:
        return {}

    derived: Dict[str, Set[str]] = {}

    for entry in sorted(os.listdir(skills_dir)):
        if entry in {"__pycache__", "toolcards"}:
            continue
        skill_path = os.path.join(skills_dir, entry)
        if not os.path.isdir(skill_path):
            continue

        meta = {}
        phase = ""
        category = ""
        skill_yaml = os.path.join(skill_path, "skill.yaml")
        if os.path.isfile(skill_yaml):
            try:
                with open(skill_yaml, "r") as f:
                    meta = yaml.safe_load(f) or {}
                phase = str(meta.get("phase") or "").strip()
                category = str(meta.get("category") or "").strip()
            except Exception:
                meta = {}

        phases = _skill_phase_to_internal_phases(phase)
        if not phases:
            phases = _category_to_internal_phases(category)
        if not phases:
            continue

        tool_names: Set[str] = set()

        tools_yaml = os.path.join(skill_path, "tools.yaml")
        if os.path.isfile(tools_yaml):
            try:
                with open(tools_yaml, "r") as f:
                    tools_doc = yaml.safe_load(f) or {}
                if isinstance(tools_doc, dict):
                    tool_names.update([str(k) for k in tools_doc.keys()])
            except Exception:
                pass

        # Some skills store a simple list under `tools:` in skill.yaml.
        try:
            meta_tools = meta.get("tools")
            if isinstance(meta_tools, list):
                for t in meta_tools:
                    if isinstance(t, str) and t.strip():
                        tool_names.add(t.strip())
        except Exception:
            pass

        for tool in tool_names:
            norm = normalize_tool_name(tool)
            if not norm or norm in ALWAYS_ALLOWED_TOOLS:
                continue
            derived.setdefault(norm, set()).update({p.upper() for p in phases})

    return {t: _filter_known_phases(phs) for t, phs in derived.items() if phs}


def build_effective_tool_phase_map(skills_dir: str) -> Dict[str, List[str]]:
    """Build the final tool->phase map (skills-derived + curated overrides)."""

    derived = {}
    try:
        derived = build_tool_phase_map_from_skills(skills_dir)
    except Exception as exc:
        logger.warning("tool_phase_map_build_failed skills_dir=%s error=%s", skills_dir, exc)
        derived = {}

    # Curated overrides win (do not broaden phases for high-impact tools).
    merged = dict(derived)
    merged.update(DEFAULT_TOOL_PHASE_MAP)

    # Ensure values are normalized and deterministic.
    for tool, phases in list(merged.items()):
        merged[tool] = _filter_known_phases(phases)

    return merged
