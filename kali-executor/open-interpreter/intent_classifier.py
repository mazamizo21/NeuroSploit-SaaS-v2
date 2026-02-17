"""
Natural-language intent classifier for TazoSploit jobs.

Converts chat-style requests into structured job configuration.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


TARGET_PATTERNS = [
    re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"\b((?:https?://)?[\w.-]+\.[a-zA-Z]{2,}(?::\d{1,5})?(?:/\S*)?)\b"),
]

CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

SERVICE_KEYWORDS = {
    "ssh": ["ssh", "openssh", "port 22"],
    "http": ["http", "https", "web", "apache", "nginx", "port 80", "port 443", "port 8080"],
    "smb": ["smb", "samba", "cifs", "port 445"],
    "rdp": ["rdp", "remote desktop", "port 3389"],
    "ftp": ["ftp", "port 21"],
    "mysql": ["mysql", "mariadb", "port 3306"],
    "mssql": ["mssql", "sql server", "port 1433"],
    "postgres": ["postgres", "postgresql", "port 5432"],
    "redis": ["redis", "port 6379"],
}

EXPLOIT_KEYWORDS = {
    "exploit",
    "attack",
    "pwn",
    "hack",
    "compromise",
    "shell",
    "rce",
    "remote code execution",
}

BRUTE_KEYWORDS = {
    "brute",
    "password",
    "credential",
    "wordlist",
    "spray",
    "hydra",
    "guess",
}

RECON_KEYWORDS = {
    "scan",
    "enumerate",
    "discover",
    "recon",
    "reconnaissance",
    "ports",
    "services",
}


class IntentClassification(BaseModel):
    target: Optional[str] = Field(default=None)
    phase: str = Field(default="FULL")
    attack_type: str = Field(default="general")
    objective: str = Field(default="")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    detected_service: Optional[str] = Field(default=None)
    detected_cve: Optional[str] = Field(default=None)
    reasoning: str = Field(default="")


def _extract_target(text: str) -> Optional[str]:
    for pattern in TARGET_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        candidate = match.group(1)
        if candidate.lower().startswith("http"):
            return candidate.rstrip("/.,")
        return candidate
    return None


def _detect_service(text_lower: str) -> Optional[str]:
    for service, keywords in SERVICE_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return service
    return None


def classify_fast(text: str) -> IntentClassification:
    source = (text or "").strip()
    lowered = source.lower()

    result = IntentClassification(objective=source)
    result.target = _extract_target(source)
    result.detected_service = _detect_service(lowered)

    cve_match = CVE_PATTERN.search(source)
    if cve_match:
        result.detected_cve = cve_match.group(1).upper()
        result.attack_type = "cve_exploit"
        result.phase = "EXPLOIT"
        result.confidence = 0.95
        result.reasoning = "Detected explicit CVE reference"
        return result

    if any(kw in lowered for kw in BRUTE_KEYWORDS):
        result.attack_type = "brute_force"
        result.phase = "EXPLOIT"
        result.confidence = 0.88
        result.reasoning = "Detected credential attack intent"
        return result

    if any(kw in lowered for kw in EXPLOIT_KEYWORDS):
        result.attack_type = "general"
        result.phase = "EXPLOIT"
        result.confidence = 0.82
        result.reasoning = "Detected exploitation intent"
        return result

    if any(kw in lowered for kw in RECON_KEYWORDS):
        result.attack_type = "general"
        result.phase = "RECON"
        result.confidence = 0.8
        result.reasoning = "Detected reconnaissance intent"
        return result

    result.phase = "FULL"
    result.attack_type = "general"
    result.confidence = 0.5
    result.reasoning = "No strong signal; default full assessment"
    return result


def build_job_config_from_intent(classification: IntentClassification) -> Dict[str, object]:
    target_list: List[str] = [classification.target] if classification.target else []

    config: Dict[str, object] = {
        "targets": target_list,
        "phase": classification.phase,
        "objective": classification.objective,
        "attack_type": classification.attack_type,
        "detected_service": classification.detected_service,
        "detected_cve": classification.detected_cve,
    }

    overrides: Dict[str, object] = {}
    if classification.attack_type == "brute_force" and classification.detected_service:
        overrides["BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS"] = 3

    if classification.detected_cve:
        overrides["EXPLOITATION_SYSTEM_PROMPT"] = (
            f"Prioritize exploiting {classification.detected_cve}; collect concrete proof artifacts."
        )

    config["settings_overrides"] = overrides
    return config
