"""
LLM Agent Profiles — Controls how strict/loose the pentest agent behaves.

Usage:
    Set LLM_PROFILE env var to one of: strict, balanced, relaxed, unleashed
    Or set AGENT_FREEDOM env var to a number 1-10 (maps to profiles automatically)
    Individual env vars still override profile defaults.
    
Freedom Scale:
    1-2  = strict   (tight leash, fast models, keyword-obedient)
    3-4  = balanced  (moderate gates, good for capable models like Sonnet)  
    5-6  = relaxed   (loose gates, trust model judgment, good for Opus-class)
    7-8  = unleashed (minimal gates, maximum model freedom)
    9-10 = unhinged  (almost no restrictions, full trust, experimental)
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("tazosploit.profiles")

# ─── Profile Definitions ───────────────────────────────────────────────────

PROFILES: Dict[str, Dict[str, Any]] = {
    "strict": {
        # Best for: GLM 4.7, Qwen, fast/cheap models that follow instructions literally
        # Philosophy: Don't trust the model. Force exploitation. Block everything else.
        "description": "Tight leash — forces exploitation, blocks enumeration aggressively",
        "freedom_range": (1, 2),
        
        # ── Exploit Gate ──
        "ENFORCE_EXPLOITATION_GATE": "true",
        "ENFORCE_EXPLOITATION_PROOF": "true",
        "EXPLOIT_ONLY_HARD": "true",
        "EXPLOITATION_GATE_COOLDOWN_ITERS": "3",         # Push exploit every 3 iters
        "EXPLOITATION_GATE_MAX_REPROMPTS": "2",           # Fail-open after 2 blocks (non-proof mode)
        "EXPLOITATION_GATE_HARD_RESET_AFTER": "4",        # Reset context after 4 blocks
        "EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN": "5",
        "EXPLOITATION_PROOF_FAIL_MODE": "skip",
        
        # ── Command Classification ──
        "CLASSIFY_CURL_STRICT": "true",       # curl without injection = enum (current behavior)
        "CLASSIFY_AUTH_CURL_AS_EXPLOIT": "false",  # auth curls still = enum
        
        # ── Token Control ──
        "LLM_MAX_COMPLETION_TOKENS": "768",
        "LLM_MIN_COMPLETION_TOKENS": "128",
        "EXPLOIT_MODE_TOKEN_CAP": "512",      # Very tight cap during exploit gate
        
        # ── Context ──
        "MAX_CONTEXT_MESSAGES": "30",
        "MAX_CONTEXT_CHARS": "12000",
        "MAX_DIGEST_CHARS": "2000",
        
        # ── Iteration Control ──
        "AUTO_COMPLETE_IDLE_ITERATIONS": "15",
        "COUNT_BLOCKED_AS_ITERATION": "true",  # Blocked = iteration (burns through faster)
        "MAX_GATE_MESSAGES_IN_CONTEXT": "10",  # Allow many gate messages
        
        # ── Scan/Redundancy ──
        "BLOCK_REDUNDANT_EXPLOITS": "true",
        "REDUNDANT_EXPLOIT_STRICTNESS": "high",  # Block similar variations
        
        # ── Output ──
        "MAX_STDOUT_CHARS": "600",
        "MAX_STDERR_CHARS": "300",
        "MAX_FEEDBACK_CHARS": "1200",
        "GATE_MESSAGE_VERBOSITY": "full",     # Full templates + arsenal suggestions
        
        # ── Temperature ──
        "LLM_TEMPERATURE": "0.2",
    },

    "balanced": {
        # Best for: Claude Sonnet 4.5, GPT-4o — capable models that mostly follow instructions
        # Philosophy: Guide the model but don't strangle it. Current production defaults.
        "description": "Moderate gates — guides exploitation while allowing strategic enumeration",
        "freedom_range": (3, 4),
        
        # ── Exploit Gate ──
        "ENFORCE_EXPLOITATION_GATE": "true",
        "ENFORCE_EXPLOITATION_PROOF": "true",
        "EXPLOIT_ONLY_HARD": "true",
        "EXPLOITATION_GATE_COOLDOWN_ITERS": "5",
        "EXPLOITATION_GATE_MAX_REPROMPTS": "3",
        "EXPLOITATION_GATE_HARD_RESET_AFTER": "6",
        "EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN": "5",
        "EXPLOITATION_PROOF_FAIL_MODE": "skip",
        
        # ── Command Classification ──
        "CLASSIFY_CURL_STRICT": "true",
        "CLASSIFY_AUTH_CURL_AS_EXPLOIT": "true",  # Auth curls = exploit
        
        # ── Token Control ──
        "LLM_MAX_COMPLETION_TOKENS": "1024",
        "LLM_MIN_COMPLETION_TOKENS": "256",
        "EXPLOIT_MODE_TOKEN_CAP": "768",
        
        # ── Context ──
        "MAX_CONTEXT_MESSAGES": "40",
        "MAX_CONTEXT_CHARS": "14000",
        "MAX_DIGEST_CHARS": "2500",
        
        # ── Iteration Control ──
        "AUTO_COMPLETE_IDLE_ITERATIONS": "20",
        "COUNT_BLOCKED_AS_ITERATION": "true",
        "MAX_GATE_MESSAGES_IN_CONTEXT": "5",
        
        # ── Scan/Redundancy ──
        "BLOCK_REDUNDANT_EXPLOITS": "true",
        "REDUNDANT_EXPLOIT_STRICTNESS": "medium",  # Allow flag variations
        
        # ── Output ──
        "MAX_STDOUT_CHARS": "800",
        "MAX_STDERR_CHARS": "400",
        "MAX_FEEDBACK_CHARS": "1500",
        "GATE_MESSAGE_VERBOSITY": "normal",
        
        # ── Temperature ──
        "LLM_TEMPERATURE": "0.3",
    },

    "relaxed": {
        # Best for: Claude Opus 4.6, Claude 3.5 Opus — reasoning models that need room to think
        # Philosophy: Trust the model's judgment. Guide gently. Let it enumerate when it wants.
        "description": "Loose gates — trusts model judgment, allows strategic enumeration",
        "freedom_range": (5, 6),
        
        # ── Exploit Gate ──
        "ENFORCE_EXPLOITATION_GATE": "true",   # Still on, but much more lenient
        "ENFORCE_EXPLOITATION_PROOF": "true",
        "EXPLOIT_ONLY_HARD": "false",          # ← KEY: Disable hard exploit-only mode
        "EXPLOITATION_GATE_COOLDOWN_ITERS": "10",  # Push exploit only every 10 iters
        "EXPLOITATION_GATE_MAX_REPROMPTS": "5",     # More patience before giving up
        "EXPLOITATION_GATE_HARD_RESET_AFTER": "12", # Much more patience before context reset
        "EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN": "8",
        "EXPLOITATION_PROOF_FAIL_MODE": "skip",
        
        # ── Command Classification ──
        "CLASSIFY_CURL_STRICT": "false",       # ← KEY: curl = context-aware (not always enum)
        "CLASSIFY_AUTH_CURL_AS_EXPLOIT": "true",
        
        # ── Token Control ──
        "LLM_MAX_COMPLETION_TOKENS": "2048",   # Let it think more
        "LLM_MIN_COMPLETION_TOKENS": "256",
        "EXPLOIT_MODE_TOKEN_CAP": "1536",      # Higher cap during exploit gate
        
        # ── Context ──
        "MAX_CONTEXT_MESSAGES": "50",
        "MAX_CONTEXT_CHARS": "18000",
        "MAX_DIGEST_CHARS": "3500",
        
        # ── Iteration Control ──
        "AUTO_COMPLETE_IDLE_ITERATIONS": "30",
        "COUNT_BLOCKED_AS_ITERATION": "false",  # ← KEY: Don't waste iterations on blocks
        "MAX_GATE_MESSAGES_IN_CONTEXT": "3",    # Fewer gate messages polluting context
        
        # ── Scan/Redundancy ──
        "BLOCK_REDUNDANT_EXPLOITS": "true",
        "REDUNDANT_EXPLOIT_STRICTNESS": "low",  # Allow most variations through
        
        # ── Output ──
        "MAX_STDOUT_CHARS": "1200",
        "MAX_STDERR_CHARS": "600",
        "MAX_FEEDBACK_CHARS": "2000",
        "GATE_MESSAGE_VERBOSITY": "minimal",   # Short gate messages
        
        # ── Temperature ──
        "LLM_TEMPERATURE": "0.4",
    },

    "unleashed": {
        # Best for: Testing raw model capability without infrastructure interference
        # Philosophy: Get out of the model's way. Minimal guardrails. Let it cook.
        "description": "Minimal gates — maximum model freedom, near-zero interference",
        "freedom_range": (7, 8),
        
        # ── Exploit Gate ──
        "ENFORCE_EXPLOITATION_GATE": "false",  # ← OFF: No forced exploitation
        "ENFORCE_EXPLOITATION_PROOF": "false",  # No proof requirements
        "EXPLOIT_ONLY_HARD": "false",
        "EXPLOITATION_GATE_COOLDOWN_ITERS": "999",
        "EXPLOITATION_GATE_MAX_REPROMPTS": "0",
        "EXPLOITATION_GATE_HARD_RESET_AFTER": "999",
        "EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN": "20",
        "EXPLOITATION_PROOF_FAIL_MODE": "continue",
        
        # ── Command Classification ──
        "CLASSIFY_CURL_STRICT": "false",
        "CLASSIFY_AUTH_CURL_AS_EXPLOIT": "true",
        
        # ── Token Control ──
        "LLM_MAX_COMPLETION_TOKENS": "4096",
        "LLM_MIN_COMPLETION_TOKENS": "256",
        "EXPLOIT_MODE_TOKEN_CAP": "4096",
        
        # ── Context ──
        "MAX_CONTEXT_MESSAGES": "60",
        "MAX_CONTEXT_CHARS": "20000",
        "MAX_DIGEST_CHARS": "4000",
        
        # ── Iteration Control ──
        "AUTO_COMPLETE_IDLE_ITERATIONS": "50",
        "COUNT_BLOCKED_AS_ITERATION": "false",
        "MAX_GATE_MESSAGES_IN_CONTEXT": "2",
        
        # ── Scan/Redundancy ──
        "BLOCK_REDUNDANT_EXPLOITS": "false",   # Let model decide
        "REDUNDANT_EXPLOIT_STRICTNESS": "off",
        
        # ── Output ──
        "MAX_STDOUT_CHARS": "2000",
        "MAX_STDERR_CHARS": "1000",
        "MAX_FEEDBACK_CHARS": "3000",
        "GATE_MESSAGE_VERBOSITY": "none",
        
        # ── Temperature ──
        "LLM_TEMPERATURE": "0.5",
    },

    "unhinged": {
        # For: Absolute max freedom. No gates. No blocks. No restrictions.
        # Philosophy: Zero infrastructure interference. Pure model capability test.
        "description": "No restrictions — pure model capability test, zero interference",
        "freedom_range": (9, 10),
        
        # ── Everything OFF ──
        "ENFORCE_EXPLOITATION_GATE": "false",
        "ENFORCE_EXPLOITATION_PROOF": "false",
        "EXPLOIT_ONLY_HARD": "false",
        "EXPLOITATION_GATE_COOLDOWN_ITERS": "99999",
        "EXPLOITATION_GATE_MAX_REPROMPTS": "0",
        "EXPLOITATION_GATE_HARD_RESET_AFTER": "99999",
        "EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN": "99999",
        "EXPLOITATION_PROOF_FAIL_MODE": "continue",
        
        "CLASSIFY_CURL_STRICT": "false",
        "CLASSIFY_AUTH_CURL_AS_EXPLOIT": "true",
        
        "LLM_MAX_COMPLETION_TOKENS": "8192",
        "LLM_MIN_COMPLETION_TOKENS": "256",
        "EXPLOIT_MODE_TOKEN_CAP": "8192",
        
        "MAX_CONTEXT_MESSAGES": "80",
        "MAX_CONTEXT_CHARS": "24000",
        "MAX_DIGEST_CHARS": "5000",
        
        "AUTO_COMPLETE_IDLE_ITERATIONS": "100",
        "COUNT_BLOCKED_AS_ITERATION": "false",
        "MAX_GATE_MESSAGES_IN_CONTEXT": "1",
        
        "BLOCK_REDUNDANT_EXPLOITS": "false",
        "REDUNDANT_EXPLOIT_STRICTNESS": "off",
        
        "MAX_STDOUT_CHARS": "3000",
        "MAX_STDERR_CHARS": "1500",
        "MAX_FEEDBACK_CHARS": "4000",
        "GATE_MESSAGE_VERBOSITY": "none",
        
        "LLM_TEMPERATURE": "0.6",
    },
}

# ─── Auto-Profile by Model Name ──────────────────────────────────────────

MODEL_PROFILE_MAP = {
    # Reasoning-heavy models → relaxed (trust their judgment)
    "claude-opus-4-6": "relaxed",
    "claude-opus-4-5": "relaxed",
    "claude-opus": "relaxed",
    "claude-3-opus": "relaxed",
    "gpt-5.2": "relaxed",
    "gpt-5.1": "relaxed",
    "gpt-5": "relaxed",
    "o1": "relaxed",
    "o3": "relaxed",
    "deepseek-r1": "relaxed",
    "kimi-k2.5": "relaxed",          # K2.5 is strong enough for relaxed
    "kimi-k2-thinking": "relaxed",
    "qwen3-max-thinking": "relaxed",
    "gemini-3-pro": "relaxed",
    "glm-5": "balanced",             # GLM-5 is capable but not Opus-tier
    
    # Capable models → balanced (guide but don't strangle)
    "claude-sonnet-4": "balanced",
    "claude-sonnet": "balanced",
    "claude-4": "balanced",
    "gpt-4.1": "balanced",
    "gpt-4o": "balanced",
    "gpt-4-turbo": "balanced",
    "gemini-3-flash": "balanced",
    "gemini-2": "balanced",
    "deepseek-v3": "balanced",
    "kimi-k2": "balanced",           # K2 base is mid-tier
    "minimax-m2": "balanced",
    "glm-4.7": "balanced",           # GLM-4.7 upgraded to balanced (good at agentic)
    
    # Fast/cheap models → strict (prescriptive, step-by-step)
    "claude-haiku": "strict",
    "gpt-5-mini": "strict",
    "gpt-5-nano": "strict",
    "gpt-4o-mini": "strict",
    "gpt-4.1-mini": "strict",
    "gpt-4.1-nano": "strict",
    "gpt-3.5": "strict",
    "glm-4.7-flash": "strict",
    "glm-4.6": "strict",
    "glm-4.5": "strict",
    "glm-4-9b": "strict",
    "qwen3-coder-next": "strict",    # MoE 3B active — needs tight leash
    "qwen": "strict",
    "llama-3.3-70b": "strict",
    "llama": "strict",
    "mistral": "strict",
    "phi": "strict",
    "gemma": "strict",
    "olmo": "strict",
}


def _freedom_to_profile(freedom: int) -> str:
    """Map freedom level (1-10) to profile name."""
    if freedom <= 2:
        return "strict"
    elif freedom <= 4:
        return "balanced"
    elif freedom <= 6:
        return "relaxed"
    elif freedom <= 8:
        return "unleashed"
    else:
        return "unhinged"


def _detect_profile_for_model(model: str) -> Optional[str]:
    """Auto-detect profile based on model name."""
    model_lower = (model or "").lower()
    for pattern, profile in MODEL_PROFILE_MAP.items():
        if pattern in model_lower:
            return profile
    return None


def resolve_profile() -> Dict[str, Any]:
    """
    Resolve the active LLM profile. Priority:
    1. LLM_PROFILE env var (explicit profile name)
    2. AGENT_FREEDOM env var (1-10 scale → profile)
    3. Auto-detect from LLM_MODEL
    4. Default: balanced
    
    Individual env vars ALWAYS override profile defaults.
    """
    # Step 1: Check explicit profile
    explicit_profile = os.getenv("LLM_PROFILE", "").strip().lower()
    
    # Step 2: Check freedom level
    freedom_str = os.getenv("AGENT_FREEDOM", "").strip()
    freedom_level = None
    if freedom_str:
        try:
            freedom_level = max(1, min(10, int(freedom_str)))
        except ValueError:
            pass
    
    # Step 3: Auto-detect from model
    model = os.getenv("LLM_MODEL", "")
    auto_profile = _detect_profile_for_model(model)
    
    # Resolve: explicit > freedom > auto > default
    if explicit_profile and explicit_profile in PROFILES:
        profile_name = explicit_profile
        source = "explicit (LLM_PROFILE)"
    elif freedom_level is not None:
        profile_name = _freedom_to_profile(freedom_level)
        source = f"freedom level {freedom_level} (AGENT_FREEDOM)"
    elif auto_profile:
        profile_name = auto_profile
        source = f"auto-detected for {model}"
    else:
        profile_name = "balanced"
        source = "default"
    
    profile = dict(PROFILES[profile_name])  # Copy
    profile["_name"] = profile_name
    profile["_source"] = source
    profile["_freedom"] = freedom_level
    
    logger.info(f"LLM Profile: {profile_name} ({source})")
    
    return profile


def apply_profile(profile: Dict[str, Any]) -> Dict[str, str]:
    """
    Apply profile settings to environment. Returns dict of all applied values.
    Individual env vars that are already set take priority over profile defaults.
    """
    applied = {}
    skipped = {}
    
    for key, value in profile.items():
        if key.startswith("_") or key == "description" or key == "freedom_range":
            continue
        
        # Check if already set in environment (user override)
        existing = os.getenv(key, "").strip()
        if existing:
            skipped[key] = existing
            applied[key] = existing  # Track actual value
        else:
            os.environ[key] = str(value)
            applied[key] = str(value)
    
    profile_name = profile.get("_name", "unknown")
    logger.info(f"Profile '{profile_name}' applied: {len(applied)} settings ({len(skipped)} overridden by env)")
    
    if skipped:
        logger.info(f"  Env overrides: {', '.join(f'{k}={v}' for k, v in skipped.items())}")
    
    return applied


def get_profile_summary(profile_name: str = None) -> str:
    """Get a human-readable summary of a profile."""
    if not profile_name:
        profile_name = resolve_profile().get("_name", "balanced")
    
    p = PROFILES.get(profile_name, PROFILES["balanced"])
    
    lines = [
        f"Profile: {profile_name.upper()}",
        f"Description: {p['description']}",
        f"Freedom range: {p['freedom_range'][0]}-{p['freedom_range'][1]}/10",
        "",
        "Key Settings:",
        f"  Exploit gate: {'ON' if p.get('ENFORCE_EXPLOITATION_GATE') == 'true' else 'OFF'}",
        f"  Exploit proof required: {'YES' if p.get('ENFORCE_EXPLOITATION_PROOF') == 'true' else 'NO'}",
        f"  Hard exploit-only mode: {'ON' if p.get('EXPLOIT_ONLY_HARD') == 'true' else 'OFF'}",
        f"  Gate cooldown: every {p.get('EXPLOITATION_GATE_COOLDOWN_ITERS', '?')} iters",
        f"  Max reprompts before fail-open: {p.get('EXPLOITATION_GATE_MAX_REPROMPTS', '?')}",
        f"  Context reset after: {p.get('EXPLOITATION_GATE_HARD_RESET_AFTER', '?')} blocks",
        f"  Proof fail mode: {p.get('EXPLOITATION_PROOF_FAIL_MODE', '?')}",
        f"  Max completion tokens: {p.get('LLM_MAX_COMPLETION_TOKENS', '?')}",
        f"  Exploit token cap: {p.get('EXPLOIT_MODE_TOKEN_CAP', '?')}",
        f"  Context window: {p.get('MAX_CONTEXT_CHARS', '?')} chars / {p.get('MAX_CONTEXT_MESSAGES', '?')} msgs",
        f"  Auto-complete after: {p.get('AUTO_COMPLETE_IDLE_ITERATIONS', '?')} idle iters",
        f"  Blocked = iteration: {'YES' if p.get('COUNT_BLOCKED_AS_ITERATION') == 'true' else 'NO'}",
        f"  Redundancy blocking: {'ON' if p.get('BLOCK_REDUNDANT_EXPLOITS') == 'true' else 'OFF'} ({p.get('REDUNDANT_EXPLOIT_STRICTNESS', '?')})",
        f"  Curl classification: {'strict' if p.get('CLASSIFY_CURL_STRICT') == 'true' else 'context-aware'}",
        f"  Gate message style: {p.get('GATE_MESSAGE_VERBOSITY', '?')}",
        f"  Temperature: {p.get('LLM_TEMPERATURE', '?')}",
    ]
    return "\n".join(lines)


def list_profiles() -> str:
    """List all available profiles."""
    lines = ["Available LLM Profiles:", ""]
    for name, p in PROFILES.items():
        r = p["freedom_range"]
        lines.append(f"  {name:12s} (freedom {r[0]}-{r[1]}/10) — {p['description']}")
    lines.append("")
    lines.append("Set via: LLM_PROFILE=<name> or AGENT_FREEDOM=<1-10>")
    return "\n".join(lines)
