"""
TazoSploit  v2 - Open Interpreter Configuration
Configures Open Interpreter for LM Studio (dev) or Claude API (prod)
"""

import os
from interpreter import interpreter

def configure_interpreter():
    """
    Configure Open Interpreter based on environment variables.
    
    Environment Variables:
        LLM_PROVIDER: 'lm-studio' or 'claude'
        LLM_API_BASE: API endpoint (default: http://localhost:1234/v1)
        LLM_MODEL: Model name (default: openai/gpt-oss-120b)
        CLAUDE_API_KEY: Anthropic API key (for production)
        INTERPRETER_AUTO_RUN: Whether to auto-run commands (default: false)
    """
    
    provider = os.getenv("LLM_PROVIDER", "lm-studio")
    
    if provider == "lm-studio":
        # Local LLM via LM Studio
        interpreter.offline = True
        interpreter.llm.model = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
        interpreter.llm.api_key = "fake_key"  # LM Studio doesn't require real key
        interpreter.llm.api_base = os.getenv("LLM_API_BASE", "http://localhost:1234/v1")
        
    elif provider == "claude":
        # Production: Claude API
        interpreter.offline = False
        interpreter.llm.model = "claude-sonnet-4-20250514"
        interpreter.llm.api_key = os.getenv("CLAUDE_API_KEY")
        
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
    
    # Safety settings
    auto_run = os.getenv("INTERPRETER_AUTO_RUN", "false").lower() == "true"
    interpreter.auto_run = auto_run
    
    # Context settings
    interpreter.llm.context_window = int(os.getenv("LLM_CONTEXT_WINDOW", "8000"))
    interpreter.llm.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "4096"))
    
    # Conversation settings
    interpreter.llm.supports_functions = True
    interpreter.llm.supports_vision = False
    
    return interpreter


def get_pentest_system_prompt():
    """
    Returns the system prompt for penetration testing operations.
    """
    return """You are an expert penetration testing AI assistant running inside a Kali Linux container.
You have access to 150+ security tools and can execute shell commands.

IMPORTANT RULES:
1. ONLY target systems explicitly provided in the approved scope
2. Log every command you execute with full input/output
3. Follow the MITRE ATT&CK framework phases in order
4. Report all findings immediately with severity ratings
5. NEVER perform destructive actions without explicit approval
6. If uncertain, ask for clarification before proceeding

AVAILABLE PHASES:
1. RECONNAISSANCE - Gather information about the target
2. VULNERABILITY SCANNING - Identify potential vulnerabilities
3. EXPLOITATION - Attempt to gain access (with approval)
4. POST-EXPLOITATION - Escalate privileges, move laterally
5. REPORTING - Document all findings

For each action:
- State what you're doing and why
- Show the exact command
- Analyze the output
- Recommend next steps

Available tools include: nmap, sqlmap, nikto, hydra, metasploit, gobuster, 
crackmapexec, impacket, linpeas, and many more.

Current working directory: /pentest
Output directory: /pentest/output
"""


# Initialize when module is imported
if __name__ != "__main__":
    pass  # Don't auto-configure on import
