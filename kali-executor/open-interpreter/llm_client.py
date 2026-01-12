"""
NeuroSploit SaaS v2 - LLM Client
Handles communication with LM Studio / Claude API with full I/O logging
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import requests

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("neurosploit.llm")

@dataclass
class LLMInteraction:
    """Captures all LLM interaction data for debugging"""
    timestamp: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    messages: List[Dict]
    response: str
    cost_usd: float = 0.0
    error: Optional[str] = None


class LLMClient:
    """Client for LM Studio / OpenAI-compatible APIs / Claude with full logging"""
    
    def __init__(self, log_dir: str = "/pentest/logs"):
        self.api_base = os.getenv("LLM_API_BASE", "http://host.docker.internal:1234/v1")
        self.model = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        self.interactions: List[LLMInteraction] = []
        self.total_tokens = 0
        self.total_cost = 0.0
        
        # Detect API provider
        self.is_claude = "anthropic.com" in self.api_base or "claude" in self.model.lower()
        self.is_openai = "api.openai.com" in self.api_base or "gpt" in self.model.lower()
        self.is_gpt5 = "gpt-5" in self.model.lower()  # GPT-5 uses different parameter names
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")
        
        logger.info(f"LLM Client initialized: {self.api_base} / {self.model} (Claude: {self.is_claude}, OpenAI: {self.is_openai}, GPT-5: {self.is_gpt5})")
    
    def _estimate_tokens(self, text: str) -> int:
        """Rough token estimation (4 chars per token)"""
        return len(text) // 4
    
    def _trim_messages(self, messages: List[Dict], max_context_tokens: int = 20000) -> List[Dict]:
        """Trim conversation history to stay under token limit for GPT-4o"""
        if not messages:
            return messages
        
        # Always keep system message
        system_msg = None
        other_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_msg = msg
            else:
                other_messages.append(msg)
        
        # Estimate total tokens
        total_tokens = sum(self._estimate_tokens(m.get("content", "")) for m in messages)
        
        # If under limit, return as-is
        if total_tokens <= max_context_tokens:
            return messages
        
        # Trim from the beginning (keep recent messages)
        logger.warning(f"Trimming context: {total_tokens} tokens > {max_context_tokens} limit")
        while total_tokens > max_context_tokens and len(other_messages) > 4:
            removed = other_messages.pop(0)
            total_tokens -= self._estimate_tokens(removed.get("content", ""))
        
        # Reconstruct with system message first
        result = []
        if system_msg:
            result.append(system_msg)
        result.extend(other_messages)
        
        logger.info(f"Context trimmed to ~{total_tokens} tokens, {len(result)} messages")
        return result
    
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> str:
        """Send chat completion request with full logging"""
        
        start_time = time.time()
        
        # Trim messages for GPT-4o to stay under 30K TPM limit
        if self.is_openai and not self.is_gpt5:
            messages = self._trim_messages(messages, max_context_tokens=20000)
        
        try:
            if self.is_claude:
                # Claude API format (using requests like NeuroSploit)
                if not self.anthropic_key:
                    raise ValueError("ANTHROPIC_API_KEY not set")
                
                url = "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": self.anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                }
                
                # Convert messages format for Claude
                system_msg = None
                claude_messages = []
                for msg in messages:
                    if msg["role"] == "system":
                        system_msg = msg["content"]
                    else:
                        claude_messages.append(msg)
                
                payload = {
                    "model": self.model,
                    "messages": claude_messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }
                if system_msg:
                    payload["system"] = system_msg
                
                response = requests.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = data["content"][0]["text"]
                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("input_tokens", 0)
                    completion_tokens = usage.get("output_tokens", 0)
                elif response.status_code == 401:
                    raise ValueError(f"Invalid Claude API key: {response.text}")
                else:
                    raise ValueError(f"Claude API error {response.status_code}: {response.text}")
                
            else:
                # OpenAI-compatible format
                headers = {}
                if self.is_openai and self.openai_key:
                    headers["Authorization"] = f"Bearer {self.openai_key}"
                
                # GPT-5 uses max_completion_tokens instead of max_tokens
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "stream": False
                }
                
                if self.is_gpt5:
                    payload["max_completion_tokens"] = max_tokens
                else:
                    payload["max_tokens"] = max_tokens
                
                response = requests.post(
                    f"{self.api_base}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=120
                )
                
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                elif response.status_code == 401:
                    raise ValueError(f"Invalid OpenAI API key: {response.text}")
                elif response.status_code == 429:
                    # Rate limited - retry with exponential backoff
                    import re
                    max_retries = 3
                    
                    for retry in range(max_retries):
                        error_data = response.json()
                        error_msg = error_data.get("error", {}).get("message", "")
                        
                        # Try to extract wait time from error message
                        wait_match = re.search(r'try again in ([\d.]+)s', error_msg)
                        wait_time = float(wait_match.group(1)) if wait_match else 10.0
                        wait_time += 2  # Add 2 second buffer
                        
                        logger.warning(f"Rate limited. Waiting {wait_time}s before retry {retry + 1}/{max_retries}...")
                        time.sleep(wait_time)
                        
                        # Retry the request with correct payload format
                        retry_payload = {
                            "model": self.model,
                            "messages": messages,
                            "temperature": temperature,
                            "stream": False
                        }
                        if self.is_gpt5:
                            retry_payload["max_completion_tokens"] = max_tokens
                        else:
                            retry_payload["max_tokens"] = max_tokens
                        
                        response = requests.post(
                            f"{self.api_base}/chat/completions",
                            headers=headers,
                            json=retry_payload,
                            timeout=120
                        )
                        
                        if response.status_code == 200:
                            data = response.json()
                            content = data["choices"][0]["message"]["content"]
                            usage = data.get("usage", {})
                            prompt_tokens = usage.get("prompt_tokens", 0)
                            completion_tokens = usage.get("completion_tokens", 0)
                            break
                        elif response.status_code != 429:
                            raise ValueError(f"API error after retry {response.status_code}: {response.text}")
                        elif retry == max_retries - 1:
                            raise ValueError(f"Rate limit exceeded after {max_retries} retries: {response.text}")
                else:
                    raise ValueError(f"API error {response.status_code}: {response.text}")
            
            latency_ms = int((time.time() - start_time) * 1000)
            total_tokens = prompt_tokens + completion_tokens
            
            interaction = LLMInteraction(
                timestamp=datetime.utcnow().isoformat(),
                model=self.model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                messages=messages,
                response=content
            )
            
            self._log_interaction(interaction)
            
            logger.info(f"LLM response: {latency_ms}ms, {interaction.total_tokens} tokens")
            
            return content
            
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            
            interaction = LLMInteraction(
                timestamp=datetime.utcnow().isoformat(),
                model=self.model,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                latency_ms=latency_ms,
                messages=messages,
                response="",
                error=str(e)
            )
            
            self._log_interaction(interaction)
            logger.error(f"LLM error: {e}")
            raise
    
    def _log_interaction(self, interaction: LLMInteraction):
        """Log interaction to file"""
        self.interactions.append(interaction)
        self.total_tokens += interaction.total_tokens
        
        log_file = os.path.join(self.log_dir, "llm_interactions.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(interaction)) + '\n')
    
    def get_stats(self) -> Dict:
        """Get usage statistics"""
        return {
            "total_interactions": len(self.interactions),
            "total_tokens": self.total_tokens,
            "total_cost_usd": self.total_cost,
            "avg_latency_ms": sum(i.latency_ms for i in self.interactions) / len(self.interactions) if self.interactions else 0
        }


# Pentest-specific system prompt
PENTEST_SYSTEM_PROMPT = """You are an expert penetration tester with deep knowledge of:
- Network reconnaissance (nmap, masscan, etc.)
- Web application testing (nikto, sqlmap, burp, etc.)
- Exploitation frameworks (metasploit, exploit-db)
- Post-exploitation and privilege escalation
- Evasion techniques for IDS/IPS/WAF

You are running inside a Kali Linux container with full access to pentest tools.

IMPORTANT RULES:
1. Always start with reconnaissance before exploitation
2. Use stealthy techniques when possible to avoid detection
3. If a tool fails or is blocked, try alternative approaches
4. Document all findings clearly
5. Never cause permanent damage to targets

When you need to execute a command, respond with:
```bash
<command here>
```

After seeing command output, analyze it and decide next steps.
Current target information will be provided in the conversation."""


class PentestLLM:
    """LLM interface specifically for pentest operations"""
    
    def __init__(self, target: str, log_dir: str = "/pentest/logs"):
        self.client = LLMClient(log_dir)
        self.target = target
        self.conversation: List[Dict] = [
            {"role": "system", "content": PENTEST_SYSTEM_PROMPT},
            {"role": "user", "content": f"Target for this engagement: {target}\nBegin reconnaissance."}
        ]
    
    def get_next_action(self) -> str:
        """Get next action from LLM"""
        response = self.client.chat(self.conversation)
        self.conversation.append({"role": "assistant", "content": response})
        return response
    
    def add_command_result(self, command: str, output: str, exit_code: int):
        """Add command execution result to conversation"""
        result_msg = f"Command executed: `{command}`\nExit code: {exit_code}\n\nOutput:\n```\n{output[:4000]}\n```"
        if len(output) > 4000:
            result_msg += f"\n... (output truncated, {len(output)} chars total)"
        
        self.conversation.append({"role": "user", "content": result_msg})
    
    def extract_command(self, response: str) -> Optional[str]:
        """Extract SINGLE bash command from LLM response"""
        import re
        
        # Look for ```bash ... ``` blocks
        match = re.search(r'```(?:bash|sh)?\s*\n(.*?)\n```', response, re.DOTALL)
        if match:
            # Get first non-comment line only
            lines = match.group(1).strip().split('\n')
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    return line
        
        # Look for single backtick commands
        match = re.search(r'`([^`]+)`', response)
        if match and any(cmd in match.group(1) for cmd in ['nmap', 'nikto', 'sqlmap', 'hydra', 'gobuster']):
            return match.group(1).strip()
        
        return None
    
    def get_stats(self) -> Dict:
        """Get LLM usage stats"""
        return self.client.get_stats()


if __name__ == "__main__":
    # Test the LLM client
    client = LLMClient(log_dir="./logs")
    
    response = client.chat([
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "What is 2+2? Reply with just the number."}
    ])
    
    print(f"Response: {response}")
    print(f"Stats: {client.get_stats()}")
