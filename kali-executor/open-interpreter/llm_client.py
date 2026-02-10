"""
TazoSploit SaaS v2 - LLM Client
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
import random
import threading
import signal
from contextlib import contextmanager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("tazosploit.llm")


@contextmanager
def _hard_timeout(seconds: int, label: str = "operation"):
    """Hard wall-clock timeout using SIGALRM (interrupts DNS hangs).

    Notes:
    - Only works in the main thread.
    - Safe no-op in non-main threads.
    """
    try:
        seconds = int(seconds or 0)
    except Exception:
        seconds = 0

    if seconds <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return

    def _handler(signum, frame):
        raise TimeoutError(f"{label} hard timeout after {seconds}s")

    old_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, _handler)
    # ITIMER_REAL is more precise than alarm()
    signal.setitimer(signal.ITIMER_REAL, float(seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)

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
        self.is_zhipu = "z.ai" in self.api_base or "zhipu" in self.api_base or "glm" in self.model.lower()
        self.anthropic_key = os.getenv("ANTHROPIC_API_KEY")
        self.anthropic_token = os.getenv("ANTHROPIC_TOKEN")  # Claude subscription token (setup-token)
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.zhipu_key = os.getenv("ZHIPU_API_KEY")
        
        # Determine Claude auth method: prefer subscription token (free) over API key (per-token billing)
        if self.anthropic_token:
            self.claude_auth_method = "subscription_token"
            logger.info("Claude auth: using subscription token (Bearer auth) — no per-token billing")
        elif self.anthropic_key:
            self.claude_auth_method = "api_key"
            logger.info("Claude auth: using API key (x-api-key header) — per-token billing")
        else:
            self.claude_auth_method = None
        
        logger.info(f"LLM Client initialized: {self.api_base} / {self.model} (Claude: {self.is_claude}, OpenAI: {self.is_openai}, GPT-5: {self.is_gpt5}, Zhipu: {self.is_zhipu})")
    
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
        import random  # Force import in function scope for Python 3.13 compatibility
        
        start_time = time.time()
        
        # Trim messages to control costs and stay under context limits
        # Claude: cap at 25K tokens to keep costs ~$0.03/iteration max
        # OpenAI: cap at 20K for TPM limits
        # Local: use full 131K context
        if self.is_claude:
            messages = self._trim_messages(messages, max_context_tokens=25000)
        elif self.is_openai and not self.is_gpt5:
            messages = self._trim_messages(messages, max_context_tokens=20000)
        elif not self.is_openai and not self.is_claude:
            # Local LLM - use 131072 context
            messages = self._trim_messages(messages, max_context_tokens=131072)
        
        try:
            # Optional: keep LLM keys out of the Kali executor by calling an internal proxy.
            # If LLM_PROXY_URL is set, we will POST the OpenAI-style payload to that URL.
            proxy_url = os.getenv("LLM_PROXY_URL", "").strip()
            proxy_token = os.getenv("LLM_PROXY_TOKEN", "").strip()
            if proxy_url:
                headers = {"Content-Type": "application/json"}
                if proxy_token:
                    headers["X-LLM-Proxy-Token"] = proxy_token

                payload = {
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                }
                provider_override = os.getenv("LLM_PROVIDER_OVERRIDE", "").strip()
                if provider_override:
                    payload["provider_override"] = provider_override

                hard_timeout_s = int(os.getenv("LLM_HARD_TIMEOUT_SECONDS", "120"))
                connect_timeout_s = float(os.getenv("LLM_CONNECT_TIMEOUT_SECONDS", "10"))
                read_timeout_s = float(os.getenv("LLM_READ_TIMEOUT_SECONDS", "120"))
                max_attempts = int(os.getenv("LLM_RETRY_MAX", "5"))
                base_backoff = float(os.getenv("LLM_RETRY_BASE_SECONDS", "2"))

                response = None
                last_error = None
                for attempt in range(1, max_attempts + 1):
                    try:
                        with _hard_timeout(hard_timeout_s, label="LLM proxy request"):
                            response = requests.post(
                                proxy_url,
                                headers=headers,
                                json=payload,
                                timeout=(connect_timeout_s, read_timeout_s),
                            )

                        if response.status_code == 200:
                            try:
                                data = response.json()
                                content = data.get("content") or data.get("choices", [{}])[0].get("message", {}).get("content")
                            except Exception:
                                content = None
                            if content:
                                break
                            last_error = "empty_content"
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 30)
                            wait_time += wait_time * random.uniform(0.1, 0.3)
                            logger.warning(
                                f"LLM proxy returned empty content. Waiting {wait_time:.1f}s before retry {attempt}/{max_attempts}..."
                            )
                            time.sleep(wait_time)
                            continue

                        if response.status_code in (429, 500, 502, 503, 504):
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 30)
                            wait_time += wait_time * random.uniform(0.1, 0.3)
                            logger.warning(
                                f"LLM proxy transient error {response.status_code}. "
                                f"Waiting {wait_time:.1f}s before retry {attempt}/{max_attempts}..."
                            )
                            time.sleep(wait_time)
                            continue

                            raise ValueError(f"LLM proxy error {response.status_code}: {response.text}")
                    except requests.exceptions.RequestException as e:
                        last_error = f"{type(e).__name__}"
                        if attempt == max_attempts:
                            raise
                        wait_time = min(base_backoff * (2 ** (attempt - 1)), 30)
                        wait_time += wait_time * random.uniform(0.1, 0.3)
                        logger.warning(
                            f"LLM proxy request failed ({type(e).__name__}). "
                            f"Waiting {wait_time:.1f}s before retry {attempt}/{max_attempts}..."
                        )
                        time.sleep(wait_time)
                        continue

                if response is None or response.status_code != 200:
                    raise ValueError(f"LLM proxy error {response.status_code if response else 'no response'}")

                data = response.json()
                content = data.get("content") or data.get("choices", [{}])[0].get("message", {}).get("content")
                if content is None:
                    raise ValueError(f"LLM proxy returned no content ({last_error or 'unknown'})")

                usage = data.get("usage", {}) or {}
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)

            elif self.is_zhipu:
                # Zhipu GLM API format (OpenAI-compatible with different endpoint)
                if not self.zhipu_key:
                    raise ValueError("ZHIPU_API_KEY not set")
                
                # Use configured API base or default to z.ai
                url = f"{self.api_base}/chat/completions" if not self.api_base.endswith('/chat/completions') else self.api_base
                if 'z.ai' not in url and 'zhipu' not in url:
                    url = "https://api.z.ai/api/coding/paas/v4/chat/completions"
                
                headers = {
                    "Authorization": f"Bearer {self.zhipu_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }
                
                hard_timeout_s = int(os.getenv("LLM_HARD_TIMEOUT_SECONDS", "120"))
                connect_timeout_s = float(os.getenv("LLM_CONNECT_TIMEOUT_SECONDS", "10"))
                read_timeout_s = float(os.getenv("LLM_READ_TIMEOUT_SECONDS", "120"))
                max_attempts = int(os.getenv("LLM_RETRY_MAX", "5"))
                base_backoff = float(os.getenv("LLM_RETRY_BASE_SECONDS", "2"))

                response = None
                for attempt in range(1, max_attempts + 1):
                    try:
                        with _hard_timeout(hard_timeout_s, label="Zhipu LLM request"):
                            response = requests.post(
                                url,
                                headers=headers,
                                json=payload,
                                timeout=(connect_timeout_s, read_timeout_s),
                            )

                        # Retry on transient upstream issues
                        if response.status_code in (429, 500, 502, 503, 504):
                            if attempt == max_attempts:
                                raise ValueError(f"Zhipu API error {response.status_code}: {response.text}")
                            wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                            logger.warning(
                                f"Zhipu transient error {response.status_code}. Waiting {wait_time:.1f}s before retry {attempt}/{max_attempts}..."
                            )
                            time.sleep(wait_time)
                            continue

                        break

                    except Exception as e:
                        if attempt == max_attempts:
                            raise
                        wait_time = min(base_backoff * (2 ** (attempt - 1)), 60) + random.uniform(0.5, 2.0)
                        logger.warning(
                            f"Zhipu request failed ({type(e).__name__}). Waiting {wait_time:.1f}s before retry {attempt}/{max_attempts}..."
                        )
                        time.sleep(wait_time)
                        continue

                if response is None:
                    raise ValueError("Zhipu request failed: no response")

                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    prompt_tokens = usage.get("prompt_tokens", 0)
                    completion_tokens = usage.get("completion_tokens", 0)
                elif response.status_code == 401:
                    raise ValueError("Invalid Zhipu API key")
                else:
                    raise ValueError(f"Zhipu API error {response.status_code}: {response.text}")
            
            elif self.is_claude:
                # Claude API - supports both API key (raw requests) and subscription token (SDK)
                if not self.anthropic_token and not self.anthropic_key:
                    raise ValueError("Neither ANTHROPIC_TOKEN nor ANTHROPIC_API_KEY is set")
                
                # Convert messages format for Claude
                system_msg = None
                claude_messages = []
                for msg in messages:
                    if msg["role"] == "system":
                        system_msg = msg["content"]
                    else:
                        claude_messages.append(msg)
                
                import re as _re
                import random  # Re-import for Python 3.13 scoping
                max_retries = 8
                
                if self.claude_auth_method == "subscription_token":
                    # Use Anthropic SDK for subscription tokens — mimics Claude Code's OAuth headers
                    try:
                        import anthropic
                    except ImportError:
                        raise ValueError("anthropic SDK required for subscription token auth. Run: pip install anthropic")
                    
                    if not hasattr(self, '_anthropic_client'):
                        self._anthropic_client = anthropic.Anthropic(
                            api_key=None,
                            auth_token=self.anthropic_token,
                            default_headers={
                                "accept": "application/json",
                                "anthropic-dangerous-direct-browser-access": "true",
                                "anthropic-beta": "claude-code-20250219,oauth-2025-04-20",
                                "user-agent": "claude-cli/2.1.2 (external, cli)",
                                "x-app": "cli",
                            },
                        )
                    
                    for attempt in range(max_retries + 1):
                        try:
                            kwargs = {
                                "model": self.model,
                                "messages": claude_messages,
                                "max_tokens": max_tokens,
                                "temperature": temperature,
                            }
                            if system_msg:
                                kwargs["system"] = system_msg
                            
                            resp = self._anthropic_client.messages.create(**kwargs)
                            content = resp.content[0].text
                            prompt_tokens = resp.usage.input_tokens
                            completion_tokens = resp.usage.output_tokens
                            break
                        except anthropic.RateLimitError as e:
                            if attempt == max_retries:
                                raise ValueError(f"Claude rate limit exceeded after {max_retries} retries: {e}")
                            wait_time = min(30 * (2 ** attempt), 300) + random.uniform(3, 10)
                            logger.warning(f"Claude rate limited. Waiting {wait_time:.1f}s before retry {attempt + 1}/{max_retries}...")
                            time.sleep(wait_time)
                        except anthropic.APIStatusError as e:
                            if e.status_code == 529:
                                if attempt == max_retries:
                                    raise ValueError(f"Claude API overloaded after {max_retries} retries: {e}")
                                wait_time = min(60 * (2 ** attempt), 600) + random.uniform(5, 15)
                                logger.warning(f"Claude overloaded. Waiting {wait_time:.1f}s...")
                                time.sleep(wait_time)
                            else:
                                raise ValueError(f"Claude API error {e.status_code}: {e}")
                else:
                    # Use raw requests for API key auth
                    url = "https://api.anthropic.com/v1/messages"
                    headers = {
                        "x-api-key": self.anthropic_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    }
                    
                    payload = {
                        "model": self.model,
                        "messages": claude_messages,
                        "max_tokens": max_tokens,
                        "temperature": temperature
                    }
                    if system_msg:
                        payload["system"] = system_msg
                    
                    for attempt in range(max_retries + 1):
                        response = requests.post(url, headers=headers, json=payload, timeout=300)
                        
                        if response.status_code == 200:
                            data = response.json()
                            content = data["content"][0]["text"]
                            usage = data.get("usage", {})
                            prompt_tokens = usage.get("input_tokens", 0)
                            completion_tokens = usage.get("output_tokens", 0)
                            break
                        elif response.status_code == 429:
                            if attempt == max_retries:
                                raise ValueError(f"Claude rate limit exceeded after {max_retries} retries: {response.text}")
                            retry_after = response.headers.get("retry-after")
                            if retry_after:
                                wait_time = float(retry_after)
                            else:
                                try:
                                    error_msg = response.json().get("error", {}).get("message", "")
                                    wait_match = _re.search(r'try again in ([\d.]+)s', error_msg)
                                    wait_time = float(wait_match.group(1)) if wait_match else min(30 * (2 ** attempt), 300)
                                except Exception:
                                    wait_time = min(30 * (2 ** attempt), 300)
                            wait_time += wait_time * random.uniform(0.1, 0.3)
                            logger.warning(f"Claude rate limited (429). Waiting {wait_time:.1f}s before retry {attempt + 1}/{max_retries}...")
                            time.sleep(wait_time)
                            continue
                        elif response.status_code == 529:
                            if attempt == max_retries:
                                raise ValueError(f"Claude API overloaded (529) after {max_retries} retries: {response.text}")
                            wait_time = min(60 * (2 ** attempt), 600) + random.uniform(5, 15)
                            logger.warning(f"Claude API overloaded (529). Waiting {wait_time:.1f}s...")
                            time.sleep(wait_time)
                            continue
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
                    timeout=300
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
                    import random  # Re-import for Python 3.13 scoping
                    max_retries = 8
                    
                    for retry in range(max_retries):
                        try:
                            error_data = response.json()
                            error_msg = error_data.get("error", {}).get("message", "")
                        except Exception:
                            error_msg = ""
                        
                        # Try to extract wait time from error message
                        wait_match = re.search(r'try again in ([\d.]+)s', error_msg)
                        if wait_match:
                            wait_time = float(wait_match.group(1)) + 2
                        else:
                            # Exponential backoff: 30s, 60s, 120s, 240s, ...
                            wait_time = min(30 * (2 ** retry), 300)
                        
                        # Add jitter
                        wait_time += wait_time * random.uniform(0.1, 0.3)
                        
                        logger.warning(f"Rate limited. Waiting {wait_time:.1f}s before retry {retry + 1}/{max_retries}...")
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
                            timeout=300
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
    
    def _calculate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate cost in USD based on model pricing"""
        # Pricing per 1M tokens (input, output)
        pricing = {
            "claude-sonnet-4-20250514": (3.0, 15.0),
            "claude-3-5-haiku-latest": (0.80, 4.0),
            "claude-3-haiku-20240307": (0.25, 1.25),
            "claude-opus-4-5-20250514": (15.0, 75.0),
            "claude-opus-4-6": (15.0, 75.0),
            "gpt-4o": (2.50, 10.0),
            "gpt-4o-mini": (0.15, 0.60),
            "gpt-5": (10.0, 30.0),
        }
        
        # Find matching pricing (partial match)
        input_price, output_price = 0.0, 0.0
        for model_key, (inp, outp) in pricing.items():
            if model_key in self.model.lower() or self.model.lower() in model_key:
                input_price, output_price = inp, outp
                break
        
        if input_price == 0 and output_price == 0:
            # Default estimate for unknown models
            input_price, output_price = 3.0, 15.0
        
        cost = (prompt_tokens * input_price / 1_000_000) + (completion_tokens * output_price / 1_000_000)
        return round(cost, 6)

    def _log_interaction(self, interaction: LLMInteraction):
        """Log interaction to file"""
        self.interactions.append(interaction)
        self.total_tokens += interaction.total_tokens
        
        # Calculate cost based on model
        interaction.cost_usd = self._calculate_cost(interaction.prompt_tokens, interaction.completion_tokens)
        self.total_cost += interaction.cost_usd
        
        log_file = os.path.join(self.log_dir, "llm_interactions.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(asdict(interaction)) + '\n')
    
    def get_stats(self) -> Dict:
        """Get usage statistics"""
        return {
            "total_interactions": len(self.interactions),
            "total_tokens": self.total_tokens,
            "total_cost_usd": self.total_cost,
            "avg_latency_ms": sum(i.latency_ms for i in self.interactions) / len(self.interactions) if self.interactions else 0,
            "prompt_tokens": sum(i.prompt_tokens for i in self.interactions),
            "completion_tokens": sum(i.completion_tokens for i in self.interactions),
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
