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
    # The model actually used for this completion (proxy-resolved when available).
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: int
    messages: List[Dict]
    response: str
    cost_usd: float = 0.0
    error: Optional[str] = None
    reasoning_content: Optional[str] = None
    # When using the internal LLM proxy, these capture what we asked for vs what was resolved.
    provider: Optional[str] = None
    requested_model: Optional[str] = None
    requested_api_base: Optional[str] = None


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
        reasoning_content = None  # Will be set if thinking is enabled and provider returns it
        used_provider: Optional[str] = None
        used_model: Optional[str] = None
        requested_model = self.model
        requested_api_base = self.api_base
        
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
                model_override = os.getenv("LLM_MODEL_OVERRIDE", "").strip()
                if model_override:
                    payload["model_override"] = model_override
                # Native thinking support (GLM-5, etc.)
                thinking_enabled = os.getenv("LLM_THINKING_ENABLED", "").strip().lower()
                if thinking_enabled in ("true", "1", "yes", "enabled"):
                    payload["thinking"] = {"type": "enabled"}

                # Default proxy timeouts were too low for "thinking"/long-context responses and caused
                # repeated ReadTimeout retries (stalling runs). Keep env overrides, but raise defaults.
                hard_timeout_s = int(os.getenv("LLM_HARD_TIMEOUT_SECONDS", "240"))
                connect_timeout_s = float(os.getenv("LLM_CONNECT_TIMEOUT_SECONDS", "10"))
                read_timeout_s = float(os.getenv("LLM_READ_TIMEOUT_SECONDS", "240"))
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
                            if attempt == max_attempts:
                                raise ValueError(f"LLM proxy error {response.status_code} after {max_attempts} retries: {response.text}")
                            time.sleep(wait_time)
                            continue
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
                reasoning_content = data.get("reasoning_content") or ""
                # Proxy is the source of truth for provider/model used.
                used_provider = (data.get("provider") or "").strip() or None
                used_model = (data.get("model") or "").strip() or None
                if content is None:
                    raise ValueError(f"LLM proxy returned no content ({last_error or 'unknown'})")

                usage = data.get("usage", {}) or {}
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)

            elif self.is_zhipu:
                # Zhipu GLM API format (OpenAI-compatible with different endpoint)
                if not self.zhipu_key:
                    raise ValueError("ZHIPU_API_KEY not set")

                used_provider = "zai"
                used_model = self.model
                
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
                
                hard_timeout_s = int(os.getenv("LLM_HARD_TIMEOUT_SECONDS", "240"))
                connect_timeout_s = float(os.getenv("LLM_CONNECT_TIMEOUT_SECONDS", "10"))
                read_timeout_s = float(os.getenv("LLM_READ_TIMEOUT_SECONDS", "240"))
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

                used_provider = "anthropic"
                used_model = self.model
                
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

                used_provider = "openai" if self.is_openai else None
                used_model = self.model
                
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
            effective_model = used_model or self.model
            
            interaction = LLMInteraction(
                timestamp=datetime.utcnow().isoformat(),
                model=effective_model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=latency_ms,
                messages=messages,
                response=content,
                reasoning_content=reasoning_content,
                provider=used_provider,
                requested_model=requested_model,
                requested_api_base=requested_api_base,
            )
            
            self._log_interaction(interaction)
            
            prov_str = f", provider={interaction.provider}" if interaction.provider else ""
            model_str = f", model={interaction.model}" if interaction.model else ""
            if reasoning_content:
                logger.info(
                    f"LLM response: {latency_ms}ms, {interaction.total_tokens} tokens{prov_str}{model_str}, THINKING={len(reasoning_content)} chars"
                )
            else:
                logger.info(f"LLM response: {latency_ms}ms, {interaction.total_tokens} tokens{prov_str}{model_str}")
            
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
                error=str(e),
                provider=used_provider,
                requested_model=requested_model,
                requested_api_base=requested_api_base,
            )
            
            self._log_interaction(interaction)
            logger.error(f"LLM error: {e}")
            raise
    
    def _calculate_cost(self, prompt_tokens: int, completion_tokens: int, model: Optional[str] = None) -> float:
        """Calculate cost in USD based on model pricing.
        
        Pricing per 1M tokens: (input, output)
        Sources: OpenAI pricing page, Anthropic docs, OpenRouter API, provider sites.
        Last updated: 2026-02-12
        """
        # Pricing per 1M tokens (input, output) — ordered by match specificity
        pricing = {
            # === Anthropic Claude ===
            "claude-opus-4-6":          (5.0, 25.0),      # Claude Opus 4.6 (Feb 2026)
            "claude-opus-4-5":          (15.0, 75.0),      # Claude Opus 4.5
            "claude-opus-4":            (15.0, 75.0),      # Claude Opus 4 (alias)
            "claude-sonnet-4-5":        (3.0, 15.0),       # Claude Sonnet 4.5
            "claude-sonnet-4":          (3.0, 15.0),       # Claude Sonnet 4
            "claude-3-5-sonnet":        (3.0, 15.0),       # Claude 3.5 Sonnet
            "claude-3-5-haiku":         (0.80, 4.0),       # Claude 3.5 Haiku
            "claude-3-haiku":           (0.25, 1.25),      # Claude 3 Haiku
            # === OpenAI GPT ===
            "gpt-5.2-codex":           (1.75, 14.0),      # GPT-5.2 Codex
            "gpt-5.2-pro":             (21.0, 168.0),      # GPT-5.2 Pro
            "gpt-5.2":                 (1.75, 14.0),       # GPT-5.2
            "gpt-5.1-codex":           (1.25, 10.0),       # GPT-5.1 Codex
            "gpt-5.1":                 (1.25, 10.0),       # GPT-5.1
            "gpt-5-pro":               (15.0, 120.0),      # GPT-5 Pro
            "gpt-5-mini":              (0.25, 2.0),        # GPT-5 Mini
            "gpt-5":                   (1.25, 10.0),       # GPT-5
            "gpt-4.1-mini":            (0.40, 1.60),       # GPT-4.1 Mini
            "gpt-4.1-nano":            (0.10, 0.40),       # GPT-4.1 Nano
            "gpt-4.1":                 (2.0, 8.0),         # GPT-4.1
            "gpt-4o-mini":             (0.15, 0.60),       # GPT-4o Mini
            "gpt-4o":                  (2.50, 10.0),       # GPT-4o
            "o4-mini":                 (1.10, 4.40),       # o4-mini
            "o3-mini":                 (1.10, 4.40),       # o3-mini
            "o3":                      (2.0, 8.0),         # o3
            "o1-mini":                 (1.10, 4.40),       # o1-mini
            "o1":                      (15.0, 60.0),       # o1
            # === Moonshot / Kimi ===
            "kimi-k2.5":              (0.45, 2.25),        # Kimi K2.5 (OpenRouter pricing)
            "kimi-k2-thinking":       (0.45, 2.25),        # Kimi K2 Thinking
            "kimi-k2-turbo":          (0.45, 2.25),        # Kimi K2 Turbo
            "kimi-k2":                (0.45, 2.25),        # Kimi K2 (base)
            "k2p5":                   (0.45, 2.25),        # kimi-coding/k2p5 alias
            # === Z.AI / GLM ===
            "glm-5":                  (1.0, 3.20),         # GLM 5 (OpenRouter)
            "glm-4.7-flash":          (0.06, 0.40),        # GLM 4.7 Flash
            "glm-4.7":                (0.40, 1.50),        # GLM 4.7 (OpenRouter pricing)
            "glm-4.6":                (0.40, 1.50),        # GLM 4.6 (est. same tier)
            "glm-4.5":                (0.40, 1.50),        # GLM 4.5 (est. same tier)
            "glm-4-9b":               (0.10, 0.30),        # GLM-4 9B (small/local)
            # === DeepSeek ===
            "deepseek-r1":            (0.55, 2.19),        # DeepSeek R1
            "deepseek-v3.2":          (0.27, 1.10),        # DeepSeek V3.2
            "deepseek-v3.1":          (0.27, 1.10),        # DeepSeek V3.1
            "deepseek-v3":            (0.27, 1.10),        # DeepSeek V3
            # === Qwen ===
            "qwen3-coder-next":       (0.07, 0.30),        # Qwen3 Coder Next (MoE 3B active)
            "qwen3-coder-480b":       (0.07, 0.30),        # Qwen3 Coder 480B MoE
            "qwen3-max-thinking":     (1.20, 6.0),         # Qwen3 Max Thinking (proprietary)
            "qwen3-235b":             (0.14, 0.60),        # Qwen3 235B (open)
            "qwen3":                  (0.14, 0.60),        # Qwen3 (generic)
            # === Google Gemini ===
            "gemini-3-pro":           (1.25, 10.0),        # Gemini 3 Pro (est.)
            "gemini-3-flash":         (0.50, 3.0),         # Gemini 3 Flash
            "gemini-2.5-flash":       (0.15, 0.60),        # Gemini 2.5 Flash
            # === MiniMax ===
            "minimax-m2.1":           (0.27, 0.95),        # MiniMax M2.1
            "minimax-m2":             (0.27, 0.95),        # MiniMax M2
            # === Misc ===
            "grok":                   (3.0, 15.0),         # xAI Grok (est.)
            "llama-3.3-70b":          (0.10, 0.30),        # Llama 3.3 70B (self-hosted/Venice)
            "llama-4-maverick":       (0.20, 0.60),        # Llama 4 Maverick
        }
        
        # Normalize model name for matching
        model_lower = (model or self.model or "").lower()
        # Strip common provider prefixes for matching
        for prefix in ["anthropic/", "openai/", "openrouter/", "moonshot/", "zai/", 
                       "venice/", "synthetic/", "cerebras/", "google/", "openai-codex/",
                       "kimi-coding/", "opencode/", "vercel-ai-gateway/", "minimax/",
                       "amazon-bedrock/", "hf:", "moonshotai/", "zai-org/", "zai-org-",
                       "anthropic.", "deepseek-ai/"]:
            if model_lower.startswith(prefix):
                model_lower = model_lower[len(prefix):]
                break
        
        # Find matching pricing (partial match, longest key wins)
        input_price, output_price = 0.0, 0.0
        best_match_len = 0
        for model_key, (inp, outp) in pricing.items():
            if model_key in model_lower or model_lower in model_key:
                if len(model_key) > best_match_len:
                    input_price, output_price = inp, outp
                    best_match_len = len(model_key)
        
        if input_price == 0 and output_price == 0:
            # Default estimate for unknown models — conservative mid-tier
            logger.warning(f"No pricing found for model '{model or self.model}', using default $3/$15 per 1M tokens")
            input_price, output_price = 3.0, 15.0
        
        cost = (prompt_tokens * input_price / 1_000_000) + (completion_tokens * output_price / 1_000_000)
        return round(cost, 6)

    def _log_interaction(self, interaction: LLMInteraction):
        """Log interaction to file"""
        self.interactions.append(interaction)
        self.total_tokens += interaction.total_tokens
        
        # Calculate cost based on model
        interaction.cost_usd = self._calculate_cost(interaction.prompt_tokens, interaction.completion_tokens, interaction.model)
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
