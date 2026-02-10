#!/usr/bin/env python3
"""
Multi-Model LLM Provider Support
Supports OpenAI, Anthropic, Ollama, and other providers
"""

import os
import json
from typing import List, Dict, Optional
from abc import ABC, abstractmethod
import httpx


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> tuple[str, Dict]:
        """
        Send chat completion request
        Returns: (response_text, usage_stats)
        """
        pass
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Get provider name"""
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI API provider"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-4o", 
                 base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.base_url = base_url
        
        if not self.api_key:
            raise ValueError("OpenAI API key required")
    
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> tuple[str, Dict]:
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }
            )
            response.raise_for_status()
            data = response.json()
        
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        
        return content, {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0)
        }
    
    def get_provider_name(self) -> str:
        return f"openai/{self.model}"


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider"""
    
    def __init__(self, api_key: str = None, model: str = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY") or os.getenv("CLAUDE_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", "claude-sonnet-4-5-20250929")
        
        if not self.api_key:
            raise ValueError("Anthropic API key required")
    
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> tuple[str, Dict]:
        
        # Convert messages format (Anthropic doesn't use system in messages array)
        system_message = ""
        converted_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            else:
                converted_messages.append(msg)
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "system": system_message,
                    "messages": converted_messages
                }
            )
            response.raise_for_status()
            data = response.json()
        
        content = data["content"][0]["text"]
        usage = data.get("usage", {})
        
        return content, {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        }
    
    def get_provider_name(self) -> str:
        return f"anthropic/{self.model}"


class OllamaProvider(LLMProvider):
    """Ollama local LLM provider"""
    
    def __init__(self, base_url: str = "http://localhost:11434", 
                 model: str = "llama3.1:70b"):
        self.base_url = base_url
        self.model = model
    
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> tuple[str, Dict]:
        
        with httpx.Client(timeout=300.0) as client:
            response = client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": max_tokens
                    }
                }
            )
            response.raise_for_status()
            data = response.json()
        
        content = data["message"]["content"]
        
        # Ollama provides token counts
        return content, {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
        }
    
    def get_provider_name(self) -> str:
        return f"ollama/{self.model}"


class LMStudioProvider(LLMProvider):
    """LM Studio local provider (OpenAI-compatible)"""
    
    def __init__(self, base_url: str = "http://localhost:1234/v1", 
                 model: str = "local-model"):
        self.base_url = base_url
        self.model = model
    
    def chat(self, messages: List[Dict], max_tokens: int = 2048, 
             temperature: float = 0.7) -> tuple[str, Dict]:
        
        with httpx.Client(timeout=120.0) as client:
            response = client.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }
            )
            response.raise_for_status()
            data = response.json()
        
        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        
        return content, {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0)
        }
    
    def get_provider_name(self) -> str:
        return f"lmstudio/{self.model}"


def create_provider(provider_type: str, **kwargs) -> LLMProvider:
    """
    Factory function to create LLM provider
    
    Args:
        provider_type: "openai", "anthropic", "ollama", "lmstudio"
        **kwargs: Provider-specific arguments
    
    Returns:
        LLMProvider instance
    """
    providers = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
        "lmstudio": LMStudioProvider
    }
    
    if provider_type not in providers:
        raise ValueError(f"Unknown provider: {provider_type}. Available: {list(providers.keys())}")
    
    return providers[provider_type](**kwargs)


def auto_detect_provider() -> LLMProvider:
    """
    Auto-detect available LLM provider based on environment
    Priority: OpenAI > Anthropic > Ollama > LM Studio
    """
    
    # Check for OpenAI
    if os.getenv("OPENAI_API_KEY"):
        return create_provider("openai")
    
    # Check for Anthropic
    if os.getenv("ANTHROPIC_API_KEY"):
        return create_provider("anthropic")
    
    # Check for Ollama
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get("http://localhost:11434/api/tags")
            if response.status_code == 200:
                return create_provider("ollama")
    except:
        pass
    
    # Check for LM Studio
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get("http://localhost:1234/v1/models")
            if response.status_code == 200:
                return create_provider("lmstudio")
    except:
        pass
    
    # Fallback to LM Studio with host.docker.internal
    return create_provider("lmstudio", base_url="http://host.docker.internal:1234/v1")


if __name__ == "__main__":
    # Test provider detection
    print("Testing LLM provider detection...")
    
    try:
        provider = auto_detect_provider()
        print(f"Detected provider: {provider.get_provider_name()}")
        
        # Test chat
        response, usage = provider.chat([
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Say 'Hello' and nothing else."}
        ])
        
        print(f"Response: {response}")
        print(f"Usage: {usage}")
    except Exception as e:
        print(f"Error: {e}")
