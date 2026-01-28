"""
LLM Router - ALL FREE FOREVER
==============================

Based on free-llm-api-resources (7.9K stars) patterns.

Philosophy: ALL FREE FOREVER - Never pay for LLM APIs.

Routes LLM requests through FREE providers only:
- Groq (Llama, Mixtral - generous free tier)
- Google AI Studio (Gemini - 60 req/min free)
- Cerebras (Ultra-fast inference - free API)
- OpenRouter (Free models available)

No fallback to paid tiers. Free forever.
"""

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class Priority(Enum):
    """Routing priority modes - ALL FREE FOREVER"""
    FREE = "free"           # DEFAULT: Free providers only (Groq, Google, Cerebras)
    FREE_FAST = "free_fast" # Free providers, fastest first (Cerebras, Groq)
    FREE_QUALITY = "free_quality"  # Free providers, best quality first


class Provider(Enum):
    """LLM providers - FREE FOREVER"""
    # === FREE PROVIDERS (Use these!) ===
    GROQ = "groq"                        # Llama, Mixtral - 30 req/min FREE
    GOOGLE_AI_STUDIO = "google_ai_studio" # Gemini - 60 req/min FREE
    CEREBRAS = "cerebras"                 # Llama - Ultra fast, FREE
    OPENROUTER_FREE = "openrouter_free"   # Free models only
    HUGGINGFACE = "huggingface"           # Inference API - FREE

    # === DEPRECATED (Don't use - not free) ===
    # OPENAI = "openai"      # COSTS MONEY - DO NOT USE
    # ANTHROPIC = "anthropic" # COSTS MONEY - DO NOT USE


@dataclass
class ProviderConfig:
    """Provider configuration"""
    provider: Provider
    api_key_env: str
    base_url: str
    default_model: str
    cost_per_1m_tokens: float  # USD per 1M tokens
    rate_limit_rpm: int = 60
    is_free: bool = False
    supports_streaming: bool = True
    max_context: int = 4096

    def get_api_key(self) -> Optional[str]:
        return os.environ.get(self.api_key_env)

    def is_available(self) -> bool:
        return self.get_api_key() is not None


# Provider configurations - ALL FREE FOREVER
PROVIDERS: Dict[Provider, ProviderConfig] = {
    # === PRIMARY: Groq - Best balance of speed and quality ===
    Provider.GROQ: ProviderConfig(
        provider=Provider.GROQ,
        api_key_env="GROQ_API_KEY",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",  # Latest Llama
        cost_per_1m_tokens=0.0,  # FREE FOREVER
        rate_limit_rpm=30,
        is_free=True,
        max_context=32768
    ),

    # === PRIMARY: Google AI Studio - Highest context, great quality ===
    Provider.GOOGLE_AI_STUDIO: ProviderConfig(
        provider=Provider.GOOGLE_AI_STUDIO,
        api_key_env="GOOGLE_AI_API_KEY",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        default_model="gemini-2.0-flash",  # Latest Gemini
        cost_per_1m_tokens=0.0,  # FREE FOREVER
        rate_limit_rpm=60,
        is_free=True,
        max_context=1048576  # 1M context - best for large documents
    ),

    # === PRIMARY: Cerebras - Ultra-fast inference ===
    Provider.CEREBRAS: ProviderConfig(
        provider=Provider.CEREBRAS,
        api_key_env="CEREBRAS_API_KEY",
        base_url="https://api.cerebras.ai/v1",
        default_model="llama-3.3-70b",
        cost_per_1m_tokens=0.0,  # FREE FOREVER
        rate_limit_rpm=30,
        is_free=True,
        max_context=8192
    ),

    # === SECONDARY: OpenRouter Free Models ===
    Provider.OPENROUTER_FREE: ProviderConfig(
        provider=Provider.OPENROUTER_FREE,
        api_key_env="OPENROUTER_API_KEY",
        base_url="https://openrouter.ai/api/v1",
        default_model="meta-llama/llama-3.2-3b-instruct:free",  # Free model
        cost_per_1m_tokens=0.0,  # FREE FOREVER (free models only)
        rate_limit_rpm=200,
        is_free=True,
        max_context=131072
    ),

    # === SECONDARY: HuggingFace Inference API ===
    Provider.HUGGINGFACE: ProviderConfig(
        provider=Provider.HUGGINGFACE,
        api_key_env="HF_TOKEN",
        base_url="https://api-inference.huggingface.co/models",
        default_model="meta-llama/Meta-Llama-3.1-8B-Instruct",
        cost_per_1m_tokens=0.0,  # FREE FOREVER
        rate_limit_rpm=30,
        is_free=True,
        max_context=8192
    ),
}


@dataclass
class RouteResult:
    """Result of a routing attempt"""
    provider: Provider
    model: str
    response: str
    tokens_used: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    success: bool = True
    error: Optional[str] = None
    fallback_count: int = 0


@dataclass
class RateLimitState:
    """Track rate limits per provider"""
    provider: Provider
    requests_this_minute: int = 0
    minute_start: float = field(default_factory=time.time)
    total_requests: int = 0
    total_tokens: int = 0

    def can_request(self, config: ProviderConfig) -> bool:
        """Check if we can make a request"""
        now = time.time()
        if now - self.minute_start > 60:
            self.requests_this_minute = 0
            self.minute_start = now
        return self.requests_this_minute < config.rate_limit_rpm

    def record_request(self, tokens: int = 0):
        """Record a request"""
        self.requests_this_minute += 1
        self.total_requests += 1
        self.total_tokens += tokens


class LLMRouter:
    """
    Intelligent LLM router with free-tier-first strategy.

    Usage:
        router = LLMRouter(priority=Priority.FREE)
        result = await router.complete("Analyze this vulnerability...")
    """

    def __init__(
        self,
        priority: Priority = Priority.FREE,  # ALL FREE FOREVER
        allowed_providers: Optional[List[Provider]] = None,
        quality_threshold: float = 0.7
    ):
        self.priority = priority
        self.allowed_providers = allowed_providers
        self.quality_threshold = quality_threshold
        self.rate_limits: Dict[Provider, RateLimitState] = {}

        # Initialize rate limit tracking
        for provider in Provider:
            self.rate_limits[provider] = RateLimitState(provider=provider)

    def get_available_providers(self) -> List[ProviderConfig]:
        """Get list of available providers (API key configured)"""
        available = []
        for provider, config in PROVIDERS.items():
            if self.allowed_providers and provider not in self.allowed_providers:
                continue
            if config.is_available():
                available.append(config)
        return available

    def get_routing_order(self) -> List[ProviderConfig]:
        """Get providers in routing order - ALL FREE FOREVER"""
        available = self.get_available_providers()

        # ALL modes are FREE - we never use paid providers
        free_providers = [c for c in available if c.is_free]

        if self.priority == Priority.FREE:
            # Default order: Groq -> Google -> Cerebras -> OpenRouter -> HuggingFace
            return free_providers

        elif self.priority == Priority.FREE_FAST:
            # Fastest first: Cerebras -> Groq -> Google -> others
            fast_order = [Provider.CEREBRAS, Provider.GROQ, Provider.GOOGLE_AI_STUDIO,
                         Provider.OPENROUTER_FREE, Provider.HUGGINGFACE]
            return sorted(free_providers,
                         key=lambda c: fast_order.index(c.provider) if c.provider in fast_order else 99)

        else:  # FREE_QUALITY
            # Best quality first: Google (1M context) -> Groq -> Cerebras -> others
            quality_order = [Provider.GOOGLE_AI_STUDIO, Provider.GROQ, Provider.CEREBRAS,
                            Provider.OPENROUTER_FREE, Provider.HUGGINGFACE]
            return sorted(free_providers,
                         key=lambda c: quality_order.index(c.provider) if c.provider in quality_order else 99)

    def _can_use_provider(self, config: ProviderConfig) -> bool:
        """Check if provider is available and not rate limited"""
        if not config.is_available():
            return False
        return self.rate_limits[config.provider].can_request(config)

    async def _call_provider(
        self,
        config: ProviderConfig,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7
    ) -> RouteResult:
        """Call a specific provider"""
        import httpx

        model = model or config.default_model
        start_time = time.time()

        try:
            # Build request based on provider type
            if config.provider == Provider.GOOGLE_AI_STUDIO:
                # Google AI uses different API format
                url = f"{config.base_url}/models/{model}:generateContent"
                headers = {}
                params = {"key": config.get_api_key()}
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "maxOutputTokens": max_tokens,
                        "temperature": temperature
                    }
                }
                if system_prompt:
                    payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        url,
                        headers=headers,
                        params=params,
                        json=payload,
                        timeout=60.0
                    )

                if response.status_code == 200:
                    data = response.json()
                    text = data["candidates"][0]["content"]["parts"][0]["text"]
                    tokens = data.get("usageMetadata", {}).get("totalTokenCount", 0)
                else:
                    raise Exception(f"Google AI error: {response.status_code}")

            else:
                # OpenAI-compatible format (Groq, Cerebras, OpenRouter, etc.)
                url = f"{config.base_url}/chat/completions"
                headers = {
                    "Authorization": f"Bearer {config.get_api_key()}",
                    "Content-Type": "application/json"
                }

                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                payload = {
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }

                # OpenRouter specific headers
                if config.provider == Provider.OPENROUTER_FREE:
                    headers["HTTP-Referer"] = "https://pentest-mission-control.local"

                async with httpx.AsyncClient() as client:
                    response = await client.post(
                        url,
                        headers=headers,
                        json=payload,
                        timeout=60.0
                    )

                if response.status_code == 200:
                    data = response.json()
                    text = data["choices"][0]["message"]["content"]
                    tokens = data.get("usage", {}).get("total_tokens", 0)
                else:
                    raise Exception(f"API error: {response.status_code} - {response.text}")

            latency = (time.time() - start_time) * 1000
            cost = (tokens / 1_000_000) * config.cost_per_1m_tokens

            # Record the request
            self.rate_limits[config.provider].record_request(tokens)

            return RouteResult(
                provider=config.provider,
                model=model,
                response=text,
                tokens_used=tokens,
                latency_ms=latency,
                cost_usd=cost,
                success=True
            )

        except Exception as e:
            logger.error(f"Provider {config.provider.value} failed: {e}")
            return RouteResult(
                provider=config.provider,
                model=model,
                response="",
                success=False,
                error=str(e)
            )

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        max_fallbacks: int = 3
    ) -> RouteResult:
        """
        Route and complete an LLM request.

        Tries providers in priority order until success or max fallbacks reached.
        """
        routing_order = self.get_routing_order()

        if not routing_order:
            return RouteResult(
                provider=Provider.GROQ,
                model="none",
                response="",
                success=False,
                error="No providers available - check API keys"
            )

        fallback_count = 0

        for config in routing_order:
            if fallback_count >= max_fallbacks:
                break

            if not self._can_use_provider(config):
                logger.debug(f"Skipping {config.provider.value} - rate limited or unavailable")
                continue

            logger.info(f"Trying provider: {config.provider.value}")

            result = await self._call_provider(
                config,
                prompt,
                system_prompt,
                model,
                max_tokens,
                temperature
            )

            if result.success:
                result.fallback_count = fallback_count
                return result

            fallback_count += 1

        # All providers failed
        return RouteResult(
            provider=routing_order[0].provider if routing_order else Provider.GROQ,
            model="none",
            response="",
            success=False,
            error=f"All providers failed after {fallback_count} attempts",
            fallback_count=fallback_count
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get router statistics"""
        return {
            'priority': self.priority.value,
            'available_providers': [c.provider.value for c in self.get_available_providers()],
            'provider_stats': {
                provider.value: {
                    'total_requests': state.total_requests,
                    'total_tokens': state.total_tokens,
                    'requests_this_minute': state.requests_this_minute
                }
                for provider, state in self.rate_limits.items()
                if state.total_requests > 0
            }
        }


# ========== Convenience Functions - ALL FREE FOREVER ==========

_default_router: Optional[LLMRouter] = None


def get_router(priority: Priority = Priority.FREE) -> LLMRouter:
    """Get or create default router - FREE FOREVER"""
    global _default_router
    if _default_router is None:
        _default_router = LLMRouter(priority=priority)
    return _default_router


async def complete(
    prompt: str,
    system_prompt: Optional[str] = None
) -> RouteResult:
    """Complete using FREE providers - ALL FREE FOREVER"""
    router = LLMRouter(priority=Priority.FREE)
    return await router.complete(prompt, system_prompt)


async def complete_fast(
    prompt: str,
    system_prompt: Optional[str] = None
) -> RouteResult:
    """Complete with fastest FREE provider (Cerebras/Groq)"""
    router = LLMRouter(priority=Priority.FREE_FAST)
    return await router.complete(prompt, system_prompt)


async def complete_quality(
    prompt: str,
    system_prompt: Optional[str] = None
) -> RouteResult:
    """Complete with best quality FREE provider (Google 1M context)"""
    router = LLMRouter(priority=Priority.FREE_QUALITY)
    return await router.complete(prompt, system_prompt)


# Backward compatibility aliases
complete_free = complete
complete_cost_optimized = complete  # No cost - it's free!


# ========== Security Analysis Prompts ==========

SECURITY_ANALYSIS_SYSTEM = """You are a security analysis expert. Analyze the provided information and identify:
1. Potential vulnerabilities
2. Risk severity (critical/high/medium/low)
3. Attack vectors
4. Remediation recommendations

Provide structured JSON output when possible."""

async def analyze_vulnerability(
    vulnerability_data: str,
    priority: Priority = Priority.FREE
) -> RouteResult:
    """Analyze vulnerability with FREE LLM - ALL FREE FOREVER"""
    router = LLMRouter(priority=priority)
    return await router.complete(
        vulnerability_data,
        system_prompt=SECURITY_ANALYSIS_SYSTEM
    )
