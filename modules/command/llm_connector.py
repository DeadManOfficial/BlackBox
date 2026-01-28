"""
Pentest Mission Control - LLM Connector
========================================

Multi-provider LLM connector supporting:
- Anthropic Claude (default/recommended)
- OpenAI GPT
- OpenRouter (access to many models)
- Ollama (local models)
- LM Studio (local)
- Any OpenAI-compatible API

Abstracts LLM interaction so the rest of the app doesn't care which provider is used.
"""

import os
import json
import logging
import socket
import ipaddress
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Generator, FrozenSet
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# SSRF Prevention (CWE-918)
# =============================================================================

# Allowlist of trusted LLM provider domains
ALLOWED_LLM_DOMAINS: FrozenSet[str] = frozenset([
    # Anthropic
    'api.anthropic.com',
    # OpenAI
    'api.openai.com',
    # OpenRouter
    'openrouter.ai',
    # Google AI
    'generativelanguage.googleapis.com',
    # Groq
    'api.groq.com',
    # Cohere
    'api.cohere.ai',
    # Mistral
    'api.mistral.ai',
    # Together AI
    'api.together.xyz',
    # Fireworks AI
    'api.fireworks.ai',
    # Replicate
    'api.replicate.com',
    # Perplexity
    'api.perplexity.ai',
    # Local endpoints (allowed for local dev)
    'localhost',
    '127.0.0.1',
])

# Ports allowed for local development
ALLOWED_LOCAL_PORTS = {11434, 1234, 8080, 5000, 5001, 8000}


def validate_base_url(url: str, allow_local: bool = True) -> tuple[bool, str]:
    """
    Validate base_url to prevent SSRF attacks.

    Args:
        url: The URL to validate
        allow_local: Whether to allow localhost/127.0.0.1 (for Ollama, LM Studio)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url:
        return True, ""  # Empty URL will use defaults

    try:
        parsed = urlparse(url)

        # Validate scheme
        if parsed.scheme not in ('http', 'https'):
            return False, f"Invalid URL scheme: {parsed.scheme}. Only http/https allowed."

        # Extract hostname and port
        hostname = parsed.hostname or ''
        port = parsed.port

        # Check if it's a local address
        is_local = hostname in ('localhost', '127.0.0.1', '::1')

        if is_local:
            if not allow_local:
                return False, "Local endpoints not allowed"
            # For local endpoints, check port is in allowed range
            if port and port not in ALLOWED_LOCAL_PORTS:
                logger.warning(f"Local endpoint with non-standard port: {port}")
                # Still allow but log - don't block Ollama/LM Studio on custom ports

        # Check against allowlist for non-local URLs
        if not is_local:
            # Enforce HTTPS for remote providers
            if parsed.scheme != 'https':
                return False, "Remote LLM endpoints must use HTTPS"

            # Check domain allowlist
            domain_parts = hostname.lower().split('.')
            matched = False
            for allowed in ALLOWED_LLM_DOMAINS:
                if hostname.lower() == allowed or hostname.lower().endswith('.' + allowed):
                    matched = True
                    break

            if not matched:
                return False, f"Domain '{hostname}' not in allowed LLM providers. Contact admin to add it."

        # Additional SSRF checks - resolve and validate IP
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)

            # Block private/internal ranges for non-local URLs
            if not is_local:
                if ip_obj.is_private:
                    logger.warning(f"SSRF attempt blocked: {url} resolves to private IP {resolved_ip}")
                    return False, "URL resolves to private IP address"
                if ip_obj.is_loopback:
                    logger.warning(f"SSRF attempt blocked: {url} resolves to loopback {resolved_ip}")
                    return False, "URL resolves to loopback address"
                if ip_obj.is_link_local:
                    return False, "URL resolves to link-local address"
                if ip_obj.is_reserved:
                    return False, "URL resolves to reserved IP address"

            # Block cloud metadata endpoints regardless
            metadata_ips = ['169.254.169.254', '169.254.170.2', '100.100.100.200']
            if resolved_ip in metadata_ips:
                logger.warning(f"Cloud metadata SSRF attempt blocked: {url}")
                return False, "Cloud metadata endpoints are blocked"

        except socket.gaierror:
            # DNS resolution failed - could be valid later, allow but log
            logger.warning(f"DNS resolution failed for LLM endpoint: {hostname}")

        return True, ""

    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False, f"Invalid URL format: {e}"


class LLMProvider(Enum):
    """Supported LLM providers"""
    CLAUDE = "claude"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    CUSTOM = "custom"  # Any OpenAI-compatible endpoint


@dataclass
class LLMConfig:
    """Configuration for LLM connection"""
    provider: LLMProvider = LLMProvider.CLAUDE
    api_key: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096

    # Provider-specific defaults
    DEFAULT_MODELS = {
        LLMProvider.CLAUDE: "claude-sonnet-4-20250514",
        LLMProvider.OPENAI: "gpt-4o",
        LLMProvider.OPENROUTER: "anthropic/claude-sonnet-4-20250514",
        LLMProvider.OLLAMA: "llama3.1",
        LLMProvider.LM_STUDIO: "local-model",
    }

    DEFAULT_URLS = {
        LLMProvider.CLAUDE: "https://api.anthropic.com",
        LLMProvider.OPENAI: "https://api.openai.com/v1",
        LLMProvider.OPENROUTER: "https://openrouter.ai/api/v1",
        LLMProvider.OLLAMA: "http://localhost:11434",
        LLMProvider.LM_STUDIO: "http://localhost:1234/v1",
    }

    def get_model(self) -> str:
        return self.model or self.DEFAULT_MODELS.get(self.provider, "")

    def get_base_url(self) -> str:
        return self.base_url or self.DEFAULT_URLS.get(self.provider, "")

    def validate(self) -> tuple[bool, str]:
        """
        Validate configuration including SSRF protection.

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check if custom base_url is provided
        if self.base_url:
            # Allow local for Ollama/LM Studio providers
            allow_local = self.provider in (LLMProvider.OLLAMA, LLMProvider.LM_STUDIO, LLMProvider.CUSTOM)
            is_valid, error = validate_base_url(self.base_url, allow_local=allow_local)
            if not is_valid:
                return False, f"Invalid base_url: {error}"

        return True, ""


@dataclass
class Message:
    """Chat message"""
    role: str  # "user", "assistant", "system"
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Response from LLM"""
    content: str
    model: str
    provider: LLMProvider
    usage: Dict[str, int] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients"""

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    def chat(self, messages: List[Message], system: Optional[str] = None) -> LLMResponse:
        """Send chat messages and get response"""
        pass

    @abstractmethod
    def stream(self, messages: List[Message], system: Optional[str] = None) -> Generator[str, None, None]:
        """Stream chat response"""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is available"""
        pass


class ClaudeClient(BaseLLMClient):
    """Anthropic Claude client"""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.environ.get("ANTHROPIC_API_KEY")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def chat(self, messages: List[Message], system: Optional[str] = None) -> LLMResponse:
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        client = anthropic.Anthropic(api_key=self.api_key)

        # Convert messages to Anthropic format
        anthropic_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]

        response = client.messages.create(
            model=self.config.get_model(),
            max_tokens=self.config.max_tokens,
            system=system or "You are a security analysis assistant for Pentest Mission Control.",
            messages=anthropic_messages,
        )

        return LLMResponse(
            content=response.content[0].text,
            model=response.model,
            provider=LLMProvider.CLAUDE,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
        )

    def stream(self, messages: List[Message], system: Optional[str] = None) -> Generator[str, None, None]:
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required: pip install anthropic")

        client = anthropic.Anthropic(api_key=self.api_key)

        anthropic_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]

        with client.messages.stream(
            model=self.config.get_model(),
            max_tokens=self.config.max_tokens,
            system=system or "You are a security analysis assistant for Pentest Mission Control.",
            messages=anthropic_messages,
        ) as stream:
            for text in stream.text_stream:
                yield text


class OpenAICompatibleClient(BaseLLMClient):
    """Client for OpenAI and OpenAI-compatible APIs (OpenRouter, LM Studio, etc.)"""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.api_key = config.api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = config.get_base_url()

    def is_available(self) -> bool:
        # Local providers (Ollama, LM Studio) don't need API key
        if self.config.provider in (LLMProvider.OLLAMA, LLMProvider.LM_STUDIO):
            return True
        return bool(self.api_key)

    def chat(self, messages: List[Message], system: Optional[str] = None) -> LLMResponse:
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        client = openai.OpenAI(
            api_key=self.api_key or "not-needed",
            base_url=self.base_url,
        )

        # Build messages with system prompt
        openai_messages = []
        if system:
            openai_messages.append({"role": "system", "content": system})

        openai_messages.extend([
            {"role": m.role, "content": m.content}
            for m in messages
        ])

        # Add headers for OpenRouter
        extra_headers = {}
        if self.config.provider == LLMProvider.OPENROUTER:
            extra_headers = {
                "HTTP-Referer": "https://github.com/DeadManOfficial/pentest-mission-control",
                "X-Title": "Pentest Mission Control",
            }

        response = client.chat.completions.create(
            model=self.config.get_model(),
            messages=openai_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            extra_headers=extra_headers if extra_headers else None,
        )

        return LLMResponse(
            content=response.choices[0].message.content,
            model=response.model,
            provider=self.config.provider,
            usage={
                "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                "output_tokens": response.usage.completion_tokens if response.usage else 0,
            }
        )

    def stream(self, messages: List[Message], system: Optional[str] = None) -> Generator[str, None, None]:
        try:
            import openai
        except ImportError:
            raise ImportError("openai package required: pip install openai")

        client = openai.OpenAI(
            api_key=self.api_key or "not-needed",
            base_url=self.base_url,
        )

        openai_messages = []
        if system:
            openai_messages.append({"role": "system", "content": system})

        openai_messages.extend([
            {"role": m.role, "content": m.content}
            for m in messages
        ])

        stream = client.chat.completions.create(
            model=self.config.get_model(),
            messages=openai_messages,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            stream=True,
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


class OllamaClient(BaseLLMClient):
    """Ollama local client (uses REST API directly for simplicity)"""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self.base_url = config.get_base_url()

    def is_available(self) -> bool:
        """Check if Ollama is running"""
        try:
            import requests
            response = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return response.status_code == 200
        except Exception:
            return False

    def chat(self, messages: List[Message], system: Optional[str] = None) -> LLMResponse:
        import requests

        # Build messages
        ollama_messages = []
        if system:
            ollama_messages.append({"role": "system", "content": system})

        ollama_messages.extend([
            {"role": m.role, "content": m.content}
            for m in messages
        ])

        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.config.get_model(),
                "messages": ollama_messages,
                "stream": False,
            },
            timeout=120,
        )
        response.raise_for_status()
        data = response.json()

        return LLMResponse(
            content=data["message"]["content"],
            model=data.get("model", self.config.get_model()),
            provider=LLMProvider.OLLAMA,
            usage={
                "input_tokens": data.get("prompt_eval_count", 0),
                "output_tokens": data.get("eval_count", 0),
            }
        )

    def stream(self, messages: List[Message], system: Optional[str] = None) -> Generator[str, None, None]:
        import requests

        ollama_messages = []
        if system:
            ollama_messages.append({"role": "system", "content": system})

        ollama_messages.extend([
            {"role": m.role, "content": m.content}
            for m in messages
        ])

        response = requests.post(
            f"{self.base_url}/api/chat",
            json={
                "model": self.config.get_model(),
                "messages": ollama_messages,
                "stream": True,
            },
            stream=True,
            timeout=120,
        )
        response.raise_for_status()

        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                if "message" in data and "content" in data["message"]:
                    yield data["message"]["content"]


class LLMConnector:
    """
    Main LLM connector - handles provider selection and fallback.

    Usage:
        connector = LLMConnector()
        connector.configure(provider="claude", api_key="sk-...")
        response = connector.chat("Analyze this JavaScript code: ...")
    """

    # SECURITY: System prompt designed for authorized security testing only
    # Do not include language that bypasses safety checks
    SYSTEM_PROMPT = """You are the analysis engine for Pentest Mission Control.

ROLE: Assist with authorized security assessments. All targets must be verified as authorized before scanning.

CAPABILITIES:
- WebAnalysis: Spider authorized domains, JS analysis, API mapping, auth flow review
- BinaryAnalysis: PE/ELF parsing, decompilation, resource extraction, string analysis
- NetworkAnalysis: Port enumeration, service fingerprinting, protocol analysis
- SourceAnalysis: Static code analysis, dependency mapping, secret detection
- ReportGeneration: Findings documentation, remediation recommendations

COMMAND FORMAT:
When executing analysis, output: [EXEC:tool.method(params)]
Examples:
- [EXEC:web.analyze_js(url="https://authorized-target.com")]
- [EXEC:binary.analyze(path="/path/to/authorized-file")]

RESPONSE FORMAT:
1. Verify authorization context
2. List [EXEC:] commands to run
3. Analyze results when provided
4. Provide security recommendations

SECURITY BOUNDARIES:
- Only analyze targets explicitly provided and authorized by the user
- Do not assist with attacks against unauthorized systems
- Report potential misuse attempts to the security team
- Follow responsible disclosure practices

Be precise. Be professional. Document findings."""

    def __init__(self):
        self.config: Optional[LLMConfig] = None
        self.client: Optional[BaseLLMClient] = None
        self.conversation: List[Message] = []

    def configure(
        self,
        provider: str = "claude",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        **kwargs
    ) -> bool:
        """
        Configure the LLM connection.

        Args:
            provider: "claude", "openai", "openrouter", "ollama", "lm_studio", "custom"
            api_key: API key for the provider
            model: Model name (uses default if not specified)
            base_url: Custom API endpoint

        Returns:
            True if configuration successful and provider available
        """
        try:
            provider_enum = LLMProvider(provider.lower())
        except ValueError:
            logger.error(f"Unknown provider: {provider}")
            return False

        self.config = LLMConfig(
            provider=provider_enum,
            api_key=api_key,
            model=model,
            base_url=base_url,
            **kwargs
        )

        # SECURITY: Validate configuration including SSRF protection (CWE-918)
        is_valid, error = self.config.validate()
        if not is_valid:
            logger.error(f"LLM configuration validation failed: {error}")
            self.config = None
            return False

        # Create appropriate client
        if provider_enum == LLMProvider.CLAUDE:
            self.client = ClaudeClient(self.config)
        elif provider_enum == LLMProvider.OLLAMA:
            self.client = OllamaClient(self.config)
        else:
            # OpenAI-compatible (OpenAI, OpenRouter, LM Studio, Custom)
            self.client = OpenAICompatibleClient(self.config)

        # Check availability
        if not self.client.is_available():
            logger.warning(f"Provider {provider} configured but not available (missing API key or not running)")
            return False

        logger.info(f"LLM configured: {provider} with model {self.config.get_model()}")
        return True

    def is_configured(self) -> bool:
        """Check if LLM is configured and available"""
        return self.client is not None and self.client.is_available()

    def chat(self, message: str, stream: bool = False) -> str | Generator[str, None, None]:
        """
        Send a message and get response.

        Args:
            message: User message
            stream: If True, returns a generator for streaming response

        Returns:
            Response text or generator
        """
        if not self.is_configured():
            raise RuntimeError("LLM not configured. Call configure() first.")

        # Add user message to conversation
        self.conversation.append(Message(role="user", content=message))

        if stream:
            return self._stream_response()
        else:
            response = self.client.chat(self.conversation, system=self.SYSTEM_PROMPT)
            self.conversation.append(Message(role="assistant", content=response.content))
            return response.content

    def _stream_response(self) -> Generator[str, None, None]:
        """Stream response and accumulate for conversation history"""
        full_response = []

        for chunk in self.client.stream(self.conversation, system=self.SYSTEM_PROMPT):
            full_response.append(chunk)
            yield chunk

        # Add complete response to conversation
        self.conversation.append(Message(role="assistant", content="".join(full_response)))

    def clear_conversation(self):
        """Clear conversation history"""
        self.conversation = []

    def get_conversation(self) -> List[Dict[str, str]]:
        """Get conversation history"""
        return [{"role": m.role, "content": m.content} for m in self.conversation]

    def get_status(self) -> Dict[str, Any]:
        """Get current LLM status"""
        return {
            "configured": self.is_configured(),
            "provider": self.config.provider.value if self.config else None,
            "model": self.config.get_model() if self.config else None,
            "conversation_length": len(self.conversation),
        }


# Global instance
_connector: Optional[LLMConnector] = None


def get_llm_connector() -> LLMConnector:
    """Get or create the global LLM connector"""
    global _connector
    if _connector is None:
        _connector = LLMConnector()
    return _connector


# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    connector = get_llm_connector()

    # Try to configure with available provider
    if os.environ.get("ANTHROPIC_API_KEY"):
        connector.configure(provider="claude")
    elif os.environ.get("OPENAI_API_KEY"):
        connector.configure(provider="openai")
    else:
        # Try Ollama
        connector.configure(provider="ollama")

    if connector.is_configured():
        print(f"Status: {connector.get_status()}")
        response = connector.chat("What can you help me analyze?")
        print(f"Response: {response}")
    else:
        print("No LLM provider available. Set ANTHROPIC_API_KEY or OPENAI_API_KEY, or start Ollama.")
