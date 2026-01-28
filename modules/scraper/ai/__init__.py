"""
AI Module
=========
FREE LLM routing for content analysis and filtering.

Providers (all FREE):
- Mistral: 1 BILLION tokens/month
- Groq: 14,400 requests/day
- Cerebras: 1M tokens/day
- Ollama: Unlimited (local)
"""

from .llm_router import FreeLLMRouter
from .relevance import filter_relevant

__all__ = ["FreeLLMRouter", "filter_relevant"]
