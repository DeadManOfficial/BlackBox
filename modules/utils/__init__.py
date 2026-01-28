"""
BlackBox Utility Modules
========================
Common utilities for token optimization and context management.

Token Axioms:
  T0: ToolSearch BEFORE MCP calls
  T1: Truncate responses > 10KB
  T2: Checkpoint after each gate
  T3: Files for data, context for summary
  T4: Batch operations in chunks of 10
"""

from .response_handler import (
    ResponseHandler,
    truncate,
    compact,
    summarize
)

from .gate_checkpoint import (
    GateCheckpoint,
    ContextManager,
    checkpoint,
    load_checkpoint,
    get_summary
)

from .token_rules import (
    TokenRules,
    BatchProcessor,
    enforce_token_rules,
    get_optimized_scrape_params,
    SCRAPING_RULES,
    GITHUB_RULES,
    API_RULES
)

__all__ = [
    # Response handling
    "ResponseHandler",
    "truncate",
    "compact",
    "summarize",
    # Gate checkpointing
    "GateCheckpoint",
    "ContextManager",
    "checkpoint",
    "load_checkpoint",
    "get_summary",
    # Token rules
    "TokenRules",
    "BatchProcessor",
    "enforce_token_rules",
    "get_optimized_scrape_params",
    "SCRAPING_RULES",
    "GITHUB_RULES",
    "API_RULES",
]
