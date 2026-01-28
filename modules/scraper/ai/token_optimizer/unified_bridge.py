#!/usr/bin/env python3
"""
Unified Token Optimization Bridge
==================================
Connects the existing token_optimizer modules with the new utils modules,
providing a single interface for all token optimization needs.

This bridge ensures all token optimization follows the Token Axioms (T0-T4):
  T0: ToolSearch BEFORE MCP calls
  T1: Truncate responses > 10KB
  T2: Checkpoint after each gate/phase
  T3: Files for data, context for summary
  T4: Batch operations in chunks of 10
"""

from typing import Any, Dict, List, Optional, Callable
from functools import wraps

# Import from existing token_optimizer modules
from .prompt_optimizers import PromptOptimizer
from .response_cache import ResponseCache
from .output_controller import OutputController
from .context_manager import ContextManager as AIContextManager
from .request_consolidator import RequestConsolidator
from .token_optimizer_class import TokenOptimizer

# Import from new utils modules
try:
    from modules.utils.response_handler import (
        ResponseHandler,
        truncate,
        compact,
        summarize
    )
    from modules.utils.gate_checkpoint import (
        GateCheckpoint,
        ContextManager as GateContextManager,
        checkpoint,
        load_checkpoint,
        get_summary
    )
    from modules.utils.token_rules import (
        TokenRules,
        BatchProcessor,
        enforce_token_rules,
        get_optimized_scrape_params,
        SCRAPING_RULES,
        GITHUB_RULES,
        API_RULES
    )
    UTILS_AVAILABLE = True
except ImportError:
    UTILS_AVAILABLE = False


class UnifiedTokenOptimizer:
    """
    Unified interface for all token optimization.

    Combines:
    - Existing: PromptOptimizer, ResponseCache, OutputController
    - New: ResponseHandler, GateCheckpoint, TokenRules

    Usage:
        optimizer = UnifiedTokenOptimizer("target_name")

        # T1: Truncate large response
        truncated = optimizer.truncate(large_response)

        # T2: Checkpoint after gate
        summary = optimizer.checkpoint("GATE_1", findings_data)

        # T3: Get summary for context
        summary = optimizer.get_summary("GATE_1")

        # T4: Process in batches
        for batch in optimizer.batch(urls):
            process(batch)
    """

    # Token Axiom thresholds
    MAX_RESPONSE_CHARS = 10000
    BATCH_SIZE = 10

    def __init__(self, target: str = None):
        """Initialize unified token optimizer."""
        self.target = target

        # Existing optimizers
        self.prompt_optimizer = PromptOptimizer()
        self.response_cache = ResponseCache()
        self.output_controller = OutputController()
        self.token_optimizer = TokenOptimizer()

        # New utils (if available)
        if UTILS_AVAILABLE:
            self.token_rules = TokenRules(target)
            self.checkpoint_manager = GateCheckpoint(target) if target else None
            self.batch_processor = BatchProcessor(target) if target else None
        else:
            self.token_rules = None
            self.checkpoint_manager = None
            self.batch_processor = None

    # =========================================================================
    # T1: Response Truncation
    # =========================================================================

    def truncate(self, response: str, max_chars: int = None) -> str:
        """
        T1: Truncate response if too large.

        Uses head (60%) + tail (40%) pattern to preserve context.
        """
        max_chars = max_chars or self.MAX_RESPONSE_CHARS

        if len(response) <= max_chars:
            return response

        if UTILS_AVAILABLE:
            return truncate(response, max_chars)
        else:
            # Fallback implementation
            head_chars = int(max_chars * 0.6)
            tail_chars = int(max_chars * 0.4)
            return (
                response[:head_chars] +
                f"\n\n[... TRUNCATED {len(response) - max_chars} chars ...]\n\n" +
                response[-tail_chars:]
            )

    def compact_json(self, data: Any, max_items: int = 10) -> Any:
        """T1: Compact JSON by limiting array sizes."""
        if UTILS_AVAILABLE:
            return ResponseHandler.compact_json(data, max_items)
        else:
            if isinstance(data, list) and len(data) > max_items:
                return data[:max_items] + [f"...and {len(data) - max_items} more"]
            return data

    # =========================================================================
    # T2: Checkpointing
    # =========================================================================

    def checkpoint(self, gate: str, data: Dict[str, Any]) -> str:
        """
        T2: Checkpoint after completing a gate/phase.

        Returns summary string for context.
        """
        if UTILS_AVAILABLE and self.checkpoint_manager:
            return self.checkpoint_manager.save(gate, data)
        else:
            # Fallback: return basic summary
            return f"{gate} COMPLETE: {len(data)} items"

    def load_checkpoint(self, gate: str) -> Optional[Dict[str, Any]]:
        """T2: Load full checkpoint data."""
        if UTILS_AVAILABLE and self.checkpoint_manager:
            return self.checkpoint_manager.load(gate)
        return None

    def get_next_gate(self) -> Optional[str]:
        """T2: Get next incomplete gate."""
        if UTILS_AVAILABLE and self.checkpoint_manager:
            return self.checkpoint_manager.get_next_gate()
        return None

    # =========================================================================
    # T3: Summary Generation
    # =========================================================================

    def get_summary(self, gate: str = None) -> Optional[str]:
        """
        T3: Get compact summary for context.

        If gate is specified, returns summary of that gate.
        Otherwise returns overall status.
        """
        if UTILS_AVAILABLE and self.checkpoint_manager:
            if gate:
                return self.checkpoint_manager.get_summary(gate)
            else:
                status = self.checkpoint_manager.get_status()
                return f"Gates: {status}"
        return None

    def summarize(self, content: str) -> str:
        """T3: Generate summary of content."""
        if UTILS_AVAILABLE:
            return summarize(content)
        else:
            # Fallback: return first 500 chars
            return content[:500] + "..." if len(content) > 500 else content

    def save_to_file(self, data: Any, filename: str) -> str:
        """T3: Save data to file, return path."""
        if UTILS_AVAILABLE and self.token_rules:
            return self.token_rules.save_to_file(data, filename)
        else:
            from pathlib import Path
            import json
            path = Path("/tmp") / filename
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return str(path)

    # =========================================================================
    # T4: Batch Processing
    # =========================================================================

    def batch(self, items: List[Any], batch_size: int = None):
        """
        T4: Yield batches of items.

        Usage:
            for batch in optimizer.batch(urls):
                results = process(batch)
                optimizer.save_batch(results)
        """
        batch_size = batch_size or self.BATCH_SIZE

        if UTILS_AVAILABLE and self.batch_processor:
            yield from self.batch_processor.process(items)
        else:
            for i in range(0, len(items), batch_size):
                yield items[i:i + batch_size]

    def save_batch(self, results: Any) -> None:
        """T4: Save results from current batch."""
        if UTILS_AVAILABLE and self.batch_processor:
            self.batch_processor.save_batch_results(results)

    def get_all_batch_results(self) -> List[Any]:
        """T4: Get combined results from all batches."""
        if UTILS_AVAILABLE and self.batch_processor:
            return self.batch_processor.get_all_results()
        return []

    # =========================================================================
    # Prompt Optimization (Existing)
    # =========================================================================

    def optimize_prompt(self, prompt: str, **kwargs) -> str:
        """Optimize prompt using existing PromptOptimizer."""
        return self.token_optimizer.optimize_prompt(prompt, **kwargs)

    def optimize_system_prompt(self, prompt: str) -> str:
        """Optimize system prompt."""
        return PromptOptimizer.optimize_system_prompt(prompt)

    def create_template(self, task: str) -> str:
        """Create efficient prompt template."""
        return PromptOptimizer.create_efficient_template(task)

    # =========================================================================
    # Caching (Existing)
    # =========================================================================

    def cache_response(self, key: str, response: Any) -> None:
        """Cache a response."""
        self.response_cache.set(key, response)

    def get_cached(self, key: str) -> Optional[Any]:
        """Get cached response."""
        return self.response_cache.get(key)

    # =========================================================================
    # Scraping Parameters
    # =========================================================================

    def get_scrape_params(self, url: str) -> Dict[str, Any]:
        """Get optimized parameters for scraping."""
        if UTILS_AVAILABLE:
            return get_optimized_scrape_params(url)
        else:
            return {
                "url": url,
                "formats": ["markdown"],
                "onlyMainContent": True,
                "excludeTags": ["script", "style", "nav", "footer"]
            }


# Convenience function
def create_optimizer(target: str = None) -> UnifiedTokenOptimizer:
    """Create a unified token optimizer for the given target."""
    return UnifiedTokenOptimizer(target)


# Decorator for automatic token optimization
def optimize_tokens(target: str = None, truncate_response: bool = True):
    """
    Decorator to apply token optimization to a function.

    Usage:
        @optimize_tokens("target_name")
        def my_scraping_function(url):
            return large_response
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)

            if truncate_response and isinstance(result, str):
                optimizer = UnifiedTokenOptimizer(target)
                result = optimizer.truncate(result)

            return result
        return wrapper
    return decorator


# Export all
__all__ = [
    'UnifiedTokenOptimizer',
    'create_optimizer',
    'optimize_tokens',
    # From existing
    'PromptOptimizer',
    'ResponseCache',
    'OutputController',
    'TokenOptimizer',
    # From utils (if available)
    'truncate',
    'checkpoint',
    'get_summary',
    'BatchProcessor',
]
