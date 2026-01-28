#!/usr/bin/env python3
"""
Token Optimization Rules Engine
================================
Enforces token optimization rules across all BlackBox operations.

Rules (T0-T4):
  T0: ToolSearch BEFORE MCP calls
  T1: Truncate responses > 10KB
  T2: Checkpoint after each gate
  T3: Files for data, context for summary
  T4: Batch operations in chunks of 10
"""

from typing import Dict, Any, List, Optional, Callable
from functools import wraps
from pathlib import Path
import json

from .response_handler import ResponseHandler
from .gate_checkpoint import GateCheckpoint, ContextManager


class TokenRules:
    """
    Enforces token optimization rules.
    Can be used as decorator or context manager.
    """

    # Rule thresholds
    MAX_RESPONSE_CHARS = 10000
    BATCH_SIZE = 10
    CONTEXT_THRESHOLD = 0.7

    def __init__(self, target: str = None):
        self.target = target
        self.context_manager = ContextManager()
        self.checkpoint = GateCheckpoint(target) if target else None
        self.violations = []

    def check_response_size(self, response: str) -> tuple[str, bool]:
        """
        T1: Check and truncate large responses.

        Returns:
            Tuple of (processed_response, was_truncated)
        """
        if len(response) > self.MAX_RESPONSE_CHARS:
            truncated = ResponseHandler.truncate(response, self.MAX_RESPONSE_CHARS)
            self.violations.append({
                "rule": "T1",
                "message": f"Response truncated from {len(response)} to {len(truncated)} chars"
            })
            return truncated, True
        return response, False

    def should_checkpoint(self) -> bool:
        """T2: Check if checkpoint is needed."""
        return self.context_manager.should_checkpoint()

    def batch_items(self, items: List[Any]) -> List[List[Any]]:
        """T4: Split items into batches."""
        return [items[i:i + self.BATCH_SIZE]
                for i in range(0, len(items), self.BATCH_SIZE)]

    def save_to_file(self, data: Any, filename: str) -> str:
        """T3: Save data to file, return path."""
        if self.target:
            path = Path.home() / "BlackBox" / "targets" / self.target / filename
        else:
            path = Path("/tmp") / filename

        path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(data, (dict, list)):
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        else:
            with open(path, 'w') as f:
                f.write(str(data))

        return str(path)

    def get_summary(self, data: Any, max_lines: int = 5) -> str:
        """T3: Generate summary for context."""
        if isinstance(data, dict):
            lines = []
            for key, value in list(data.items())[:max_lines]:
                if isinstance(value, list):
                    lines.append(f"- {key}: {len(value)} items")
                elif isinstance(value, dict):
                    lines.append(f"- {key}: {len(value)} keys")
                else:
                    lines.append(f"- {key}: {value}")
            return "\n".join(lines)

        if isinstance(data, list):
            return f"List with {len(data)} items"

        return str(data)[:200]

    def track_operation(self, content: str, name: str = ""):
        """Track operation for context management."""
        self.context_manager.add_operation(content, name)

    def get_status(self) -> Dict[str, Any]:
        """Get current optimization status."""
        return {
            "context_usage": self.context_manager.get_usage(),
            "violations": self.violations,
            "target": self.target
        }


def enforce_token_rules(target: str = None):
    """
    Decorator to enforce token rules on a function.

    Usage:
        @enforce_token_rules("viewcreator.ai")
        def my_scraping_function(url):
            # Large response will be auto-truncated
            return large_response
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            rules = TokenRules(target)

            # Execute function
            result = func(*args, **kwargs)

            # Apply T1: Truncate large responses
            if isinstance(result, str):
                result, was_truncated = rules.check_response_size(result)
                if was_truncated:
                    print(f"[T1] Response truncated to {len(result)} chars")

            # Track for context management
            if result:
                rules.track_operation(str(result), func.__name__)

            # Check T2: Checkpoint warning
            if rules.should_checkpoint():
                print(f"[T2] WARNING: Context at {rules.context_manager.get_usage()['usage_percent']:.1f}% - consider checkpointing")

            return result

        return wrapper
    return decorator


class BatchProcessor:
    """
    T4: Process items in batches with automatic checkpointing.

    Usage:
        processor = BatchProcessor("viewcreator.ai", batch_size=10)

        for batch in processor.process(urls):
            results = scrape_batch(batch)
            processor.save_batch_results(results)

        final_results = processor.get_all_results()
    """

    def __init__(self, target: str, batch_size: int = 10):
        self.target = target
        self.batch_size = batch_size
        self.checkpoint = GateCheckpoint(target)
        self.batch_results = []
        self.current_batch = 0

    def process(self, items: List[Any]):
        """Yield batches of items."""
        for i in range(0, len(items), self.batch_size):
            self.current_batch = i // self.batch_size
            yield items[i:i + self.batch_size]

    def save_batch_results(self, results: Any):
        """Save results from current batch."""
        self.batch_results.append({
            "batch": self.current_batch,
            "count": len(results) if isinstance(results, list) else 1,
            "results": results
        })

        # Auto-checkpoint every 5 batches
        if self.current_batch > 0 and self.current_batch % 5 == 0:
            self._checkpoint()

    def _checkpoint(self):
        """Internal checkpoint."""
        self.checkpoint.save(f"batch_{self.current_batch}", {
            "batches_completed": self.current_batch,
            "results_count": sum(b["count"] for b in self.batch_results)
        })

    def get_all_results(self) -> List[Any]:
        """Get all results from all batches."""
        all_results = []
        for batch in self.batch_results:
            if isinstance(batch["results"], list):
                all_results.extend(batch["results"])
            else:
                all_results.append(batch["results"])
        return all_results


# Pre-configured rules for common operations
SCRAPING_RULES = {
    "formats": ["markdown"],
    "onlyMainContent": True,
    "excludeTags": ["script", "style", "nav", "footer", "header", "aside"],
    "max_response_chars": 10000
}

GITHUB_RULES = {
    "max_files_per_request": 10,
    "exclude_patterns": ["node_modules", ".git", "dist", "build"],
    "max_file_size": 50000
}

API_RULES = {
    "max_response_items": 20,
    "include_metadata": False,
    "compact_output": True
}


def get_optimized_scrape_params(url: str) -> Dict[str, Any]:
    """Get optimized parameters for scraping."""
    return {
        "url": url,
        **SCRAPING_RULES
    }


if __name__ == "__main__":
    print("Token Rules Engine")
    print("=" * 50)

    # Test response truncation
    rules = TokenRules("test_target")

    large_response = "A" * 50000
    truncated, was_truncated = rules.check_response_size(large_response)
    print(f"Original: {len(large_response)}, Truncated: {len(truncated)}, Was truncated: {was_truncated}")

    # Test batching
    items = list(range(25))
    batches = rules.batch_items(items)
    print(f"25 items -> {len(batches)} batches of {rules.BATCH_SIZE}")

    # Test summary generation
    data = {"findings": [1,2,3], "urls": list(range(100)), "status": "complete"}
    summary = rules.get_summary(data)
    print(f"Summary:\n{summary}")

    print("\nToken Rules Engine ready.")
