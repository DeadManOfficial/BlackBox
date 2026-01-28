# [TRACEABILITY] REQ-301
# Cloned from: github.com/DeadManOfficial/token-optimization
#
# Token Axioms (T0-T4):
#   T0: ToolSearch BEFORE MCP calls (46% reduction)
#   T1: Truncate responses > 10KB (head+tail pattern)
#   T2: Checkpoint after each gate/phase
#   T3: Files for data, context for summary only
#   T4: Batch operations in chunks of 10
#
from .prompt_optimizers import PromptOptimizer
from .response_cache import ResponseCache
from .output_controller import OutputController
from .context_manager import ContextManager
from .request_consolidator import RequestConsolidator
from .token_optimizer_class import TokenOptimizer

# Unified bridge (connects to modules/utils/)
try:
    from .unified_bridge import (
        UnifiedTokenOptimizer,
        create_optimizer,
        optimize_tokens
    )
    UNIFIED_AVAILABLE = True
except ImportError:
    UNIFIED_AVAILABLE = False
    UnifiedTokenOptimizer = None
    create_optimizer = None
    optimize_tokens = None

__all__ = [
    # Core optimizers
    'TokenOptimizer',
    'PromptOptimizer',
    'ResponseCache',
    'OutputController',
    'ContextManager',
    'RequestConsolidator',
    # Quick functions
    'optimize_for_claude',
    'optimize_system_prompt',
    'create_template',
    # Unified bridge (if available)
    'UnifiedTokenOptimizer',
    'create_optimizer',
    'optimize_tokens',
]

def optimize_for_claude(prompt: str, max_words: int = 200) -> str:
    """Quick optimization for Claude API"""
    optimizer = TokenOptimizer()
    return optimizer.optimize_prompt(prompt, compress=True, max_words=max_words)


def optimize_system_prompt(prompt: str) -> str:
    """Quick system prompt optimization"""
    return PromptOptimizer.optimize_system_prompt(prompt)


def create_template(task: str) -> str:
    """Get efficient template"""
    return PromptOptimizer.create_efficient_template(task)
