"""
BlackBox Scraper Module
=======================
5-layer adaptive web scraper with TOR integration.

Submodules:
- core: Engine, Scheduler, Config, Signals
- ai: LLM routing, relevance filtering, token optimization
- fetch: Adaptive downloader, TOR, proxies
- stealth: Anti-detection, fingerprinting, session management
- discovery: Search aggregation
- extract: Content extraction
- darkweb: Onion scraping
- storage: MongoDB, Elasticsearch backends
- analytics: Metrics and reporting

Usage:
    from modules.scraper.core import Engine, Config
    from modules.scraper.fetch import TORManager
    from modules.scraper.storage import MongoDBStore

DEADMAN // DEATH INCARNATE
"""

__version__ = "6.0.0"


# Lazy imports to avoid dependency issues
def __getattr__(name):
    if name == "Engine":
        from .core import Engine
        return Engine
    elif name == "Config":
        from .core import Config
        return Config
    elif name == "Scheduler":
        from .core import Scheduler
        return Scheduler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["__version__", "Engine", "Config", "Scheduler"]
