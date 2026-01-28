"""
Extraction Module
=================
Strategy pattern content extraction (CSS, XPath, Regex, LLM).
"""

from .extractor import Extractor
from .url_extractor import URLExtractor

__all__ = ["Extractor", "URLExtractor"]
