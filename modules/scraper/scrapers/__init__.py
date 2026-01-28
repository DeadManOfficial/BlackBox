"""
Scraper Registry
================
Central access point for all site-specific scrapers.
"""

from .base import SiteScraper
from .internet import InternetScraper
from .sentinel import SentinelScraper

# CostcoScraper not in local modules
__all__ = ["SiteScraper", "SentinelScraper", "InternetScraper"]
