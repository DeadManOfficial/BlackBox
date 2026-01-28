#!/usr/bin/env python3
"""
BlackBox AI - Scraper Module
=============================

Web scraping and data extraction tools:
- DeadManUltimateScraper integration
- Anti-detect browser support
- Proxy rotation
- Rate limiting
- Data extraction patterns

Based on: ~/.claude-home/BlackBox/modules/scraper/
"""

import sys
import os
from pathlib import Path

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition
from modules.cli import CLIToolWrapper
from typing import Dict, Any, List, Optional
import logging
import json
import re

logger = logging.getLogger(__name__)


class ScrapyWrapper(CLIToolWrapper):
    """Wrapper for Scrapy spider execution"""
    name = "scrapy"
    description = "Scrapy web scraping framework"

    def build_command(self, spider: str = "", url: str = "",
                     output: str = "", format_type: str = "json",
                     **kwargs) -> List[str]:
        command = [self.tool_path, "crawl"]

        if spider:
            command.append(spider)
        if url:
            command.extend(["-a", f"url={url}"])
        if output:
            command.extend(["-o", output])
        if format_type:
            command.extend(["-t", format_type])

        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "output": stdout,
            "success": return_code == 0
        }


class PlaywrightScraper:
    """Browser-based scraper using Playwright"""

    def __init__(self):
        self._browser = None
        self._context = None

    async def scrape_page(self, url: str, selectors: Dict[str, str] = None,
                         screenshot: bool = False, wait_for: str = None) -> Dict[str, Any]:
        """Scrape a page using headless browser"""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return {"error": "playwright not installed"}

        result = {"url": url, "data": {}, "success": False}

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                )
                page = await context.new_page()

                await page.goto(url, wait_until="networkidle")

                if wait_for:
                    await page.wait_for_selector(wait_for, timeout=10000)

                # Get page content
                result["html"] = await page.content()
                result["title"] = await page.title()

                # Extract data using selectors
                if selectors:
                    for name, selector in selectors.items():
                        try:
                            elements = await page.query_selector_all(selector)
                            result["data"][name] = [
                                await el.inner_text() for el in elements
                            ]
                        except:
                            result["data"][name] = []

                # Take screenshot if requested
                if screenshot:
                    screenshot_bytes = await page.screenshot()
                    result["screenshot_size"] = len(screenshot_bytes)

                await browser.close()
                result["success"] = True

        except Exception as e:
            result["error"] = str(e)

        return result

    def scrape_sync(self, url: str, **kwargs) -> Dict[str, Any]:
        """Synchronous wrapper for scrape_page"""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.scrape_page(url, **kwargs))


class DataExtractor:
    """Extract structured data from HTML/text"""

    # Common extraction patterns
    PATTERNS = {
        "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        "phone": r'[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}',
        "url": r'https?://[^\s<>"]+',
        "ip_address": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "api_key": r'(?:api[_-]?key|apikey|key)[=:"\s]+([a-zA-Z0-9_\-]{20,})',
        "jwt": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        "aws_key": r'AKIA[0-9A-Z]{16}',
        "github_token": r'ghp_[a-zA-Z0-9]{36}',
        "credit_card": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        "ssn": r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
        "bitcoin": r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
        "onion": r'[a-z2-7]{16,56}\.onion'
    }

    @classmethod
    def extract(cls, text: str, patterns: List[str] = None) -> Dict[str, List[str]]:
        """Extract data matching patterns from text"""
        if patterns is None:
            patterns = list(cls.PATTERNS.keys())

        results = {}
        for pattern_name in patterns:
            if pattern_name in cls.PATTERNS:
                matches = re.findall(cls.PATTERNS[pattern_name], text, re.IGNORECASE)
                results[pattern_name] = list(set(matches))

        return results

    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        """Extract all supported patterns"""
        return cls.extract(text, list(cls.PATTERNS.keys()))

    @classmethod
    def extract_custom(cls, text: str, pattern: str) -> List[str]:
        """Extract using custom regex pattern"""
        try:
            return list(set(re.findall(pattern, text, re.IGNORECASE)))
        except re.error as e:
            return [f"regex error: {e}"]

    @classmethod
    def available_patterns(cls) -> Dict[str, str]:
        """List available patterns"""
        return {name: pattern for name, pattern in cls.PATTERNS.items()}


class ProxyRotator:
    """Manage proxy rotation for scraping"""

    def __init__(self):
        self.proxies: List[Dict[str, str]] = []
        self.current_index = 0
        self.failures: Dict[str, int] = {}

    def add_proxy(self, proxy: str, proxy_type: str = "http") -> None:
        """Add a proxy to the pool"""
        self.proxies.append({
            "url": proxy,
            "type": proxy_type
        })

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get next proxy in rotation"""
        if not self.proxies:
            return None

        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy

    def mark_failed(self, proxy_url: str) -> None:
        """Mark a proxy as failed"""
        self.failures[proxy_url] = self.failures.get(proxy_url, 0) + 1

        # Remove if too many failures
        if self.failures[proxy_url] >= 3:
            self.proxies = [p for p in self.proxies if p["url"] != proxy_url]

    def get_stats(self) -> Dict[str, Any]:
        """Get proxy pool statistics"""
        return {
            "total_proxies": len(self.proxies),
            "failures": self.failures
        }


class ScraperModule(BaseModule):
    """
    Scraper Module for BlackBox.

    Provides web scraping and data extraction capabilities.
    """

    name = "scraper"
    version = "1.0.0"
    category = ModuleCategory.SCRAPER
    description = "Web scraping and data extraction tools"
    author = "BlackBox Team"
    tags = ["scraper", "extraction", "web", "data"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        self.scrapy = ScrapyWrapper()
        self.playwright_scraper = PlaywrightScraper()
        self.extractor = DataExtractor()
        self.proxy_rotator = ProxyRotator()

    def on_load(self) -> bool:
        self.logger.info(f"Loading {self.name} module v{self.version}")

        # Check for playwright
        try:
            import playwright
            playwright_available = True
        except ImportError:
            playwright_available = False

        tools = {
            "scrapy": self.scrapy.is_available(),
            "playwright": playwright_available,
            "data_extractor": True,  # Built-in
            "proxy_rotator": True  # Built-in
        }

        available = sum(tools.values())
        self.logger.info(f"Scraper tools available: {available}/{len(tools)}")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        tools = []

        @mcp.tool()
        def scraper_extract_data(text: str, patterns: List[str] = None) -> Dict[str, Any]:
            """
            Extract structured data from text using patterns.

            Args:
                text: Text to extract from
                patterns: Patterns to use (email, phone, url, ip_address, api_key, jwt, etc.)

            Returns:
                Extracted data by pattern type
            """
            if patterns:
                result = self.extractor.extract(text, patterns)
            else:
                result = self.extractor.extract_all(text)

            return {
                "patterns_used": patterns or list(self.extractor.PATTERNS.keys()),
                "extracted": result,
                "total_matches": sum(len(v) for v in result.values())
            }

        tools.append(ToolDefinition(
            name="scraper_extract_data",
            description="Extract data using patterns",
            handler=scraper_extract_data,
            category="scraper",
            tags=["extract", "pattern"]
        ))

        @mcp.tool()
        def scraper_extract_custom(text: str, pattern: str) -> Dict[str, Any]:
            """
            Extract data using custom regex pattern.

            Args:
                text: Text to extract from
                pattern: Custom regex pattern

            Returns:
                Matched data
            """
            matches = self.extractor.extract_custom(text, pattern)
            return {
                "pattern": pattern,
                "matches": matches,
                "count": len(matches)
            }

        tools.append(ToolDefinition(
            name="scraper_extract_custom",
            description="Extract with custom regex",
            handler=scraper_extract_custom,
            category="scraper",
            tags=["extract", "regex"]
        ))

        @mcp.tool()
        def scraper_list_patterns() -> Dict[str, Any]:
            """
            List available extraction patterns.

            Returns:
                Available patterns and their regex
            """
            return {
                "patterns": self.extractor.available_patterns()
            }

        tools.append(ToolDefinition(
            name="scraper_list_patterns",
            description="List extraction patterns",
            handler=scraper_list_patterns,
            category="scraper",
            tags=["patterns", "list"]
        ))

        @mcp.tool()
        def scraper_browser_scrape(url: str, selectors: Dict[str, str] = None,
                                  screenshot: bool = False,
                                  wait_for: str = None) -> Dict[str, Any]:
            """
            Scrape a page using headless browser.

            Args:
                url: URL to scrape
                selectors: CSS selectors to extract {name: selector}
                screenshot: Take screenshot
                wait_for: Selector to wait for before scraping

            Returns:
                Scraped page data
            """
            self.logger.info(f"Browser scraping: {url}")
            return self.playwright_scraper.scrape_sync(
                url=url, selectors=selectors,
                screenshot=screenshot, wait_for=wait_for
            )

        tools.append(ToolDefinition(
            name="scraper_browser_scrape",
            description="Scrape with headless browser",
            handler=scraper_browser_scrape,
            category="scraper",
            tags=["browser", "playwright"]
        ))

        @mcp.tool()
        def scraper_proxy_add(proxy: str, proxy_type: str = "http") -> Dict[str, Any]:
            """
            Add proxy to rotation pool.

            Args:
                proxy: Proxy URL (e.g., http://ip:port)
                proxy_type: Proxy type (http, socks5)

            Returns:
                Proxy pool status
            """
            self.proxy_rotator.add_proxy(proxy, proxy_type)
            return {
                "added": proxy,
                "stats": self.proxy_rotator.get_stats()
            }

        tools.append(ToolDefinition(
            name="scraper_proxy_add",
            description="Add proxy to pool",
            handler=scraper_proxy_add,
            category="scraper",
            tags=["proxy"]
        ))

        @mcp.tool()
        def scraper_proxy_stats() -> Dict[str, Any]:
            """
            Get proxy pool statistics.

            Returns:
                Proxy pool stats
            """
            return self.proxy_rotator.get_stats()

        tools.append(ToolDefinition(
            name="scraper_proxy_stats",
            description="Get proxy pool stats",
            handler=scraper_proxy_stats,
            category="scraper",
            tags=["proxy", "stats"]
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        from flask import request, jsonify
        routes = []

        @app.route('/api/scraper/extract', methods=['POST'])
        def api_scraper_extract():
            data = request.get_json() or {}
            text = data.get('text', '')
            patterns = data.get('patterns')

            if patterns:
                result = self.extractor.extract(text, patterns)
            else:
                result = self.extractor.extract_all(text)

            return jsonify({"extracted": result})

        routes.append(RouteDefinition(path="/api/scraper/extract", methods=["POST"],
                                     handler=api_scraper_extract, description="Extract data"))

        @app.route('/api/scraper/patterns', methods=['GET'])
        def api_scraper_patterns():
            return jsonify(self.extractor.available_patterns())

        routes.append(RouteDefinition(path="/api/scraper/patterns", methods=["GET"],
                                     handler=api_scraper_patterns, description="List patterns"))

        @app.route('/api/scraper/status', methods=['GET'])
        def api_scraper_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(path="/api/scraper/status", methods=["GET"],
                                     handler=api_scraper_status, description="Module status"))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        try:
            import playwright
            playwright_available = True
        except ImportError:
            playwright_available = False

        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "healthy": True,
            "tools": {
                "scrapy": self.scrapy.is_available(),
                "playwright": playwright_available,
                "data_extractor": True,
                "proxy_rotator": True
            },
            "proxy_pool": self.proxy_rotator.get_stats()
        }


Module = ScraperModule
