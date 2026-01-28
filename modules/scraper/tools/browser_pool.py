"""
Browser Pool Manager - Efficient Headless Browser Management

Implements browser context pooling for high-throughput scraping.
Single browser instance hosts multiple isolated contexts (10-20x memory efficiency).

Author: DeadManOfficial
Version: 1.0.0
"""

import asyncio
import hashlib
import random
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Awaitable, Set
from datetime import datetime, timedelta
from enum import Enum
import json


class BrowserType(Enum):
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


@dataclass
class BrowserPoolConfig:
    """Configuration for browser pool"""
    browser_type: BrowserType = BrowserType.CHROMIUM
    headless: bool = True

    # Pool sizing
    max_browsers: int = 3
    contexts_per_browser: int = 10
    max_pages_per_context: int = 50

    # Resource management
    context_ttl_seconds: int = 300  # 5 minutes
    page_ttl_seconds: int = 60  # 1 minute
    memory_limit_mb: int = 2048

    # Anti-detection
    stealth_mode: bool = True
    randomize_viewport: bool = True
    randomize_timezone: bool = True

    # Network
    proxy: Optional[str] = None
    block_resources: List[str] = field(default_factory=lambda: ["image", "font", "media"])

    # Retry
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class PageResult:
    """Result from page operation"""
    url: str
    html: str
    status: int
    headers: Dict[str, str]
    cookies: List[Dict[str, Any]]
    timing: Dict[str, float]

    # Extracted data
    title: Optional[str] = None
    meta: Dict[str, str] = field(default_factory=dict)

    # Network data
    requests: List[Dict[str, Any]] = field(default_factory=list)
    responses: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "meta": self.meta,
            "timing": self.timing,
            "html_length": len(self.html),
            "request_count": len(self.requests),
            "cookies": self.cookies
        }


class StealthConfig:
    """Anti-detection configuration for Playwright"""

    VIEWPORTS = [
        {"width": 1920, "height": 1080},
        {"width": 1366, "height": 768},
        {"width": 1536, "height": 864},
        {"width": 1440, "height": 900},
        {"width": 1280, "height": 720},
    ]

    TIMEZONES = [
        "America/New_York",
        "America/Los_Angeles",
        "America/Chicago",
        "Europe/London",
        "Europe/Paris",
    ]

    LOCALES = ["en-US", "en-GB", "en-CA"]

    WEBGL_VENDORS = [
        "Intel Inc.",
        "NVIDIA Corporation",
        "AMD",
    ]

    WEBGL_RENDERERS = [
        "Intel Iris OpenGL Engine",
        "NVIDIA GeForce GTX 1080",
        "AMD Radeon Pro 5500M",
    ]

    @classmethod
    def get_random_config(cls) -> Dict[str, Any]:
        """Generate random browser fingerprint"""
        return {
            "viewport": random.choice(cls.VIEWPORTS),
            "timezone_id": random.choice(cls.TIMEZONES),
            "locale": random.choice(cls.LOCALES),
            "color_scheme": random.choice(["light", "dark"]),
            "webgl_vendor": random.choice(cls.WEBGL_VENDORS),
            "webgl_renderer": random.choice(cls.WEBGL_RENDERERS),
        }


class BrowserContextWrapper:
    """Wrapper for browser context with metadata"""

    def __init__(self, context, browser_id: str, context_id: str):
        self.context = context
        self.browser_id = browser_id
        self.context_id = context_id
        self.created_at = datetime.now()
        self.page_count = 0
        self.request_count = 0
        self._pages: List[Any] = []

    @property
    def age_seconds(self) -> float:
        return (datetime.now() - self.created_at).total_seconds()

    async def new_page(self):
        """Create new page in this context"""
        page = await self.context.new_page()
        self._pages.append(page)
        self.page_count += 1
        return page

    async def close(self):
        """Close all pages and context"""
        for page in self._pages:
            try:
                await page.close()
            except:
                pass
        try:
            await self.context.close()
        except:
            pass


class BrowserPool:
    """
    High-performance browser pool with context isolation.

    Features:
    - Multiple browser instances for parallelism
    - Context pooling (10-20 contexts per browser)
    - Automatic resource cleanup
    - Anti-detection measures
    - Network interception
    """

    def __init__(self, config: Optional[BrowserPoolConfig] = None):
        self.config = config or BrowserPoolConfig()
        self._browsers: Dict[str, Any] = {}
        self._contexts: Dict[str, BrowserContextWrapper] = {}
        self._playwright = None
        self._lock = asyncio.Lock()
        self._initialized = False

        # Statistics
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "contexts_created": 0,
            "contexts_recycled": 0,
        }

    async def initialize(self):
        """Initialize Playwright"""
        if self._initialized:
            return

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._initialized = True
        except ImportError:
            raise ImportError("playwright not installed. Run: pip install playwright && playwright install")

    async def _launch_browser(self, browser_id: str) -> Any:
        """Launch a new browser instance"""
        if not self._initialized:
            await self.initialize()

        launch_args = {
            "headless": self.config.headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--disable-site-isolation-trials",
                f"--js-flags=--max-old-space-size={self.config.memory_limit_mb}",
            ]
        }

        if self.config.browser_type == BrowserType.CHROMIUM:
            browser = await self._playwright.chromium.launch(**launch_args)
        elif self.config.browser_type == BrowserType.FIREFOX:
            browser = await self._playwright.firefox.launch(**launch_args)
        else:
            browser = await self._playwright.webkit.launch(**launch_args)

        self._browsers[browser_id] = browser
        return browser

    async def _create_context(self, browser_id: str) -> BrowserContextWrapper:
        """Create a new browser context with stealth settings"""
        browser = self._browsers.get(browser_id)
        if not browser:
            browser = await self._launch_browser(browser_id)

        # Get stealth configuration
        stealth = StealthConfig.get_random_config() if self.config.stealth_mode else {}

        context_options = {
            "viewport": stealth.get("viewport", {"width": 1920, "height": 1080}),
            "locale": stealth.get("locale", "en-US"),
            "timezone_id": stealth.get("timezone_id", "America/New_York"),
            "color_scheme": stealth.get("color_scheme", "light"),
            "user_agent": self._get_random_user_agent(),
            "ignore_https_errors": True,
        }

        if self.config.proxy:
            context_options["proxy"] = {"server": self.config.proxy}

        context = await browser.new_context(**context_options)

        # Apply stealth scripts
        if self.config.stealth_mode:
            await self._apply_stealth_scripts(context, stealth)

        # Block unnecessary resources
        if self.config.block_resources:
            await self._setup_resource_blocking(context)

        context_id = f"{browser_id}_{len(self._contexts)}"
        wrapper = BrowserContextWrapper(context, browser_id, context_id)
        self._contexts[context_id] = wrapper

        self._stats["contexts_created"] += 1
        return wrapper

    async def _apply_stealth_scripts(self, context, stealth: Dict[str, Any]):
        """Inject anti-detection scripts"""
        stealth_script = """
        // Override webdriver
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });

        // Override plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });

        // Override languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });

        // WebGL vendor/renderer
        const getParameter = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(parameter) {
            if (parameter === 37445) return '%VENDOR%';
            if (parameter === 37446) return '%RENDERER%';
            return getParameter.apply(this, arguments);
        };

        // Chrome runtime
        window.chrome = {
            runtime: {}
        };

        // Permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        );
        """

        stealth_script = stealth_script.replace(
            '%VENDOR%', stealth.get('webgl_vendor', 'Intel Inc.')
        ).replace(
            '%RENDERER%', stealth.get('webgl_renderer', 'Intel Iris OpenGL Engine')
        )

        await context.add_init_script(stealth_script)

    async def _setup_resource_blocking(self, context):
        """Block unnecessary resources to speed up page loads"""
        await context.route("**/*", self._handle_route)

    async def _handle_route(self, route):
        """Handle route for resource blocking"""
        resource_type = route.request.resource_type

        if resource_type in self.config.block_resources:
            await route.abort()
        else:
            await route.continue_()

    def _get_random_user_agent(self) -> str:
        """Get random user agent"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        ]
        return random.choice(user_agents)

    async def get_context(self) -> BrowserContextWrapper:
        """Get an available context (or create new one)"""
        async with self._lock:
            # Clean up expired contexts
            await self._cleanup_expired_contexts()

            # Find available context
            for context_id, wrapper in self._contexts.items():
                if wrapper.page_count < self.config.max_pages_per_context:
                    if wrapper.age_seconds < self.config.context_ttl_seconds:
                        return wrapper

            # Create new context if under limit
            total_contexts = len(self._contexts)
            max_total = self.config.max_browsers * self.config.contexts_per_browser

            if total_contexts < max_total:
                browser_id = f"browser_{total_contexts // self.config.contexts_per_browser}"
                return await self._create_context(browser_id)

            # Recycle oldest context
            oldest = min(self._contexts.values(), key=lambda c: c.created_at)
            await oldest.close()
            del self._contexts[oldest.context_id]
            self._stats["contexts_recycled"] += 1

            browser_id = oldest.browser_id
            return await self._create_context(browser_id)

    async def _cleanup_expired_contexts(self):
        """Remove expired contexts"""
        expired = [
            cid for cid, wrapper in self._contexts.items()
            if wrapper.age_seconds > self.config.context_ttl_seconds
        ]

        for context_id in expired:
            wrapper = self._contexts[context_id]
            await wrapper.close()
            del self._contexts[context_id]
            self._stats["contexts_recycled"] += 1

    async def fetch_page(
        self,
        url: str,
        wait_for: Optional[str] = None,
        wait_timeout: int = 30000,
        intercept_network: bool = False,
        screenshot: bool = False
    ) -> PageResult:
        """
        Fetch a page with full rendering.

        Args:
            url: URL to fetch
            wait_for: Selector to wait for before returning
            wait_timeout: Timeout for waiting
            intercept_network: Capture network requests/responses
            screenshot: Take screenshot

        Returns:
            PageResult with HTML and metadata
        """
        context_wrapper = await self.get_context()
        page = await context_wrapper.new_page()

        requests = []
        responses = []

        try:
            # Setup network interception
            if intercept_network:
                page.on("request", lambda req: requests.append({
                    "url": req.url,
                    "method": req.method,
                    "headers": dict(req.headers),
                    "resource_type": req.resource_type
                }))

                page.on("response", lambda res: responses.append({
                    "url": res.url,
                    "status": res.status,
                    "headers": dict(res.headers)
                }))

            # Navigate
            start_time = datetime.now()
            response = await page.goto(url, wait_until="networkidle", timeout=wait_timeout)
            load_time = (datetime.now() - start_time).total_seconds() * 1000

            # Wait for specific element
            if wait_for:
                await page.wait_for_selector(wait_for, timeout=wait_timeout)

            # Extract data
            html = await page.content()
            title = await page.title()

            # Get meta tags
            meta = {}
            meta_elements = await page.query_selector_all("meta")
            for meta_el in meta_elements:
                name = await meta_el.get_attribute("name") or await meta_el.get_attribute("property")
                content = await meta_el.get_attribute("content")
                if name and content:
                    meta[name] = content

            # Get cookies
            cookies = await context_wrapper.context.cookies()

            self._stats["total_requests"] += 1
            self._stats["successful_requests"] += 1

            result = PageResult(
                url=url,
                html=html,
                status=response.status if response else 0,
                headers=dict(response.headers) if response else {},
                cookies=cookies,
                timing={"load_ms": load_time},
                title=title,
                meta=meta,
                requests=requests,
                responses=responses
            )

            return result

        except Exception as e:
            self._stats["total_requests"] += 1
            self._stats["failed_requests"] += 1
            raise

        finally:
            await page.close()

    async def fetch_batch(
        self,
        urls: List[str],
        max_concurrent: int = 10,
        callback: Optional[Callable[[PageResult], Awaitable[None]]] = None
    ) -> List[PageResult]:
        """
        Fetch multiple pages concurrently.

        Args:
            urls: List of URLs to fetch
            max_concurrent: Maximum concurrent fetches
            callback: Optional callback for each result

        Returns:
            List of PageResults
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []

        async def fetch_one(url: str) -> Optional[PageResult]:
            async with semaphore:
                try:
                    result = await self.fetch_page(url)
                    if callback:
                        await callback(result)
                    return result
                except Exception as e:
                    return None

        tasks = [fetch_one(url) for url in urls]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r is not None]

    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        return {
            **self._stats,
            "active_browsers": len(self._browsers),
            "active_contexts": len(self._contexts),
            "success_rate": (
                self._stats["successful_requests"] / self._stats["total_requests"]
                if self._stats["total_requests"] > 0 else 0
            )
        }

    async def close(self):
        """Shutdown all browsers and contexts"""
        for wrapper in self._contexts.values():
            await wrapper.close()

        for browser in self._browsers.values():
            await browser.close()

        if self._playwright:
            await self._playwright.stop()

        self._contexts.clear()
        self._browsers.clear()
        self._initialized = False


# Convenience function
async def quick_fetch(url: str, headless: bool = True) -> PageResult:
    """Quick single-page fetch"""
    pool = BrowserPool(BrowserPoolConfig(headless=headless))
    try:
        await pool.initialize()
        return await pool.fetch_page(url)
    finally:
        await pool.close()


# Example usage
async def example():
    config = BrowserPoolConfig(
        max_browsers=2,
        contexts_per_browser=5,
        stealth_mode=True,
        block_resources=["image", "font", "media"]
    )

    pool = BrowserPool(config)
    await pool.initialize()

    try:
        # Single fetch
        result = await pool.fetch_page(
            "https://example.com",
            intercept_network=True
        )
        print(f"Title: {result.title}")
        print(f"Network requests: {len(result.requests)}")

        # Batch fetch
        urls = [
            "https://httpbin.org/html",
            "https://httpbin.org/headers",
            "https://httpbin.org/ip"
        ]

        results = await pool.fetch_batch(urls, max_concurrent=3)
        print(f"Fetched {len(results)} pages")

        # Stats
        print(f"Pool stats: {pool.get_stats()}")

    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(example())
