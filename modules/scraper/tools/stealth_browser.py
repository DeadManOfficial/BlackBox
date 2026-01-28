"""
Stealth Browser Integration - Camoufox & Nodriver
==================================================

Advanced anti-detect browser automation using:
- Camoufox: C++ level fingerprint masking (Firefox-based)
- Nodriver: CDP-minimal Chrome automation
- Fallback to Playwright with stealth patches

Author: DeadManOfficial
Version: 2.0.0 (2026 Edition)
"""

from __future__ import annotations

import asyncio
import random
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Awaitable, Union
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


# =============================================================================
# CONFIGURATION
# =============================================================================

class BrowserEngine(Enum):
    """Available browser engines in order of stealth capability"""
    CAMOUFOX = "camoufox"      # C++ level stealth (best)
    NODRIVER = "nodriver"      # CDP-minimal (excellent)
    PLAYWRIGHT = "playwright"  # With stealth patches (good)
    AUTO = "auto"              # Auto-select best available


@dataclass
class StealthConfig:
    """Configuration for stealth browsing"""
    engine: BrowserEngine = BrowserEngine.AUTO
    headless: bool = True

    # Fingerprint randomization (master switch + individual)
    randomize_fingerprint: bool = True  # Master switch for all fingerprint randomization
    randomize_viewport: bool = True
    randomize_timezone: bool = True
    randomize_locale: bool = True
    randomize_webgl: bool = True
    randomize_canvas: bool = True
    randomize_audio: bool = True

    # Network
    proxy: Optional[str] = None
    proxy_type: str = "http"  # http, socks5

    # Behavior
    human_like_typing: bool = True
    human_like_mouse: bool = True
    random_delays: bool = True
    delay_range: tuple = (0.5, 2.0)

    # Resource blocking
    block_images: bool = False
    block_fonts: bool = False
    block_media: bool = True
    block_ads: bool = True
    block_resources: List[str] = field(default_factory=lambda: ['image', 'font', 'media'])

    # Persistence
    persist_cookies: bool = False
    cookie_file: Optional[str] = None

    # Timeout
    timeout: int = 30000

    def __post_init__(self):
        """Apply master randomize_fingerprint switch"""
        if not self.randomize_fingerprint:
            self.randomize_viewport = False
            self.randomize_timezone = False
            self.randomize_locale = False
            self.randomize_webgl = False
            self.randomize_canvas = False
            self.randomize_audio = False


@dataclass
class BrowserFingerprint:
    """Browser fingerprint configuration"""
    viewport_width: int = 1920
    viewport_height: int = 1080
    user_agent: str = ""
    platform: str = "Win32"
    timezone: str = "America/New_York"
    locale: str = "en-US"
    color_depth: int = 24
    device_memory: int = 8
    hardware_concurrency: int = 8
    webgl_vendor: str = "Intel Inc."
    webgl_renderer: str = "Intel Iris OpenGL Engine"
    canvas_fingerprint: str = ""
    audio_fingerprint: str = ""

    def to_dict(self) -> Dict:
        """Convert fingerprint to dictionary"""
        return {
            "viewport_width": self.viewport_width,
            "viewport_height": self.viewport_height,
            "user_agent": self.user_agent,
            "platform": self.platform,
            "timezone": self.timezone,
            "locale": self.locale,
            "color_depth": self.color_depth,
            "device_memory": self.device_memory,
            "hardware_concurrency": self.hardware_concurrency,
            "webgl_vendor": self.webgl_vendor,
            "webgl_renderer": self.webgl_renderer
        }

    @classmethod
    def generate_random(cls) -> 'BrowserFingerprint':
        """Generate randomized realistic fingerprint"""
        viewports = [
            (1920, 1080), (1366, 768), (1536, 864),
            (1440, 900), (1280, 720), (2560, 1440)
        ]

        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        ]

        timezones = [
            "America/New_York", "America/Los_Angeles", "America/Chicago",
            "Europe/London", "Europe/Paris", "Asia/Tokyo"
        ]

        webgl_configs = [
            ("Intel Inc.", "Intel Iris OpenGL Engine"),
            ("Intel Inc.", "Intel(R) UHD Graphics 620"),
            ("NVIDIA Corporation", "NVIDIA GeForce GTX 1080/PCIe/SSE2"),
            ("AMD", "AMD Radeon Pro 5500M OpenGL Engine"),
        ]

        vw, vh = random.choice(viewports)
        webgl = random.choice(webgl_configs)

        return cls(
            viewport_width=vw,
            viewport_height=vh,
            user_agent=random.choice(user_agents),
            platform=random.choice(["Win32", "MacIntel"]),
            timezone=random.choice(timezones),
            locale=random.choice(["en-US", "en-GB", "en-CA"]),
            device_memory=random.choice([4, 8, 16]),
            hardware_concurrency=random.choice([4, 8, 12, 16]),
            webgl_vendor=webgl[0],
            webgl_renderer=webgl[1]
        )


# =============================================================================
# ABSTRACT BROWSER INTERFACE
# =============================================================================

class StealthBrowser(ABC):
    """Abstract base class for stealth browsers"""

    def __init__(self, config: StealthConfig):
        self.config = config
        self.fingerprint = BrowserFingerprint.generate_random()
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize browser"""
        pass

    @abstractmethod
    async def goto(self, url: str, wait_until: str = "networkidle") -> 'PageResult':
        """Navigate to URL"""
        pass

    @abstractmethod
    async def click(self, selector: str) -> bool:
        """Click element"""
        pass

    @abstractmethod
    async def type_text(self, selector: str, text: str) -> bool:
        """Type text into element"""
        pass

    @abstractmethod
    async def get_content(self) -> str:
        """Get page HTML content"""
        pass

    @abstractmethod
    async def screenshot(self, path: Optional[str] = None) -> bytes:
        """Take screenshot"""
        pass

    @abstractmethod
    async def evaluate(self, script: str) -> Any:
        """Execute JavaScript"""
        pass

    @abstractmethod
    async def close(self):
        """Close browser"""
        pass

    async def _human_delay(self):
        """Add human-like delay"""
        if self.config.random_delays:
            delay = random.uniform(*self.config.delay_range)
            await asyncio.sleep(delay)


@dataclass
class PageResult:
    """Result from page navigation"""
    url: str
    status: int
    html: str
    title: str
    cookies: List[Dict]
    headers: Dict[str, str]
    timing: Dict[str, float]
    screenshot: Optional[bytes] = None

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "status": self.status,
            "title": self.title,
            "html_length": len(self.html),
            "cookies_count": len(self.cookies),
            "timing": self.timing
        }


# =============================================================================
# CAMOUFOX IMPLEMENTATION
# =============================================================================

class CamoufoxBrowser(StealthBrowser):
    """
    Camoufox anti-detect browser.

    Uses C++ level fingerprint masking based on Firefox.
    Most effective against advanced anti-bot systems.
    """

    def __init__(self, config: StealthConfig):
        super().__init__(config)
        self._browser = None
        self._page = None

    async def initialize(self) -> bool:
        try:
            from camoufox.async_api import AsyncCamoufox

            # Launch with fingerprint config
            self._browser = await AsyncCamoufox(
                headless=self.config.headless,
                geoip=True,  # Use GeoIP for realistic fingerprint
                humanize=self.config.human_like_mouse,
            ).start()

            self._page = await self._browser.new_page()

            # Set viewport
            await self._page.set_viewport_size({
                "width": self.fingerprint.viewport_width,
                "height": self.fingerprint.viewport_height
            })

            self._initialized = True
            logger.info("Camoufox browser initialized")
            return True

        except ImportError:
            logger.warning("Camoufox not installed: pip install camoufox")
            return False
        except Exception as e:
            logger.error(f"Camoufox init error: {e}")
            return False

    async def goto(self, url: str, wait_until: str = "networkidle") -> PageResult:
        if not self._initialized:
            raise RuntimeError("Browser not initialized")

        start = datetime.now()
        response = await self._page.goto(url, wait_until=wait_until)

        html = await self._page.content()
        title = await self._page.title()
        cookies = await self._page.context.cookies()

        return PageResult(
            url=str(self._page.url),
            status=response.status if response else 0,
            html=html,
            title=title,
            cookies=cookies,
            headers=dict(response.headers) if response else {},
            timing={"load_ms": (datetime.now() - start).total_seconds() * 1000}
        )

    async def click(self, selector: str) -> bool:
        try:
            await self._human_delay()
            await self._page.click(selector)
            return True
        except Exception as e:
            logger.error(f"Click error: {e}")
            return False

    async def type_text(self, selector: str, text: str) -> bool:
        try:
            await self._human_delay()

            if self.config.human_like_typing:
                # Type character by character with random delays
                await self._page.click(selector)
                for char in text:
                    await self._page.keyboard.type(char)
                    await asyncio.sleep(random.uniform(0.05, 0.15))
            else:
                await self._page.fill(selector, text)

            return True
        except Exception as e:
            logger.error(f"Type error: {e}")
            return False

    async def get_content(self) -> str:
        return await self._page.content()

    async def screenshot(self, path: Optional[str] = None) -> bytes:
        return await self._page.screenshot(path=path)

    async def evaluate(self, script: str) -> Any:
        return await self._page.evaluate(script)

    async def close(self):
        if self._page:
            await self._page.close()
        if self._browser:
            await self._browser.stop()
        self._initialized = False


# =============================================================================
# NODRIVER IMPLEMENTATION
# =============================================================================

class NodriverBrowser(StealthBrowser):
    """
    Nodriver anti-detect browser.

    Uses CDP-minimal approach - communicates with Chrome directly
    while avoiding detection vectors that traditional tools create.
    """

    def __init__(self, config: StealthConfig):
        super().__init__(config)
        self._browser = None
        self._tab = None

    async def initialize(self) -> bool:
        try:
            import nodriver as uc

            # Launch with minimal CDP footprint
            self._browser = await uc.start(
                headless=self.config.headless,
                sandbox=False
            )

            self._tab = await self._browser.get("about:blank")

            self._initialized = True
            logger.info("Nodriver browser initialized")
            return True

        except ImportError:
            logger.warning("Nodriver not installed: pip install nodriver")
            return False
        except Exception as e:
            logger.error(f"Nodriver init error: {e}")
            return False

    async def goto(self, url: str, wait_until: str = "networkidle") -> PageResult:
        if not self._initialized:
            raise RuntimeError("Browser not initialized")

        start = datetime.now()
        await self._tab.get(url)

        # Wait for page to load
        await asyncio.sleep(2)

        html = await self._tab.get_content()
        title = await self._tab.evaluate("document.title")

        return PageResult(
            url=str(self._tab.url),
            status=200,  # Nodriver doesn't expose status
            html=html,
            title=title or "",
            cookies=[],
            headers={},
            timing={"load_ms": (datetime.now() - start).total_seconds() * 1000}
        )

    async def click(self, selector: str) -> bool:
        try:
            await self._human_delay()
            element = await self._tab.select(selector)
            if element:
                await element.click()
                return True
            return False
        except Exception as e:
            logger.error(f"Click error: {e}")
            return False

    async def type_text(self, selector: str, text: str) -> bool:
        try:
            await self._human_delay()
            element = await self._tab.select(selector)
            if element:
                await element.send_keys(text)
                return True
            return False
        except Exception as e:
            logger.error(f"Type error: {e}")
            return False

    async def get_content(self) -> str:
        return await self._tab.get_content()

    async def screenshot(self, path: Optional[str] = None) -> bytes:
        return await self._tab.save_screenshot(path) if path else b""

    async def evaluate(self, script: str) -> Any:
        return await self._tab.evaluate(script)

    async def close(self):
        if self._browser:
            self._browser.stop()
        self._initialized = False


# =============================================================================
# PLAYWRIGHT STEALTH IMPLEMENTATION
# =============================================================================

class PlaywrightStealthBrowser(StealthBrowser):
    """
    Playwright with stealth patches.

    Fallback option with comprehensive stealth scripts.
    """

    STEALTH_SCRIPT = """
    // Override webdriver
    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

    // Override plugins
    Object.defineProperty(navigator, 'plugins', {
        get: () => [1, 2, 3, 4, 5]
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', {
        get: () => ['en-US', 'en']
    });

    // Chrome runtime
    window.chrome = {runtime: {}};

    // Permissions
    const originalQuery = window.navigator.permissions.query;
    window.navigator.permissions.query = (parameters) => (
        parameters.name === 'notifications' ?
        Promise.resolve({state: Notification.permission}) :
        originalQuery(parameters)
    );

    // WebGL
    const getParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(parameter) {
        if (parameter === 37445) return '{webgl_vendor}';
        if (parameter === 37446) return '{webgl_renderer}';
        return getParameter.apply(this, arguments);
    };
    """

    def __init__(self, config: StealthConfig):
        super().__init__(config)
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    async def initialize(self) -> bool:
        try:
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()

            # Launch browser
            self._browser = await self._playwright.chromium.launch(
                headless=self.config.headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--no-sandbox"
                ]
            )

            # Create context with fingerprint
            self._context = await self._browser.new_context(
                viewport={
                    "width": self.fingerprint.viewport_width,
                    "height": self.fingerprint.viewport_height
                },
                user_agent=self.fingerprint.user_agent,
                locale=self.fingerprint.locale,
                timezone_id=self.fingerprint.timezone,
                proxy={"server": self.config.proxy} if self.config.proxy else None
            )

            # Inject stealth script
            stealth = self.STEALTH_SCRIPT.replace(
                "{webgl_vendor}", self.fingerprint.webgl_vendor
            ).replace(
                "{webgl_renderer}", self.fingerprint.webgl_renderer
            )
            await self._context.add_init_script(stealth)

            self._page = await self._context.new_page()

            self._initialized = True
            logger.info("Playwright stealth browser initialized")
            return True

        except ImportError:
            logger.warning("Playwright not installed: pip install playwright")
            return False
        except Exception as e:
            logger.error(f"Playwright init error: {e}")
            return False

    async def goto(self, url: str, wait_until: str = "networkidle") -> PageResult:
        if not self._initialized:
            raise RuntimeError("Browser not initialized")

        start = datetime.now()
        response = await self._page.goto(url, wait_until=wait_until)

        html = await self._page.content()
        title = await self._page.title()
        cookies = await self._context.cookies()

        return PageResult(
            url=str(self._page.url),
            status=response.status if response else 0,
            html=html,
            title=title,
            cookies=cookies,
            headers=dict(response.headers) if response else {},
            timing={"load_ms": (datetime.now() - start).total_seconds() * 1000}
        )

    async def click(self, selector: str) -> bool:
        try:
            await self._human_delay()
            await self._page.click(selector)
            return True
        except Exception as e:
            logger.error(f"Click error: {e}")
            return False

    async def type_text(self, selector: str, text: str) -> bool:
        try:
            await self._human_delay()

            if self.config.human_like_typing:
                await self._page.click(selector)
                for char in text:
                    await self._page.keyboard.type(char)
                    await asyncio.sleep(random.uniform(0.05, 0.15))
            else:
                await self._page.fill(selector, text)

            return True
        except Exception as e:
            logger.error(f"Type error: {e}")
            return False

    async def get_content(self) -> str:
        return await self._page.content()

    async def screenshot(self, path: Optional[str] = None) -> bytes:
        return await self._page.screenshot(path=path)

    async def evaluate(self, script: str) -> Any:
        return await self._page.evaluate(script)

    async def close(self):
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        self._initialized = False


# =============================================================================
# BROWSER FACTORY
# =============================================================================

class StealthBrowserFactory:
    """Factory for creating stealth browsers"""

    # Priority order for auto-selection
    PRIORITY = [
        (BrowserEngine.CAMOUFOX, CamoufoxBrowser),
        (BrowserEngine.NODRIVER, NodriverBrowser),
        (BrowserEngine.PLAYWRIGHT, PlaywrightStealthBrowser),
    ]

    @classmethod
    async def create(
        cls,
        config: Optional[StealthConfig] = None,
        engine: str = None
    ) -> StealthBrowser:
        """
        Create best available stealth browser.

        Args:
            config: Browser configuration
            engine: Engine name string (optional, overrides config.engine)

        Returns:
            Initialized stealth browser
        """
        config = config or StealthConfig()

        # Handle engine parameter (can be string or enum)
        if engine is not None:
            if isinstance(engine, str):
                engine_map = {
                    'auto': BrowserEngine.AUTO,
                    'camoufox': BrowserEngine.CAMOUFOX,
                    'nodriver': BrowserEngine.NODRIVER,
                    'playwright': BrowserEngine.PLAYWRIGHT,
                }
                config.engine = engine_map.get(engine.lower(), BrowserEngine.AUTO)
            elif isinstance(engine, BrowserEngine):
                config.engine = engine

        if config.engine == BrowserEngine.AUTO:
            # Try in priority order
            for engine, browser_cls in cls.PRIORITY:
                browser = browser_cls(config)
                if await browser.initialize():
                    return browser
                await browser.close()

            raise RuntimeError("No stealth browser available")

        else:
            # Use specific engine
            browser_map = {
                BrowserEngine.CAMOUFOX: CamoufoxBrowser,
                BrowserEngine.NODRIVER: NodriverBrowser,
                BrowserEngine.PLAYWRIGHT: PlaywrightStealthBrowser,
            }

            browser_cls = browser_map.get(config.engine)
            if not browser_cls:
                raise ValueError(f"Unknown engine: {config.engine}")

            browser = browser_cls(config)
            if not await browser.initialize():
                raise RuntimeError(f"Failed to initialize {config.engine.value}")

            return browser

    @classmethod
    def available_engines(cls) -> List[str]:
        """Get list of available browser engines as strings"""
        available = []

        # Check Camoufox
        try:
            import camoufox
            available.append('camoufox')
        except ImportError:
            pass

        # Check Nodriver
        try:
            import nodriver
            available.append('nodriver')
        except ImportError:
            pass

        # Check Playwright
        try:
            import playwright
            available.append('playwright')
        except ImportError:
            pass

        return available

    @classmethod
    def recommend_engine(cls) -> str:
        """Recommend the best available engine"""
        available = cls.available_engines()
        # Priority: camoufox > nodriver > playwright
        for engine in ['camoufox', 'nodriver', 'playwright']:
            if engine in available:
                return engine
        return 'none'


# =============================================================================
# STEALTH SESSION MANAGER
# =============================================================================

class StealthSession:
    """
    Managed stealth browser session with automatic rotation.

    Features:
    - Automatic browser/fingerprint rotation
    - Cookie persistence
    - Request rate limiting
    - Proxy rotation
    """

    def __init__(
        self,
        config: Optional[StealthConfig] = None,
        rotate_every: int = 50,  # Rotate browser every N requests
        proxies: Optional[List[str]] = None
    ):
        self.config = config or StealthConfig()
        self.rotate_every = rotate_every
        self.proxies = proxies or []

        self._browser: Optional[StealthBrowser] = None
        self._request_count = 0
        self._proxy_index = 0

    async def __aenter__(self):
        await self._ensure_browser()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def _ensure_browser(self):
        """Ensure browser is running, rotate if needed"""
        if self._browser is None or self._request_count >= self.rotate_every:
            await self._rotate()

    async def _rotate(self):
        """Rotate browser and fingerprint"""
        if self._browser:
            await self._browser.close()

        # Rotate proxy
        if self.proxies:
            self.config.proxy = self.proxies[self._proxy_index % len(self.proxies)]
            self._proxy_index += 1

        self._browser = await StealthBrowserFactory.create(self.config)
        self._request_count = 0

        logger.info(f"Rotated browser. Proxy: {self.config.proxy}")

    async def fetch(self, url: str, **kwargs) -> PageResult:
        """Fetch URL with automatic rotation"""
        await self._ensure_browser()
        self._request_count += 1
        return await self._browser.goto(url, **kwargs)

    async def fetch_many(
        self,
        urls: List[str],
        max_concurrent: int = 5,
        callback: Optional[Callable[[PageResult], Awaitable[None]]] = None
    ) -> List[PageResult]:
        """Fetch multiple URLs"""
        results = []
        semaphore = asyncio.Semaphore(max_concurrent)

        async def fetch_one(url: str) -> Optional[PageResult]:
            async with semaphore:
                try:
                    result = await self.fetch(url)
                    if callback:
                        await callback(result)
                    return result
                except Exception as e:
                    logger.error(f"Error fetching {url}: {e}")
                    return None

        tasks = [fetch_one(url) for url in urls]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r is not None]

    async def close(self):
        """Close session"""
        if self._browser:
            await self._browser.close()
            self._browser = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def stealth_fetch(url: str, engine: BrowserEngine = BrowserEngine.AUTO) -> PageResult:
    """Quick stealth fetch of single URL"""
    config = StealthConfig(engine=engine)
    browser = await StealthBrowserFactory.create(config)

    try:
        return await browser.goto(url)
    finally:
        await browser.close()


async def stealth_fetch_many(
    urls: List[str],
    proxies: Optional[List[str]] = None
) -> List[PageResult]:
    """Fetch multiple URLs with stealth session"""
    async with StealthSession(proxies=proxies) as session:
        return await session.fetch_many(urls)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    async def main():
        print("Stealth Browser Demo")
        print("=" * 50)

        # Check available engines
        available = StealthBrowserFactory.available_engines()
        print(f"Available engines: {[e.value for e in available]}")

        if not available:
            print("No stealth browser available!")
            print("Install one of: pip install camoufox nodriver playwright")
            return

        # Create session
        config = StealthConfig(
            engine=BrowserEngine.AUTO,
            headless=True,
            human_like_typing=True,
            random_delays=True
        )

        print(f"\nUsing engine: {config.engine.value}")

        async with StealthSession(config) as session:
            # Test bot detection
            test_urls = [
                "https://bot.sannysoft.com/",
                "https://arh.antoinevastel.com/bots/areyouheadless",
                "https://intoli.com/blog/not-possible-to-block-chrome-headless/chrome-headless-test.html"
            ]

            print("\nTesting bot detection sites...")
            for url in test_urls:
                try:
                    result = await session.fetch(url)
                    print(f"  {url}")
                    print(f"    Status: {result.status}")
                    print(f"    Title: {result.title}")
                    print(f"    Load time: {result.timing.get('load_ms', 0):.0f}ms")
                except Exception as e:
                    print(f"  {url}: Error - {e}")

        print("\nDemo complete!")

    asyncio.run(main())
