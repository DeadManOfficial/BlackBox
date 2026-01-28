#!/usr/bin/env python3
"""
Scraper Enhancements Module - Intelligence-Based Improvements
==============================================================
Implements techniques extracted from 5.17 MB of intelligence data

Enhancements Based on Analysis:
1. Advanced User-Agent Rotation (realistic 2026 browsers)
2. WebDriver Property Hiding (anti-detection)
3. Headless Detection Bypass
4. Smart Retry Logic with Exponential Backoff
5. Enhanced Cookie/Session Management
6. Browser Fingerprint Randomization

All techniques are FREE and production-ready.
"""

import random
import time
import hashlib
from typing import Dict, List, Optional
from datetime import datetime

class EnhancedUserAgents:
    """
    Advanced User-Agent Management
    Based on intelligence analysis of bot detection bypass techniques
    """

    # Realistic 2026 browser user agents (extracted from intelligence)
    CHROME_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]

    FIREFOX_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    ]

    SAFARI_AGENTS = [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    ]

    EDGE_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    ]

    @classmethod
    def get_random_agent(cls, browser_type: Optional[str] = None) -> str:
        """Get random user agent, optionally filtered by browser type"""
        if browser_type:
            agents_map = {
                'chrome': cls.CHROME_AGENTS,
                'firefox': cls.FIREFOX_AGENTS,
                'safari': cls.SAFARI_AGENTS,
                'edge': cls.EDGE_AGENTS
            }
            agents = agents_map.get(browser_type.lower(), cls.CHROME_AGENTS)
        else:
            agents = (cls.CHROME_AGENTS + cls.FIREFOX_AGENTS +
                     cls.SAFARI_AGENTS + cls.EDGE_AGENTS)

        return random.choice(agents)

    @classmethod
    def get_matching_headers(cls, user_agent: str) -> Dict[str, str]:
        """Get realistic headers matching the user agent"""
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }

        # Add browser-specific headers
        if 'Chrome' in user_agent:
            headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120"'
            headers['sec-ch-ua-mobile'] = '?0'
            headers['sec-ch-ua-platform'] = '"Windows"'

        return headers


class WebDriverStealth:
    """
    WebDriver Property Hiding
    Techniques from intelligence analysis to hide automation
    """

    @staticmethod
    def get_stealth_script() -> str:
        """
        JavaScript to hide WebDriver properties
        Based on selenium-stealth and undetected-chromedriver techniques
        """
        return """
        // Hide webdriver property
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });

        // Hide automation flags
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });

        // Spoof navigator.languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });

        // Override permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );

        // Hide chrome property
        Object.defineProperty(window, 'chrome', {
            get: () => ({
                runtime: {},
                loadTimes: function() {},
                csi: function() {},
                app: {}
            })
        });

        // Spoof plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                return [
                    {
                        description: "Portable Document Format",
                        filename: "internal-pdf-viewer",
                        name: "Chrome PDF Plugin"
                    },
                    {
                        description: "Portable Document Format",
                        filename: "internal-pdf-viewer",
                        name: "Chrome PDF Viewer"
                    }
                ];
            }
        });
        """

    @staticmethod
    def apply_to_driver(driver):
        """Apply stealth techniques to Selenium WebDriver"""
        try:
            driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': WebDriverStealth.get_stealth_script()
            })
            return True
        except Exception as e:
            print(f"[WARN] Could not apply stealth: {e}")
            return False


class SmartRetryLogic:
    """
    Intelligent Retry with Exponential Backoff
    Based on rate-limiting and throttling intelligence
    """

    def __init__(self,
                 max_retries: int = 5,
                 base_delay: float = 1.0,
                 max_delay: float = 60.0,
                 exponential_base: float = 2.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.retry_count = 0

    def should_retry(self, status_code: Optional[int] = None,
                     exception: Optional[Exception] = None) -> bool:
        """Determine if request should be retried"""
        if self.retry_count >= self.max_retries:
            return False

        # Retry on specific status codes
        retry_codes = {429, 500, 502, 503, 504, 408, 520, 521, 522, 523, 524}
        if status_code and status_code in retry_codes:
            return True

        # Retry on specific exceptions
        if exception:
            retry_exceptions = (
                'ConnectionError', 'Timeout', 'ReadTimeout',
                'ConnectTimeout', 'ProxyError'
            )
            if any(exc in str(type(exception).__name__) for exc in retry_exceptions):
                return True

        return False

    def get_delay(self) -> float:
        """Calculate delay with exponential backoff and jitter"""
        # Exponential backoff
        delay = min(
            self.base_delay * (self.exponential_base ** self.retry_count),
            self.max_delay
        )

        # Add jitter (randomness) to prevent thundering herd
        jitter = delay * 0.1 * random.random()

        return delay + jitter

    def wait(self):
        """Wait before retry"""
        delay = self.get_delay()
        print(f"[RETRY] Attempt {self.retry_count + 1}/{self.max_retries} - "
              f"Waiting {delay:.2f}s...")
        time.sleep(delay)
        self.retry_count += 1

    def reset(self):
        """Reset retry counter"""
        self.retry_count = 0


class EnhancedCookieManager:
    """
    Advanced Cookie and Session Management
    Based on session persistence intelligence
    """

    def __init__(self):
        self.cookies = {}
        self.session_data = {}

    def save_cookies(self, cookies: List[Dict], domain: str):
        """Save cookies for a domain"""
        self.cookies[domain] = {
            'cookies': cookies,
            'timestamp': datetime.now().isoformat(),
            'hash': self._hash_cookies(cookies)
        }

    def load_cookies(self, domain: str) -> Optional[List[Dict]]:
        """Load cookies for a domain"""
        if domain in self.cookies:
            return self.cookies[domain]['cookies']
        return None

    def _hash_cookies(self, cookies: List[Dict]) -> str:
        """Generate hash of cookies for change detection"""
        cookie_str = str(sorted([(c.get('name'), c.get('value')) for c in cookies]))
        return hashlib.md5(cookie_str.encode()).hexdigest()

    def cookies_changed(self, domain: str, new_cookies: List[Dict]) -> bool:
        """Check if cookies have changed"""
        if domain not in self.cookies:
            return True

        old_hash = self.cookies[domain]['hash']
        new_hash = self._hash_cookies(new_cookies)
        return old_hash != new_hash


class BrowserFingerprintRandomizer:
    """
    Browser Fingerprint Randomization
    Makes each request appear to come from different browser
    """

    @staticmethod
    def get_random_screen_resolution() -> tuple:
        """Get realistic screen resolution"""
        resolutions = [
            (1920, 1080),  # Full HD
            (2560, 1440),  # 2K
            (3840, 2160),  # 4K
            (1366, 768),   # HD
            (1440, 900),   # WXGA+
            (1536, 864),   # Common laptop
        ]
        return random.choice(resolutions)

    @staticmethod
    def get_random_timezone() -> str:
        """Get random timezone"""
        timezones = [
            'America/New_York',
            'America/Los_Angeles',
            'America/Chicago',
            'Europe/London',
            'Europe/Paris',
            'Asia/Tokyo',
            'Australia/Sydney'
        ]
        return random.choice(timezones)

    @staticmethod
    def get_random_language() -> str:
        """Get random language preference"""
        languages = [
            'en-US',
            'en-GB',
            'en-CA',
            'en-AU'
        ]
        return random.choice(languages)

    @classmethod
    def get_fingerprint_script(cls) -> str:
        """Get JavaScript to randomize browser fingerprint"""
        width, height = cls.get_random_screen_resolution()

        return f"""
        // Randomize screen properties
        Object.defineProperty(screen, 'width', {{
            get: () => {width}
        }});
        Object.defineProperty(screen, 'height', {{
            get: () => {height}
        }});
        Object.defineProperty(screen, 'availWidth', {{
            get: () => {width}
        }});
        Object.defineProperty(screen, 'availHeight', {{
            get: () => {height - 40}
        }});

        // Randomize timezone
        Date.prototype.getTimezoneOffset = function() {{
            return {random.randint(-720, 720)};
        }};

        // Randomize hardware concurrency
        Object.defineProperty(navigator, 'hardwareConcurrency', {{
            get: () => {random.choice([4, 8, 12, 16])}
        }});

        // Randomize device memory
        Object.defineProperty(navigator, 'deviceMemory', {{
            get: () => {random.choice([4, 8, 16, 32])}
        }});
        """


class CloudflareBypassHelper:
    """
    Cloudflare Challenge Bypass Techniques
    Based on cloudflare-bypass intelligence
    """

    @staticmethod
    def get_cloudflare_headers() -> Dict[str, str]:
        """Get headers that help bypass Cloudflare"""
        return {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers'
        }

    @staticmethod
    def should_use_cloudscraper(response_text: str) -> bool:
        """Detect if Cloudflare challenge is present"""
        cloudflare_indicators = [
            'Checking your browser',
            'Just a moment',
            'cf-browser-verification',
            'cf_clearance',
            '__cf_bm'
        ]
        return any(indicator in response_text for indicator in cloudflare_indicators)


# Export all enhancements
__all__ = [
    'EnhancedUserAgents',
    'WebDriverStealth',
    'SmartRetryLogic',
    'EnhancedCookieManager',
    'BrowserFingerprintRandomizer',
    'CloudflareBypassHelper'
]
