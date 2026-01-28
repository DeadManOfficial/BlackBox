"""
TLS Fingerprint Client - Bypass JA3/JA4 Detection

Wraps curl_cffi to impersonate real browser TLS signatures.
Defeats Cloudflare, Akamai, DataDome, and PerimeterX.

Author: DeadManOfficial
Version: 1.0.0
"""

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, List, Callable, Awaitable
from datetime import datetime
import random


class BrowserProfile(Enum):
    """Browser profiles for TLS impersonation"""
    # Chrome profiles
    CHROME_120 = "chrome120"
    CHROME_119 = "chrome119"
    CHROME_118 = "chrome118"
    CHROME_110 = "chrome110"
    CHROME_107 = "chrome107"
    CHROME_104 = "chrome104"
    CHROME_100 = "chrome100"
    CHROME_99 = "chrome99"

    # Firefox profiles
    FIREFOX_120 = "firefox120"
    FIREFOX_117 = "firefox117"
    FIREFOX_110 = "firefox110"
    FIREFOX_102 = "firefox102"

    # Safari profiles
    SAFARI_17_0 = "safari17_0"
    SAFARI_16_0 = "safari16_0"
    SAFARI_15_5 = "safari15_5"

    # Edge profiles
    EDGE_120 = "edge120"
    EDGE_101 = "edge101"
    EDGE_99 = "edge99"


@dataclass
class TLSConfig:
    """Configuration for TLS client"""
    browser: BrowserProfile = BrowserProfile.CHROME_120
    proxy: Optional[str] = None
    timeout: int = 30
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10

    # Header customization
    custom_headers: Dict[str, str] = field(default_factory=dict)
    randomize_headers: bool = True

    # Retry configuration
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_on_status: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class TLSResponse:
    """Response from TLS request"""
    status_code: int
    headers: Dict[str, str]
    text: str
    url: str
    elapsed_ms: float

    # TLS info
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None

    # Cookies
    cookies: Dict[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        """Parse response as JSON"""
        return json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class TLSClient:
    """
    High-performance TLS client with browser fingerprint impersonation.

    Uses curl_cffi to match real browser JA3/JA4 signatures, defeating
    modern anti-bot systems like Cloudflare and Akamai.
    """

    # User agents matched to browser profiles
    USER_AGENTS = {
        BrowserProfile.CHROME_120: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        BrowserProfile.CHROME_119: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        BrowserProfile.CHROME_118: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        BrowserProfile.FIREFOX_120: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        BrowserProfile.FIREFOX_117: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
        BrowserProfile.SAFARI_17_0: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        BrowserProfile.EDGE_120: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    }

    # Common headers to randomize
    ACCEPT_LANGUAGES = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9",
        "en-US,en;q=0.9,es;q=0.8",
        "en-US,en;q=0.8,de;q=0.6",
    ]

    ACCEPT_ENCODINGS = [
        "gzip, deflate, br",
        "gzip, deflate, br, zstd",
        "gzip, deflate",
    ]

    def __init__(self, config: Optional[TLSConfig] = None):
        self.config = config or TLSConfig()
        self._session = None
        self._curl_cffi_available = False
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if curl_cffi is available"""
        try:
            from curl_cffi.requests import AsyncSession
            self._curl_cffi_available = True
        except ImportError:
            self._curl_cffi_available = False

    def _get_headers(self, custom: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Generate browser-like headers"""
        ua = self.USER_AGENTS.get(
            self.config.browser,
            self.USER_AGENTS[BrowserProfile.CHROME_120]
        )

        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": random.choice(self.ACCEPT_LANGUAGES) if self.config.randomize_headers else "en-US,en;q=0.9",
            "Accept-Encoding": random.choice(self.ACCEPT_ENCODINGS) if self.config.randomize_headers else "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        }

        # Add custom headers
        headers.update(self.config.custom_headers)
        if custom:
            headers.update(custom)

        return headers

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> TLSResponse:
        """Perform GET request with TLS impersonation"""
        return await self._request("GET", url, headers=headers, params=params, cookies=cookies)

    async def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> TLSResponse:
        """Perform POST request with TLS impersonation"""
        return await self._request("POST", url, headers=headers, data=data, json_data=json_data, cookies=cookies)

    async def _request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> TLSResponse:
        """Internal request method with retry logic"""

        request_headers = self._get_headers(headers)
        start_time = datetime.now()

        for attempt in range(self.config.max_retries):
            try:
                if self._curl_cffi_available:
                    response = await self._curl_cffi_request(
                        method, url, request_headers, params, data, json_data, cookies
                    )
                else:
                    response = await self._aiohttp_fallback(
                        method, url, request_headers, params, data, json_data, cookies
                    )

                # Check if we should retry
                if response.status_code in self.config.retry_on_status and attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                    continue

                response.elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
                return response

            except Exception as e:
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                    continue
                raise

        raise Exception(f"Max retries ({self.config.max_retries}) exceeded for {url}")

    async def _curl_cffi_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, str]],
        data: Optional[Dict[str, Any]],
        json_data: Optional[Dict[str, Any]],
        cookies: Optional[Dict[str, str]]
    ) -> TLSResponse:
        """Make request using curl_cffi with browser impersonation"""
        from curl_cffi.requests import AsyncSession

        async with AsyncSession(impersonate=self.config.browser.value) as session:
            response = await session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
                proxy=self.config.proxy,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects
            )

            return TLSResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                text=response.text,
                url=str(response.url),
                elapsed_ms=0,
                cookies=dict(response.cookies) if response.cookies else {}
            )

    async def _aiohttp_fallback(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, str]],
        data: Optional[Dict[str, Any]],
        json_data: Optional[Dict[str, Any]],
        cookies: Optional[Dict[str, str]]
    ) -> TLSResponse:
        """Fallback to aiohttp if curl_cffi not available"""
        import aiohttp

        connector = aiohttp.TCPConnector(ssl=self.config.verify_ssl)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async with session.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
                proxy=self.config.proxy,
                allow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects
            ) as response:
                text = await response.text()

                return TLSResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    text=text,
                    url=str(response.url),
                    elapsed_ms=0,
                    cookies={k: v.value for k, v in response.cookies.items()}
                )


class ProxyWaterfall:
    """
    Proxy waterfall rotation strategy.

    Attempts requests with cheapest proxy tier first, escalating to
    more expensive/reliable tiers on failure.

    Tier 1: Datacenter IPs (cheap, fast, low trust)
    Tier 2: Residential IPs (medium cost, high trust)
    Tier 3: Mobile IPs (expensive, highest trust)
    """

    @dataclass
    class ProxyTier:
        name: str
        proxies: List[str]
        cost_per_gb: float
        success_rate: float = 0.0
        total_requests: int = 0
        successful_requests: int = 0

    def __init__(self):
        self.tiers: List[ProxyWaterfall.ProxyTier] = []
        self._current_tier_index = 0

    def add_tier(self, name: str, proxies: List[str], cost_per_gb: float):
        """Add a proxy tier"""
        self.tiers.append(self.ProxyTier(
            name=name,
            proxies=proxies,
            cost_per_gb=cost_per_gb
        ))

    def get_proxy(self, tier_index: int = 0) -> Optional[str]:
        """Get a proxy from specified tier"""
        if tier_index >= len(self.tiers):
            return None

        tier = self.tiers[tier_index]
        if not tier.proxies:
            return None

        return random.choice(tier.proxies)

    def report_success(self, tier_index: int):
        """Report successful request for tier"""
        if tier_index < len(self.tiers):
            tier = self.tiers[tier_index]
            tier.total_requests += 1
            tier.successful_requests += 1
            tier.success_rate = tier.successful_requests / tier.total_requests

    def report_failure(self, tier_index: int):
        """Report failed request for tier"""
        if tier_index < len(self.tiers):
            tier = self.tiers[tier_index]
            tier.total_requests += 1
            tier.success_rate = tier.successful_requests / tier.total_requests

    async def request_with_waterfall(
        self,
        client: TLSClient,
        method: str,
        url: str,
        **kwargs
    ) -> TLSResponse:
        """
        Attempt request starting from cheapest tier, escalating on failure.
        """
        last_error = None

        for tier_index, tier in enumerate(self.tiers):
            proxy = self.get_proxy(tier_index)

            try:
                # Update client proxy
                original_proxy = client.config.proxy
                client.config.proxy = proxy

                if method.upper() == "GET":
                    response = await client.get(url, **kwargs)
                elif method.upper() == "POST":
                    response = await client.post(url, **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                # Check for anti-bot block
                if response.status_code in [403, 429, 503]:
                    self.report_failure(tier_index)
                    client.config.proxy = original_proxy
                    continue

                self.report_success(tier_index)
                client.config.proxy = original_proxy
                return response

            except Exception as e:
                self.report_failure(tier_index)
                last_error = e
                continue

        raise Exception(f"All proxy tiers exhausted. Last error: {last_error}")

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics for all tiers"""
        return {
            "tiers": [
                {
                    "name": tier.name,
                    "proxy_count": len(tier.proxies),
                    "cost_per_gb": tier.cost_per_gb,
                    "success_rate": f"{tier.success_rate * 100:.1f}%",
                    "total_requests": tier.total_requests
                }
                for tier in self.tiers
            ],
            "total_requests": sum(t.total_requests for t in self.tiers),
            "estimated_cost": self._estimate_cost()
        }

    def _estimate_cost(self, avg_request_kb: float = 50) -> float:
        """Estimate total cost based on usage"""
        total_cost = 0
        for tier in self.tiers:
            gb_used = (tier.total_requests * avg_request_kb) / (1024 * 1024)
            total_cost += gb_used * tier.cost_per_gb
        return round(total_cost, 4)


# Convenience function for quick setup
def create_stealth_client(
    browser: BrowserProfile = BrowserProfile.CHROME_120,
    proxy: Optional[str] = None
) -> TLSClient:
    """Create a TLS client with stealth configuration"""
    config = TLSConfig(
        browser=browser,
        proxy=proxy,
        randomize_headers=True,
        max_retries=3
    )
    return TLSClient(config)


# Example usage
async def example():
    # Basic usage
    client = create_stealth_client(BrowserProfile.CHROME_120)
    response = await client.get("https://httpbin.org/headers")
    print(f"Status: {response.status_code}")
    print(f"Headers sent: {response.json()}")

    # With proxy waterfall
    waterfall = ProxyWaterfall()
    waterfall.add_tier("datacenter", ["http://dc1:8080", "http://dc2:8080"], cost_per_gb=0.50)
    waterfall.add_tier("residential", ["http://res1:8080"], cost_per_gb=5.00)
    waterfall.add_tier("mobile", ["http://mob1:8080"], cost_per_gb=15.00)

    response = await waterfall.request_with_waterfall(
        client, "GET", "https://example.com"
    )
    print(f"Stats: {waterfall.get_stats()}")


if __name__ == "__main__":
    asyncio.run(example())
