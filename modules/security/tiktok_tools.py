"""
TikTok Security Testing Tools
X-Bogus signature generation and API interaction

Usage:
    from modules.security.tiktok_tools import TikTokTools, generate_xbogus

    # Generate X-Bogus signature
    sig = generate_xbogus(params, user_agent)

    # Full API testing
    tt = TikTokTools()
    tt.test_api_endpoint(endpoint, params)
"""

import hashlib
import time
import random
import string
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class XBogusGenerator:
    """
    X-Bogus signature generator for TikTok API.

    Note: This is a simplified implementation for security research.
    Full implementation requires reverse engineering the actual algorithm.
    """

    # Known X-Bogus constants from reverse engineering
    CHARSET = "Dkdpgh4ZKsQB80/Mfvw36XI1R25-WUAlEi7NLboqYTOPuzmFjJnryx9HVGcaStCe"

    def __init__(self, user_agent: str = None):
        self.user_agent = user_agent or self._default_user_agent()

    def _default_user_agent(self) -> str:
        """Generate realistic mobile user agent."""
        return "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"

    def _generate_random_string(self, length: int = 8) -> str:
        """Generate random string component."""
        return ''.join(random.choices(self.CHARSET, k=length))

    def _calculate_hash(self, data: str) -> str:
        """Calculate hash component."""
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def generate(self, params: Dict[str, Any], timestamp: int = None) -> str:
        """
        Generate X-Bogus signature for given parameters.

        Args:
            params: API request parameters
            timestamp: Unix timestamp (default: current time)

        Returns:
            X-Bogus signature string
        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)

        # Serialize parameters
        param_string = urlencode(sorted(params.items()))

        # Create signature base
        sig_base = f"{param_string}{self.user_agent}{timestamp}"

        # Calculate hash
        hash_component = self._calculate_hash(sig_base)

        # Generate X-Bogus format: DFSz[random][hash][suffix]
        random_part = self._generate_random_string(4)
        suffix = self._generate_random_string(8)

        return f"DFSz{random_part}{hash_component}{suffix}"


class MsTokenGenerator:
    """Generate msToken for TikTok API authentication."""

    @staticmethod
    def generate(length: int = 128) -> str:
        """Generate msToken of specified length."""
        chars = string.ascii_letters + string.digits + "-_"
        return ''.join(random.choices(chars, k=length))


class TikTokTools:
    """TikTok security testing toolkit."""

    # TikTok API endpoints
    API_ENDPOINTS = {
        "user_info": "https://www.tiktok.com/api/user/detail/",
        "user_posts": "https://www.tiktok.com/api/post/item_list/",
        "video_info": "https://www.tiktok.com/api/item/detail/",
        "search": "https://www.tiktok.com/api/search/general/full/",
        "comments": "https://www.tiktok.com/api/comment/list/",
        "trending": "https://www.tiktok.com/api/recommend/item_list/",
    }

    # Mobile API endpoints (different signatures)
    MOBILE_ENDPOINTS = {
        "aweme_detail": "https://api-h2.tiktokv.com/aweme/v1/aweme/detail/",
        "user_profile": "https://api-h2.tiktokv.com/aweme/v1/user/profile/other/",
        "feed": "https://api-h2.tiktokv.com/aweme/v1/feed/",
    }

    def __init__(self, user_agent: str = None):
        self.xbogus = XBogusGenerator(user_agent)
        self.mstoken = MsTokenGenerator()
        self.user_agent = user_agent or self.xbogus.user_agent

    def _get_base_params(self) -> Dict[str, Any]:
        """Get base parameters for API requests."""
        return {
            "aid": "1988",
            "app_language": "en",
            "app_name": "tiktok_web",
            "browser_language": "en-US",
            "browser_name": "Mozilla",
            "browser_online": "true",
            "browser_platform": "Linux armv81",
            "browser_version": "5.0 (Linux; Android 12)",
            "channel": "tiktok_web",
            "device_id": self._generate_device_id(),
            "device_platform": "web_mobile",
            "focus_state": "true",
            "from_page": "user",
            "history_len": str(random.randint(1, 10)),
            "is_fullscreen": "false",
            "is_page_visible": "true",
            "os": "android",
            "priority_region": "US",
            "referer": "",
            "region": "US",
            "screen_height": "896",
            "screen_width": "414",
            "tz_name": "America/New_York",
            "webcast_language": "en",
        }

    def _generate_device_id(self) -> str:
        """Generate device ID."""
        return ''.join(random.choices(string.digits, k=19))

    def build_signed_url(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Build signed URL with X-Bogus and msToken.

        Args:
            endpoint: API endpoint key or full URL
            params: Additional parameters

        Returns:
            Dict with URL and headers
        """
        # Get base URL
        if endpoint in self.API_ENDPOINTS:
            base_url = self.API_ENDPOINTS[endpoint]
        elif endpoint in self.MOBILE_ENDPOINTS:
            base_url = self.MOBILE_ENDPOINTS[endpoint]
        else:
            base_url = endpoint

        # Merge parameters
        all_params = self._get_base_params()
        if params:
            all_params.update(params)

        # Add tokens
        all_params["msToken"] = self.mstoken.generate()

        # Generate X-Bogus
        xbogus = self.xbogus.generate(all_params)
        all_params["X-Bogus"] = xbogus

        # Build URL
        query_string = urlencode(all_params)
        full_url = f"{base_url}?{query_string}"

        # Build headers
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://www.tiktok.com/",
            "Origin": "https://www.tiktok.com",
        }

        return {
            "url": full_url,
            "headers": headers,
            "params": all_params,
            "xbogus": xbogus,
        }

    def test_endpoint(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test TikTok API endpoint.

        Args:
            endpoint: API endpoint key or URL
            params: Request parameters

        Returns:
            Response data or error info
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        signed = self.build_signed_url(endpoint, params)

        try:
            response = requests.get(
                signed["url"],
                headers=signed["headers"],
                timeout=30
            )

            return {
                "status_code": response.status_code,
                "success": response.status_code == 200,
                "response_length": len(response.content),
                "xbogus_used": signed["xbogus"],
                "data": response.json() if response.headers.get("content-type", "").startswith("application/json") else None
            }
        except Exception as e:
            return {"error": str(e)}

    def enumerate_endpoints(self) -> List[Dict[str, Any]]:
        """Test all known endpoints for accessibility."""
        results = []

        for name, url in {**self.API_ENDPOINTS, **self.MOBILE_ENDPOINTS}.items():
            result = self.test_endpoint(name)
            result["endpoint_name"] = name
            result["endpoint_url"] = url
            results.append(result)

        return results


# Convenience functions
def generate_xbogus(params: Dict[str, Any], user_agent: str = None) -> str:
    """Quick X-Bogus generation."""
    gen = XBogusGenerator(user_agent)
    return gen.generate(params)


def generate_mstoken(length: int = 128) -> str:
    """Quick msToken generation."""
    return MsTokenGenerator.generate(length)


def get_signed_request(endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Quick signed request builder."""
    tools = TikTokTools()
    return tools.build_signed_url(endpoint, params)
