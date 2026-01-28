"""
BlackBox Stealth - WAF Bypass & Evasion Tools
=============================================

Tools for bypassing WAFs and security controls.
Note: For authorized testing only.
"""

from typing import Optional, List, Dict, Any
import urllib.request
import urllib.parse
import socket
import ssl


def waf_bypass_scan(domain: str) -> Dict[str, Any]:
    """
    Discover origin IP behind WAF/CDN.

    Methods:
    - DNS history lookup
    - SSL certificate analysis
    - Header leak detection

    Args:
        domain: Target domain
    """
    findings = []

    # Check DNS records
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        findings.append({
            "method": "dns_resolution",
            "ips": ips,
            "note": "Current DNS resolution"
        })
    except socket.gaierror:
        pass

    # Check for direct IP headers
    test_urls = [
        f"https://{domain}",
        f"http://{domain}",
    ]

    for url in test_urls:
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
            })
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = dict(response.headers)

                # Look for origin IP leaks in headers
                leak_headers = [
                    "X-Real-IP", "X-Forwarded-For", "X-Original-Host",
                    "X-Backend-Server", "X-Server-IP", "Via"
                ]

                for header in leak_headers:
                    if header in headers:
                        findings.append({
                            "method": "header_leak",
                            "header": header,
                            "value": headers[header]
                        })

                # Check server header
                if "Server" in headers:
                    findings.append({
                        "method": "server_header",
                        "value": headers["Server"]
                    })

        except Exception:
            continue

    # SSL certificate check
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                findings.append({
                    "method": "ssl_certificate",
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", []))
                })
    except Exception:
        pass

    return {
        "domain": domain,
        "findings": findings,
        "recommendations": [
            "Check DNS history services (SecurityTrails, ViewDNS)",
            "Search Shodan/Censys for SSL cert fingerprint",
            "Test subdomain IPs for origin discovery"
        ]
    }


def waf_bypass_request(
    url: str,
    method: str = "GET",
    data: Optional[Dict] = None,
    encoding_chain: Optional[List[str]] = None,
    fingerprint_rotation: bool = True,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Send request with WAF bypass techniques.

    Args:
        url: Target URL
        method: HTTP method
        data: Request body
        encoding_chain: Encodings to apply (url_encode, double_url, unicode, etc.)
        fingerprint_rotation: Enable fingerprint rotation
        headers: Custom headers
    """
    if encoding_chain is None:
        encoding_chain = ["url_encode"]

    if headers is None:
        headers = {}

    # Apply encoding chain to URL
    encoded_url = url
    for encoding in encoding_chain:
        if encoding == "url_encode":
            parsed = urllib.parse.urlparse(encoded_url)
            encoded_url = f"{parsed.scheme}://{parsed.netloc}{urllib.parse.quote(parsed.path)}"
        elif encoding == "double_url":
            parsed = urllib.parse.urlparse(encoded_url)
            double_encoded = urllib.parse.quote(urllib.parse.quote(parsed.path))
            encoded_url = f"{parsed.scheme}://{parsed.netloc}{double_encoded}"

    # Fingerprint rotation - add varying headers
    if fingerprint_rotation:
        ua_variants = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        import random
        headers["User-Agent"] = random.choice(ua_variants)
        headers["Accept-Language"] = random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"])

    try:
        req = urllib.request.Request(encoded_url, headers=headers, method=method)
        if data:
            req.data = urllib.parse.urlencode(data).encode()

        with urllib.request.urlopen(req, timeout=15) as response:
            return {
                "status": response.status,
                "url_used": encoded_url,
                "encodings_applied": encoding_chain,
                "response_size": len(response.read()),
                "blocked": False
            }

    except urllib.error.HTTPError as e:
        blocked_indicators = [403, 406, 429, 503]
        return {
            "status": e.code,
            "url_used": encoded_url,
            "blocked": e.code in blocked_indicators,
            "waf_detected": e.code in blocked_indicators
        }
    except Exception as e:
        return {"error": str(e)}


def stealth_fetch(
    url: str,
    engine: str = "auto",
    headless: bool = True,
    get_content: bool = False,
    get_cookies: bool = False,
    timeout: int = 30000
) -> Dict[str, Any]:
    """
    Fetch URL with stealth browser.

    Note: Requires playwright or similar browser automation.
    This is a stub that provides guidance.

    Args:
        url: URL to fetch
        engine: Browser engine (auto, playwright)
        headless: Run headless
        get_content: Return page content
        get_cookies: Return cookies
        timeout: Timeout in ms
    """
    return {
        "url": url,
        "note": "Stealth fetch requires browser automation",
        "recommendation": "Use mcp__playwright__browser_navigate for browser-based fetching",
        "alternatives": [
            "mcp__hyperbrowser__browser_use_agent",
            "mcp__firecrawl__firecrawl_scrape"
        ]
    }


def stealth_engines() -> Dict[str, Any]:
    """List available stealth browser engines."""
    return {
        "engines": [
            {"name": "playwright", "status": "available", "mcp": "mcp__playwright__*"},
            {"name": "hyperbrowser", "status": "available", "mcp": "mcp__hyperbrowser__*"},
            {"name": "firecrawl", "status": "available", "mcp": "mcp__firecrawl__*"}
        ]
    }


__all__ = [
    "waf_bypass_scan",
    "waf_bypass_request",
    "stealth_fetch",
    "stealth_engines"
]
