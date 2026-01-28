"""
BlackBox Recon - Reconnaissance Tools
=====================================

API and endpoint discovery tools.
"""

import json
import urllib.request
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, urljoin


# Common API paths to test
API_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql",
    "/swagger", "/swagger.json", "/swagger-ui",
    "/openapi", "/openapi.json",
    "/docs", "/redoc",
    "/health", "/healthz", "/status",
    "/metrics", "/prometheus",
    "/admin", "/admin/api",
    "/internal", "/internal/api",
    "/.well-known/openid-configuration",
    "/oauth", "/oauth/token", "/oauth/authorize",
    "/auth", "/auth/login", "/auth/token",
    "/users", "/user", "/me", "/profile",
    "/config", "/settings", "/env",
    "/debug", "/trace", "/actuator",
]


def api_enumerate(
    base_url: str,
    wordlist: str = "common",
    methods: Optional[List[str]] = None,
    auth_header: Optional[str] = None,
    fuzz_params: bool = True,
    detect_versions: bool = True,
    concurrent: int = 10,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Discover and enumerate API endpoints.

    Args:
        base_url: Base URL of the API
        wordlist: Wordlist to use (common, full, graphql, rest)
        methods: HTTP methods to test
        auth_header: Authorization header value
        fuzz_params: Fuzz for parameters
        detect_versions: Detect API versions
        concurrent: Concurrent requests (not implemented in sync version)
        headers: Custom headers
    """
    if methods is None:
        methods = ["GET", "POST", "OPTIONS"]

    if headers is None:
        headers = {"User-Agent": "BlackBox-Recon/1.0"}

    if auth_header:
        headers["Authorization"] = auth_header

    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    discovered = []
    tested = 0

    for path in API_WORDLIST:
        url = urljoin(base, path)
        tested += 1

        for method in methods:
            try:
                req = urllib.request.Request(url, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=5) as response:
                    status = response.status
                    content_type = response.headers.get("Content-Type", "")
                    body = response.read().decode('utf-8', errors='ignore')[:1000]

                    discovered.append({
                        "path": path,
                        "url": url,
                        "method": method,
                        "status": status,
                        "content_type": content_type,
                        "is_api": "json" in content_type.lower() or "xml" in content_type.lower(),
                        "size": len(body)
                    })
                    break  # Found with this method, skip others

            except urllib.error.HTTPError as e:
                if e.code in [401, 403]:
                    discovered.append({
                        "path": path,
                        "url": url,
                        "method": method,
                        "status": e.code,
                        "note": "Protected endpoint",
                        "auth_required": True
                    })
                    break
            except:
                continue

    # Detect API versions
    versions_found = []
    if detect_versions:
        for endpoint in discovered:
            path = endpoint.get("path", "")
            for v in ["v1", "v2", "v3", "v4"]:
                if v in path:
                    versions_found.append(v)
        versions_found = list(set(versions_found))

    return {
        "base_url": base_url,
        "endpoints_tested": tested,
        "endpoints_found": len(discovered),
        "discovered": discovered,
        "api_versions": versions_found,
        "methods_tested": methods
    }


def tech_fingerprint(url: str) -> Dict[str, Any]:
    """
    Fingerprint technology stack.

    Args:
        url: URL to fingerprint
    """
    technologies = []

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlackBox-Recon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            headers_dict = dict(response.headers)
            body = response.read().decode('utf-8', errors='ignore')

            # Header-based detection
            server = headers_dict.get("Server", "")
            if server:
                technologies.append({"type": "server", "name": server, "source": "header"})

            powered_by = headers_dict.get("X-Powered-By", "")
            if powered_by:
                technologies.append({"type": "framework", "name": powered_by, "source": "header"})

            # Cookie-based detection
            cookies = headers_dict.get("Set-Cookie", "")
            if "PHPSESSID" in cookies:
                technologies.append({"type": "language", "name": "PHP", "source": "cookie"})
            if "JSESSIONID" in cookies:
                technologies.append({"type": "language", "name": "Java", "source": "cookie"})
            if "ASP.NET" in cookies:
                technologies.append({"type": "framework", "name": "ASP.NET", "source": "cookie"})

            # Body-based detection
            body_indicators = {
                "React": ["react", "_reactRootContainer", "data-reactroot"],
                "Vue": ["v-cloak", "vue", "__vue__"],
                "Angular": ["ng-app", "ng-controller", "angular"],
                "Next.js": ["__NEXT_DATA__", "_next/static"],
                "Nuxt": ["__NUXT__", "_nuxt/"],
                "WordPress": ["wp-content", "wp-includes", "wordpress"],
                "Django": ["csrfmiddlewaretoken", "django"],
                "Laravel": ["laravel_session"],
                "Rails": ["rails", "csrf-token"],
            }

            for tech, indicators in body_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        technologies.append({"type": "framework", "name": tech, "source": "body"})
                        break

    except Exception as e:
        return {"error": str(e)}

    return {
        "url": url,
        "technologies": technologies,
        "count": len(technologies)
    }


__all__ = ["api_enumerate", "tech_fingerprint"]
