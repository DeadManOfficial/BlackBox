"""
Endpoint Discovery Module

Discovers and maps API endpoints through various techniques:
- JavaScript bundle analysis
- Source map extraction
- Directory brute forcing
- Pattern-based discovery
- Swagger/OpenAPI detection
"""

import re
import json
import asyncio
import aiohttp
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from urllib.parse import urljoin, urlparse


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint"""
    path: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    auth_required: bool = False
    params: List[str] = field(default_factory=list)
    source: str = ""  # How it was discovered
    response_sample: Optional[str] = None


@dataclass
class EndpointMap:
    """Complete endpoint map for a target"""
    base_url: str
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    swagger_url: Optional[str] = None
    graphql_url: Optional[str] = None
    websocket_url: Optional[str] = None
    technologies: Set[str] = field(default_factory=set)


class EndpointDiscovery:
    """
    Discovers API endpoints through multiple techniques.

    Features:
    - JavaScript analysis for endpoint patterns
    - Common path enumeration
    - Swagger/OpenAPI detection
    - GraphQL introspection
    - WebSocket endpoint detection
    """

    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/v1", "/v2", "/v3",
        "/rest", "/rest/api",
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json", "/openapi.yaml",
        "/api-docs", "/api/docs", "/docs/api",
        "/health", "/healthz", "/status", "/_status",
        "/metrics", "/prometheus",
        "/admin", "/admin/api", "/dashboard/api",
        "/internal", "/internal/api",
        "/debug", "/debug/api",
        "/.well-known/openapi.json",
    ]

    COMMON_CRUD_ENDPOINTS = [
        "/users", "/user", "/accounts", "/account",
        "/auth", "/login", "/logout", "/register", "/signup",
        "/token", "/tokens", "/oauth", "/oauth2",
        "/sessions", "/session",
        "/profiles", "/profile", "/me",
        "/settings", "/config", "/configuration",
        "/messages", "/notifications",
        "/files", "/uploads", "/media",
        "/search", "/query",
        "/webhooks", "/callbacks",
        "/logs", "/events", "/audit",
    ]

    def __init__(self, concurrency: int = 10, timeout: float = 10.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': 'application/json, text/html, */*',
            }
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def discover(self, base_url: str,
                      js_urls: Optional[List[str]] = None,
                      deep: bool = False) -> EndpointMap:
        """
        Discover endpoints for a target.

        Args:
            base_url: Base URL of the target
            js_urls: JavaScript bundle URLs to analyze
            deep: Perform deep enumeration
        """
        endpoint_map = EndpointMap(base_url=base_url)

        async with self:
            # Phase 1: Check common paths
            await self._check_common_paths(base_url, endpoint_map)

            # Phase 2: Detect API documentation
            await self._detect_api_docs(base_url, endpoint_map)

            # Phase 3: Analyze JavaScript if provided
            if js_urls:
                await self._analyze_javascript(js_urls, endpoint_map)

            # Phase 4: Deep enumeration if requested
            if deep:
                await self._deep_enumeration(base_url, endpoint_map)

            # Phase 5: Detect WebSocket endpoints
            await self._detect_websocket(base_url, endpoint_map)

        return endpoint_map

    async def _check_common_paths(self, base_url: str, endpoint_map: EndpointMap):
        """Check common API paths"""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_path(path: str):
            async with semaphore:
                url = urljoin(base_url, path)
                try:
                    async with self.session.get(url, allow_redirects=False) as resp:
                        if resp.status < 400:
                            content_type = resp.headers.get('Content-Type', '')
                            endpoint_map.endpoints.append(DiscoveredEndpoint(
                                path=path,
                                method="GET",
                                status_code=resp.status,
                                content_type=content_type,
                                source="common_path_enum"
                            ))

                            # Detect technologies from response
                            if 'json' in content_type:
                                endpoint_map.technologies.add('json-api')
                            if 'graphql' in path.lower():
                                endpoint_map.graphql_url = url
                            if 'swagger' in path.lower() or 'openapi' in path.lower():
                                endpoint_map.swagger_url = url

                except:
                    pass

        await asyncio.gather(*[check_path(p) for p in self.COMMON_API_PATHS])

    async def _detect_api_docs(self, base_url: str, endpoint_map: EndpointMap):
        """Detect and parse API documentation"""
        swagger_paths = [
            "/swagger.json", "/swagger/v1/swagger.json",
            "/api-docs", "/api/swagger.json",
            "/openapi.json", "/v3/api-docs",
        ]

        for path in swagger_paths:
            url = urljoin(base_url, path)
            try:
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        try:
                            spec = json.loads(content)
                            endpoint_map.swagger_url = url
                            self._parse_openapi_spec(spec, endpoint_map)
                            return
                        except json.JSONDecodeError:
                            pass
            except:
                pass

    def _parse_openapi_spec(self, spec: Dict, endpoint_map: EndpointMap):
        """Parse OpenAPI/Swagger specification"""
        paths = spec.get('paths', {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    params = []
                    for param in details.get('parameters', []):
                        params.append(param.get('name', ''))

                    auth_required = bool(details.get('security', []))

                    endpoint_map.endpoints.append(DiscoveredEndpoint(
                        path=path,
                        method=method.upper(),
                        auth_required=auth_required,
                        params=params,
                        source="openapi_spec"
                    ))

    async def _analyze_javascript(self, js_urls: List[str], endpoint_map: EndpointMap):
        """Analyze JavaScript bundles for endpoints"""
        from .js_intel import JSIntelligence

        intel = JSIntelligence()

        for js_url in js_urls:
            try:
                result = intel.analyze_url(js_url)
                for ep in result.endpoints:
                    endpoint_map.endpoints.append(DiscoveredEndpoint(
                        path=ep.path,
                        method=ep.method,
                        auth_required=ep.auth_required,
                        source="javascript_analysis"
                    ))
                endpoint_map.technologies.update(result.technologies)
            except:
                pass

    async def _deep_enumeration(self, base_url: str, endpoint_map: EndpointMap):
        """Deep endpoint enumeration using discovered paths"""
        discovered_paths = [ep.path for ep in endpoint_map.endpoints]

        # Generate variations
        variations = set()
        for path in discovered_paths:
            parts = path.strip('/').split('/')
            if len(parts) > 1:
                # Add parent paths
                for i in range(1, len(parts)):
                    variations.add('/' + '/'.join(parts[:i]))

                # Add common sub-paths
                for sub in ['list', 'create', 'update', 'delete', 'search', 'export', 'import']:
                    variations.add(path + '/' + sub)

        # Add CRUD variations
        for crud_path in self.COMMON_CRUD_ENDPOINTS:
            for prefix in ['/api', '/api/v1', '/v1', '']:
                variations.add(prefix + crud_path)

        # Check variations
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_variation(path: str):
            if path in [ep.path for ep in endpoint_map.endpoints]:
                return
            async with semaphore:
                url = urljoin(base_url, path)
                try:
                    async with self.session.get(url, allow_redirects=False) as resp:
                        if resp.status < 400 and resp.status != 301:
                            endpoint_map.endpoints.append(DiscoveredEndpoint(
                                path=path,
                                method="GET",
                                status_code=resp.status,
                                source="deep_enumeration"
                            ))
                except:
                    pass

        await asyncio.gather(*[check_variation(p) for p in list(variations)[:100]])

    async def _detect_websocket(self, base_url: str, endpoint_map: EndpointMap):
        """Detect WebSocket endpoints"""
        parsed = urlparse(base_url)
        ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'

        ws_paths = ['/', '/ws', '/websocket', '/socket', '/realtime', '/live']

        for path in ws_paths:
            ws_url = f"{ws_scheme}://{parsed.netloc}{path}"
            try:
                import websockets
                async with websockets.connect(ws_url, open_timeout=3) as ws:
                    endpoint_map.websocket_url = ws_url
                    endpoint_map.technologies.add('websocket')
                    break
            except:
                pass

    def generate_report(self, endpoint_map: EndpointMap) -> str:
        """Generate markdown report"""
        report = f"""# Endpoint Discovery Report

## Target
- **Base URL:** {endpoint_map.base_url}
- **Swagger URL:** {endpoint_map.swagger_url or 'Not found'}
- **GraphQL URL:** {endpoint_map.graphql_url or 'Not found'}
- **WebSocket URL:** {endpoint_map.websocket_url or 'Not found'}

## Technologies
{chr(10).join(f'- {t}' for t in sorted(endpoint_map.technologies)) or '- None detected'}

## Endpoints ({len(endpoint_map.endpoints)})

| Method | Path | Status | Auth | Source |
|--------|------|--------|------|--------|
"""
        for ep in sorted(endpoint_map.endpoints, key=lambda x: x.path):
            auth = '🔒' if ep.auth_required else '🔓'
            status = ep.status_code or '-'
            report += f"| {ep.method} | `{ep.path}` | {status} | {auth} | {ep.source} |\n"

        return report


async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python endpoint_discovery.py <base_url> [js_url...]")
        sys.exit(1)

    base_url = sys.argv[1]
    js_urls = sys.argv[2:] if len(sys.argv) > 2 else None

    discovery = EndpointDiscovery()
    async with discovery:
        result = await discovery.discover(base_url, js_urls, deep=True)
        print(discovery.generate_report(result))


if __name__ == "__main__":
    asyncio.run(main())
