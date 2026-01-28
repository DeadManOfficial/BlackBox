#!/usr/bin/env python3
"""
BlackBox AI - Reconnaissance Module
Native Python implementation - no external tools.
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
import socket
import ssl
import urllib.request
import urllib.parse
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition, ToolResult

logger = logging.getLogger(__name__)


class NativeSubdomainEnumerator:
    """Native subdomain enumeration using DNS and web sources."""

    name = "subdomain_enum"
    description = "Native subdomain enumeration"

    # Common subdomain prefixes to check
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "mx1", "mx2", "blog", "dev", "staging", "api",
        "app", "admin", "test", "demo", "beta", "alpha", "cdn", "static", "assets",
        "img", "images", "media", "portal", "secure", "vpn", "remote", "gateway",
        "auth", "login", "sso", "dashboard", "panel", "cp", "cpanel", "webdisk",
        "shop", "store", "cart", "checkout", "pay", "payment", "billing",
        "support", "help", "docs", "wiki", "forum", "community", "status",
        "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "build",
        "prod", "production", "uat", "qa", "stage", "internal", "intranet",
        "m", "mobile", "wap", "autodiscover", "autoconfig", "calendar", "meet"
    ]

    def __init__(self):
        self._available = True

    def is_available(self) -> bool:
        return self._available

    def enumerate(self, domain: str, timeout: int = 120) -> ToolResult:
        """Enumerate subdomains for a domain."""
        found = []
        errors = []

        def check_subdomain(sub: str) -> Optional[str]:
            fqdn = f"{sub}.{domain}"
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub
                      for sub in self.COMMON_SUBDOMAINS}

            for future in as_completed(futures, timeout=timeout):
                try:
                    result = future.result()
                    if result:
                        found.append(result)
                except Exception as e:
                    errors.append(str(e))

        return ToolResult(
            success=True,
            output="\n".join(found),
            data={
                "domain": domain,
                "subdomains": found,
                "count": len(found),
                "method": "dns_bruteforce"
            }
        )


class NativeHTTPProber:
    """Native HTTP probing using urllib."""

    name = "http_prober"
    description = "Native HTTP endpoint probing"

    def __init__(self):
        self._available = True

    def is_available(self) -> bool:
        return self._available

    def probe(self, targets: List[str], timeout: int = 60) -> ToolResult:
        """Probe HTTP endpoints."""
        results = []

        def probe_target(target: str) -> Dict[str, Any]:
            if not target.startswith(('http://', 'https://')):
                target = f"https://{target}"

            result = {
                "url": target,
                "alive": False,
                "status_code": None,
                "title": None,
                "server": None,
                "content_length": None
            }

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"}
                )

                with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                    result["alive"] = True
                    result["status_code"] = response.getcode()
                    result["server"] = response.headers.get("Server")
                    result["content_length"] = response.headers.get("Content-Length")

                    # Try to get title
                    try:
                        content = response.read(8192).decode('utf-8', errors='ignore')
                        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.I)
                        if title_match:
                            result["title"] = title_match.group(1).strip()
                    except:
                        pass

            except urllib.error.HTTPError as e:
                result["alive"] = True
                result["status_code"] = e.code
            except Exception:
                result["alive"] = False

            return result

        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split('\n') if t.strip()]

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(probe_target, t): t for t in targets}

            for future in as_completed(futures, timeout=timeout):
                try:
                    results.append(future.result())
                except Exception:
                    pass

        live_hosts = [r for r in results if r["alive"]]

        return ToolResult(
            success=True,
            output=json.dumps(live_hosts, indent=2),
            data={
                "total": len(targets),
                "alive": len(live_hosts),
                "dead": len(targets) - len(live_hosts),
                "results": results,
                "live_hosts": live_hosts
            }
        )


class ReconnaissanceModule(BaseModule):
    """
    Reconnaissance module for target discovery and OSINT.
    Native Python implementation - no external tools required.
    """

    name = "reconnaissance"
    version = "2.0.0"
    category = ModuleCategory.RECON
    description = "Target reconnaissance and OSINT tools (native)"
    author = "BlackBox Team"
    tags = ["recon", "osint", "subdomain", "discovery"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.subfinder = NativeSubdomainEnumerator()
        self.httpx = NativeHTTPProber()
        self._client = None
        self._mcp = None
        self.logger = logging.getLogger(f"blackbox.{self.name}")

    def initialize(self) -> bool:
        """Initialize the module."""
        self.status = ModuleStatus.LOADED
        return True

    def on_load(self) -> bool:
        """Initialize module"""
        self.logger.info(f"Loading {self.name} module v{self.version}")
        tools_status = {
            "subfinder": self.subfinder.is_available(),
            "httpx": self.httpx.is_available()
        }
        available = sum(tools_status.values())
        self.logger.info(f"Tools available: {available}/{len(tools_status)}")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        """Register MCP tools"""
        self._mcp = mcp
        self._client = client
        tools = []

        @mcp.tool()
        def recon_subdomains(domain: str, timeout: int = 120) -> Dict[str, Any]:
            """
            Enumerate subdomains for a target domain.

            Args:
                domain: Target domain to enumerate
                timeout: Execution timeout in seconds

            Returns:
                Dictionary with discovered subdomains
            """
            self.logger.info(f"Enumerating subdomains for: {domain}")
            result = self.subfinder.enumerate(domain=domain, timeout=timeout)
            return {
                "success": result.success,
                "subdomains": result.data.get("subdomains", []),
                "count": result.data.get("count", 0),
                "domain": domain
            }

        tools.append(ToolDefinition(
            name="recon_subdomains",
            description="Enumerate subdomains for a target domain",
            handler=recon_subdomains
        ))

        @mcp.tool()
        def recon_probe_http(targets: str, timeout: int = 60) -> Dict[str, Any]:
            """
            Probe HTTP endpoints for live hosts and information.

            Args:
                targets: Newline-separated URLs to probe
                timeout: Execution timeout in seconds

            Returns:
                Dictionary with probe results
            """
            self.logger.info(f"Probing HTTP targets")
            result = self.httpx.probe(targets=targets, timeout=timeout)
            return {
                "success": result.success,
                "alive": result.data.get("alive", 0),
                "total": result.data.get("total", 0),
                "live_hosts": result.data.get("live_hosts", [])
            }

        tools.append(ToolDefinition(
            name="recon_probe_http",
            description="Probe HTTP endpoints for live hosts",
            handler=recon_probe_http
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        """Register Flask API routes"""
        from flask import request, jsonify
        routes = []

        @app.route('/api/recon/subdomains', methods=['POST'])
        def api_recon_subdomains():
            data = request.get_json() or {}
            domain = data.get('domain')
            if not domain:
                return jsonify({"error": "domain required", "success": False}), 400
            result = self.subfinder.enumerate(domain=domain, timeout=data.get('timeout', 120))
            return jsonify(result.data)

        routes.append(RouteDefinition(
            path="/api/recon/subdomains",
            methods=["POST"],
            handler=api_recon_subdomains,
            description="Enumerate subdomains"
        ))

        @app.route('/api/recon/probe', methods=['POST'])
        def api_recon_probe():
            data = request.get_json() or {}
            targets = data.get('targets')
            if not targets:
                return jsonify({"error": "targets required", "success": False}), 400
            result = self.httpx.probe(targets=targets, timeout=data.get('timeout', 60))
            return jsonify(result.data)

        routes.append(RouteDefinition(
            path="/api/recon/probe",
            methods=["POST"],
            handler=api_recon_probe,
            description="Probe HTTP endpoints"
        ))

        @app.route('/api/recon/status', methods=['GET'])
        def api_recon_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(
            path="/api/recon/status",
            methods=["GET"],
            handler=api_recon_status,
            description="Module status"
        ))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        """Check module health"""
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value if hasattr(self.status, 'value') else str(self.status),
            "healthy": True,
            "native": True,
            "tools": {
                "subfinder": self.subfinder.is_available(),
                "httpx": self.httpx.is_available()
            }
        }


Module = ReconnaissanceModule
