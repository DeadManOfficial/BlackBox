#!/usr/bin/env python3
"""
BlackBox AI - Dark Web Module
==============================

Dark web and Tor network tools:
- OnionSearch (search aggregator)
- onionscan (site investigation)
- TorCrawl (web crawler)
- TorBot (OSINT)
- Tor proxy management
"""

import sys
import os
from pathlib import Path

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition, ToolWrapper, ToolResult
from modules.cli import CLIToolWrapper
from modules.docker import DockerToolWrapper
from typing import Dict, Any, List, Optional
import logging
import json
import subprocess

logger = logging.getLogger(__name__)


class OnionSearchWrapper(CLIToolWrapper):
    """Wrapper for OnionSearch .onion search aggregator"""
    name = "onionsearch"
    description = "Search multiple .onion search engines"

    def _find_tool(self) -> Optional[str]:
        import shutil
        path = shutil.which("onionsearch")
        if not path:
            for p in ["./external-tools/OnionSearch/onionsearch/core.py",
                     "./external-tools/OnionSearch",
                     "./external-tools/OnionSearch/onionsearch"]:
                if os.path.exists(p):
                    return p
        return path

    def build_command(self, query: str, engines: str = "ahmia,torch",
                     limit: int = 100, **kwargs) -> List[str]:
        command = ["python3", self.tool_path, "--search", query]

        if engines:
            command.extend(["--engines", engines])
        command.extend(["--limit", str(limit)])

        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        results = []
        for line in stdout.split('\n'):
            if '.onion' in line:
                results.append(line.strip())

        return {
            "results": results,
            "count": len(results),
            "raw_output": stdout
        }


class TorCrawlWrapper(CLIToolWrapper):
    """Wrapper for TorCrawl .onion crawler"""
    name = "torcrawl"
    description = "Crawl .onion websites through Tor"

    def _find_tool(self) -> Optional[str]:
        for p in ["./external-tools/TorCrawl.py/torcrawl.py",
                 "./external-tools/TorCrawl.py/torcrawl.py"]:
            if os.path.exists(p):
                return p
        return None

    def build_command(self, url: str, depth: int = 1,
                     pause: int = 1, **kwargs) -> List[str]:
        command = ["python3", self.tool_path, "-u", url]
        command.extend(["-d", str(depth)])
        command.extend(["-p", str(pause)])
        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        links = []
        for line in stdout.split('\n'):
            if 'http' in line and '.onion' in line:
                links.append(line.strip())

        return {
            "links": list(set(links)),
            "count": len(set(links)),
            "raw_output": stdout
        }


class TorBotWrapper(CLIToolWrapper):
    """Wrapper for TorBot dark web OSINT"""
    name = "torbot"
    description = "Dark web OSINT tool"

    def _find_tool(self) -> Optional[str]:
        for p in ["./external-tools/TorBot/main.py",
                 "./external-tools/TorBot"]:
            if os.path.exists(p):
                return p
        return None

    def build_command(self, url: str, save: bool = True,
                     mail: bool = False, **kwargs) -> List[str]:
        command = ["python3", self.tool_path, "-u", url]

        if save:
            command.append("-s")
        if mail:
            command.append("-m")

        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "raw_output": stdout,
            "lines": stdout.strip().split('\n') if stdout else []
        }


class TorManager:
    """Manage Tor proxy for dark web operations"""

    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 9050):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_url = f"socks5://{proxy_host}:{proxy_port}"

    def is_running(self) -> bool:
        """Check if Tor is running"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()
            return result == 0
        except:
            return False

    def get_exit_ip(self) -> Optional[str]:
        """Get current Tor exit node IP"""
        if not self.is_running():
            return None

        try:
            import requests
            proxies = {
                'http': self.proxy_url,
                'https': self.proxy_url
            }
            resp = requests.get('https://check.torproject.org/api/ip',
                              proxies=proxies, timeout=10)
            data = resp.json()
            if data.get('IsTor'):
                return data.get('IP')
        except:
            pass
        return None

    def start_docker(self) -> bool:
        """Start Tor using Docker"""
        try:
            subprocess.run([
                "docker", "run", "-d", "--name", "blackbox-tor",
                "-p", f"{self.proxy_port}:9050",
                "dperson/torproxy"
            ], capture_output=True, timeout=30)
            return True
        except:
            return False

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.is_running(),
            "proxy_url": self.proxy_url,
            "exit_ip": self.get_exit_ip()
        }


class DarkwebModule(BaseModule):
    """
    Dark Web Module for BlackBox.

    Provides tools for dark web reconnaissance and monitoring.
    """

    name = "darkweb"
    version = "1.0.0"
    category = ModuleCategory.SCRAPER
    description = "Dark web and Tor network tools"
    author = "BlackBox Team"
    tags = ["darkweb", "tor", "onion", "osint"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        # Tool wrappers
        self.onionsearch = OnionSearchWrapper()
        self.torcrawl = TorCrawlWrapper()
        self.torbot = TorBotWrapper()

        # Tor manager
        tor_config = config.get('tor', {}) if config else {}
        self.tor = TorManager(
            proxy_host=tor_config.get('proxy_host', '127.0.0.1'),
            proxy_port=tor_config.get('proxy_port', 9050)
        )

    def on_load(self) -> bool:
        self.logger.info(f"Loading {self.name} module v{self.version}")

        tools = {
            "onionsearch": self.onionsearch.is_available(),
            "torcrawl": self.torcrawl.is_available(),
            "torbot": self.torbot.is_available(),
            "tor_proxy": self.tor.is_running()
        }

        available = sum(tools.values())
        self.logger.info(f"Dark web tools available: {available}/{len(tools)}")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        tools = []

        @mcp.tool()
        def darkweb_search(query: str, engines: str = "ahmia,torch",
                         limit: int = 50, timeout: int = 120) -> Dict[str, Any]:
            """
            Search dark web using multiple .onion search engines.

            Args:
                query: Search query
                engines: Comma-separated list of engines (ahmia,torch,darksearch)
                limit: Max results per engine
                timeout: Execution timeout

            Returns:
                Search results from dark web
            """
            self.logger.info(f"Searching dark web for: {query}")
            result = self.onionsearch.execute(
                query=query, engines=engines, limit=limit, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="darkweb_search",
            description="Search dark web engines",
            handler=darkweb_search,
            category="darkweb",
            tags=["search", "onion"]
        ))

        @mcp.tool()
        def darkweb_crawl(url: str, depth: int = 1,
                        timeout: int = 300) -> Dict[str, Any]:
            """
            Crawl an .onion website.

            Args:
                url: .onion URL to crawl
                depth: Crawl depth
                timeout: Execution timeout

            Returns:
                Crawled links and data
            """
            self.logger.info(f"Crawling .onion site: {url}")
            result = self.torcrawl.execute(url=url, depth=depth, timeout=timeout)
            return result.to_dict()

        tools.append(ToolDefinition(
            name="darkweb_crawl",
            description="Crawl .onion websites",
            handler=darkweb_crawl,
            category="darkweb",
            tags=["crawl", "onion"]
        ))

        @mcp.tool()
        def darkweb_tor_status() -> Dict[str, Any]:
            """
            Check Tor proxy status.

            Returns:
                Tor proxy status and exit IP
            """
            return self.tor.status()

        tools.append(ToolDefinition(
            name="darkweb_tor_status",
            description="Check Tor proxy status",
            handler=darkweb_tor_status,
            category="darkweb",
            tags=["tor", "status"]
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        from flask import request, jsonify
        routes = []

        @app.route('/api/darkweb/search', methods=['POST'])
        def api_darkweb_search():
            data = request.get_json() or {}
            query = data.get('query')
            if not query:
                return jsonify({"error": "query required"}), 400
            result = self.onionsearch.execute(
                query=query,
                engines=data.get('engines', 'ahmia,torch'),
                limit=data.get('limit', 50)
            )
            return jsonify(result.to_dict())

        routes.append(RouteDefinition(path="/api/darkweb/search", methods=["POST"],
                                     handler=api_darkweb_search, description="Dark web search"))

        @app.route('/api/darkweb/crawl', methods=['POST'])
        def api_darkweb_crawl():
            data = request.get_json() or {}
            url = data.get('url')
            if not url:
                return jsonify({"error": "url required"}), 400
            result = self.torcrawl.execute(url=url, depth=data.get('depth', 1))
            return jsonify(result.to_dict())

        routes.append(RouteDefinition(path="/api/darkweb/crawl", methods=["POST"],
                                     handler=api_darkweb_crawl, description="Crawl .onion"))

        @app.route('/api/darkweb/tor/status', methods=['GET'])
        def api_tor_status():
            return jsonify(self.tor.status())

        routes.append(RouteDefinition(path="/api/darkweb/tor/status", methods=["GET"],
                                     handler=api_tor_status, description="Tor status"))

        @app.route('/api/darkweb/status', methods=['GET'])
        def api_darkweb_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(path="/api/darkweb/status", methods=["GET"],
                                     handler=api_darkweb_status, description="Module status"))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "healthy": self.tor.is_running(),
            "tools": {
                "onionsearch": self.onionsearch.is_available(),
                "torcrawl": self.torcrawl.is_available(),
                "torbot": self.torbot.is_available()
            },
            "tor": self.tor.status()
        }


Module = DarkwebModule
