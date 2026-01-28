"""
BlackBox Dark Web Intelligence Module
Unified interface to dark web and Tor network tools.

Tools integrated:
- TorBot - Tor crawler
- onionscan - Hidden service scanner
- darkdump - Dark web search
- darker - Dark web scraper
- DarkScrape - Dark web scraping
- OnionIngestor - Onion intelligence
- OnionSearch - Onion search
- dark-web-osint-tools - OSINT resources
- pryingdeep - Deep web intelligence
"""

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

BLACKBOX_ROOT = Path(__file__).parent.parent.parent
EXTERNAL_TOOLS = BLACKBOX_ROOT / "external-tools"

# Tool paths
TORBOT_PATH = EXTERNAL_TOOLS / "TorBot"
ONIONSCAN_PATH = EXTERNAL_TOOLS / "onionscan"
DARKDUMP_PATH = EXTERNAL_TOOLS / "darkdump"
DARKER_PATH = EXTERNAL_TOOLS / "darker"
DARKSCRAPE_PATH = EXTERNAL_TOOLS / "DarkScrape"
ONIONINGESTOR_PATH = EXTERNAL_TOOLS / "OnionIngestor"
ONIONSEARCH_PATH = EXTERNAL_TOOLS / "OnionSearch"
DARKWEB_OSINT_PATH = EXTERNAL_TOOLS / "dark-web-osint-tools"
PRYINGDEEP_PATH = EXTERNAL_TOOLS / "pryingdeep"
DARKUS_PATH = EXTERNAL_TOOLS / "Darkus"
TORCRAWL_PATH = EXTERNAL_TOOLS / "TorCrawl.py"
KATANA_DARKWEB_PATH = EXTERNAL_TOOLS / "katana-darkweb"
VIGILANTONION_PATH = EXTERNAL_TOOLS / "VigilantOnion"
DARKWEB_SERVER_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "darkWEB_server"


class DarkWebToolType(Enum):
    TORBOT = "torbot"
    ONIONSCAN = "onionscan"
    DARKDUMP = "darkdump"
    DARKER = "darker"
    DARKSCRAPE = "darkscrape"
    ONIONINGESTOR = "onioningestor"
    ONIONSEARCH = "onionsearch"
    PRYINGDEEP = "pryingdeep"


@dataclass
class DarkWebResult:
    """Result from dark web operation."""
    tool: str
    target: str
    operation: str
    data: Dict[str, Any] = field(default_factory=dict)
    onion_addresses: List[str] = field(default_factory=list)
    raw_output: str = ""
    success: bool = True
    error: Optional[str] = None


class DarkWebModule:
    """
    Unified dark web intelligence module.

    Usage:
        darkweb = DarkWebModule()

        # Crawl onion site
        result = darkweb.crawl_onion("http://example.onion")

        # Scan hidden service
        result = darkweb.scan_hidden_service("example.onion")

        # Search dark web
        result = darkweb.search("keyword")

        # Get OSINT resources
        resources = darkweb.get_osint_resources()
    """

    def __init__(self):
        self.tools_status = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        return {
            "torbot": TORBOT_PATH.exists(),
            "onionscan": ONIONSCAN_PATH.exists(),
            "darkdump": DARKDUMP_PATH.exists(),
            "darker": DARKER_PATH.exists(),
            "darkscrape": DARKSCRAPE_PATH.exists(),
            "onioningestor": ONIONINGESTOR_PATH.exists(),
            "onionsearch": ONIONSEARCH_PATH.exists(),
            "pryingdeep": PRYINGDEEP_PATH.exists(),
            "darkus": DARKUS_PATH.exists(),
            "torcrawl": TORCRAWL_PATH.exists(),
            "katana_darkweb": KATANA_DARKWEB_PATH.exists(),
            "vigilantonion": VIGILANTONION_PATH.exists(),
            "darkweb_osint": DARKWEB_OSINT_PATH.exists(),
        }

    def get_available_tools(self) -> List[str]:
        return [t for t, available in self.tools_status.items() if available]

    def get_tools_by_purpose(self) -> Dict[str, List[str]]:
        """Get tools organized by purpose."""
        purposes = {
            "crawling": [],
            "scanning": [],
            "searching": [],
            "scraping": [],
            "intelligence": [],
            "resources": [],
        }

        for tool in ["torbot", "torcrawl", "katana_darkweb"]:
            if self.tools_status.get(tool):
                purposes["crawling"].append(tool)

        if self.tools_status.get("onionscan"):
            purposes["scanning"].append("onionscan")

        for tool in ["darkdump", "onionsearch"]:
            if self.tools_status.get(tool):
                purposes["searching"].append(tool)

        for tool in ["darker", "darkscrape", "darkus"]:
            if self.tools_status.get(tool):
                purposes["scraping"].append(tool)

        for tool in ["onioningestor", "pryingdeep", "vigilantonion"]:
            if self.tools_status.get(tool):
                purposes["intelligence"].append(tool)

        if self.tools_status.get("darkweb_osint"):
            purposes["resources"].append("darkweb_osint")

        return purposes

    # =========================================================================
    # Crawling
    # =========================================================================

    def crawl_onion(self, url: str, depth: int = 2) -> DarkWebResult:
        """
        Crawl an onion site.

        Args:
            url: Onion URL to crawl
            depth: Crawl depth

        Returns:
            DarkWebResult with crawl data
        """
        if not url.endswith(".onion") and ".onion" not in url:
            return DarkWebResult(
                tool="torbot",
                target=url,
                operation="crawl",
                success=False,
                error="URL must be an .onion address"
            )

        tool = None
        cmd = None

        if self.tools_status.get("torbot"):
            tool = "torbot"
            cmd = f"cd {TORBOT_PATH} && python torBot.py -u {url}"
        elif self.tools_status.get("torcrawl"):
            tool = "torcrawl"
            cmd = f"cd {TORCRAWL_PATH} && python torcrawl.py -u {url} -d {depth}"
        else:
            return DarkWebResult(
                tool="none",
                target=url,
                operation="crawl",
                success=False,
                error="No crawling tools available"
            )

        return DarkWebResult(
            tool=tool,
            target=url,
            operation="crawl",
            data={"depth": depth},
            raw_output=f"Run: {cmd}",
            success=True
        )

    # =========================================================================
    # Scanning
    # =========================================================================

    def scan_hidden_service(self, onion_address: str) -> DarkWebResult:
        """
        Scan a hidden service for information leaks and misconfigurations.

        Args:
            onion_address: Onion address (without http://)

        Returns:
            DarkWebResult with scan findings
        """
        if not self.tools_status.get("onionscan"):
            return DarkWebResult(
                tool="onionscan",
                target=onion_address,
                operation="scan",
                success=False,
                error="onionscan not available"
            )

        return DarkWebResult(
            tool="onionscan",
            target=onion_address,
            operation="scan",
            data={
                "checks": [
                    "Apache mod_status leak",
                    "Open directories",
                    "EXIF metadata",
                    "SSH key fingerprints",
                    "Related clearnet services",
                    "Bitcoin addresses",
                    "Email addresses"
                ]
            },
            raw_output=f"Run: cd {ONIONSCAN_PATH} && ./onionscan {onion_address}",
            success=True
        )

    # =========================================================================
    # Searching
    # =========================================================================

    def search(self, query: str, engine: str = "auto") -> DarkWebResult:
        """
        Search the dark web.

        Args:
            query: Search query
            engine: Search engine to use

        Returns:
            DarkWebResult with search results
        """
        tool = None
        cmd = None

        if engine == "auto":
            if self.tools_status.get("darkdump"):
                tool = "darkdump"
                cmd = f"cd {DARKDUMP_PATH} && python darkdump.py -q \"{query}\""
            elif self.tools_status.get("onionsearch"):
                tool = "onionsearch"
                cmd = f"cd {ONIONSEARCH_PATH} && python onionsearch.py -q \"{query}\""
        else:
            return DarkWebResult(
                tool="none",
                target=query,
                operation="search",
                success=False,
                error="No search tools available"
            )

        if not tool:
            return DarkWebResult(
                tool="none",
                target=query,
                operation="search",
                success=False,
                error="No search tools available"
            )

        return DarkWebResult(
            tool=tool,
            target=query,
            operation="search",
            raw_output=f"Run: {cmd}",
            success=True
        )

    # =========================================================================
    # Intelligence
    # =========================================================================

    def start_intelligence_gathering(self) -> DarkWebResult:
        """
        Start dark web intelligence gathering.

        Returns:
            DarkWebResult with available intelligence tools
        """
        intel_tools = {}

        if self.tools_status.get("onioningestor"):
            intel_tools["onioningestor"] = {
                "description": "Automated onion link collection",
                "command": f"cd {ONIONINGESTOR_PATH} && python run.py"
            }

        if self.tools_status.get("pryingdeep"):
            intel_tools["pryingdeep"] = {
                "description": "Deep web intelligence platform",
                "command": f"cd {PRYINGDEEP_PATH} && python pryingdeep.py"
            }

        if self.tools_status.get("vigilantonion"):
            intel_tools["vigilantonion"] = {
                "description": "Onion monitoring and alerting",
                "command": f"cd {VIGILANTONION_PATH} && python vigilant.py"
            }

        return DarkWebResult(
            tool="intelligence",
            target="darkweb",
            operation="gather",
            data=intel_tools,
            success=True
        )

    # =========================================================================
    # OSINT Resources
    # =========================================================================

    def get_osint_resources(self) -> DarkWebResult:
        """
        Get dark web OSINT resources and tools list.

        Returns:
            DarkWebResult with resource links
        """
        resources = {
            "tools_available": self.get_available_tools(),
            "categories": self.get_tools_by_purpose(),
        }

        if self.tools_status.get("darkweb_osint"):
            resources["resource_path"] = str(DARKWEB_OSINT_PATH)

        return DarkWebResult(
            tool="osint",
            target="resources",
            operation="list",
            data=resources,
            success=True
        )


def create_darkweb_module() -> DarkWebModule:
    return DarkWebModule()


__all__ = ["DarkWebModule", "DarkWebResult", "DarkWebToolType", "create_darkweb_module"]
