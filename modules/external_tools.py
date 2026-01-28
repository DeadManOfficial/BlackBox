"""
BlackBox External Tools Master Interface
Unified access to all 175+ integrated security tools.

This module provides a single entry point to access all external tools
organized by category.

Usage:
    from modules.external_tools import ExternalTools

    tools = ExternalTools()

    # Access by category
    tools.osint.spiderfoot_scan("example.com")
    tools.web.test_xss("http://example.com/page?p=test")
    tools.defense.scan_for_backdoors("/path/to/project")
    tools.cloud.audit_aws()
    tools.wireless.start_airgeddon()
    tools.darkweb.search("keyword")
    tools.injection.test_sqli("http://example.com?id=1")
    tools.payloads.get_xss_payloads()
    tools.ai.scan_llm("http://api/chat")
"""

from typing import Dict, List, Any, Optional
from pathlib import Path
import sys

# Import all modules
try:
    from .osint import OSINTModule, create_osint_module
except ImportError:
    OSINTModule = None

try:
    from .web_security import WebSecurityModule, create_websec_module
except ImportError:
    WebSecurityModule = None

try:
    from .defense import DefenseModule, create_defense_module
except ImportError:
    DefenseModule = None

try:
    from .cloud import CloudSecurityModule, create_cloud_module
except ImportError:
    CloudSecurityModule = None

try:
    from .wireless import WirelessModule, create_wireless_module
except ImportError:
    WirelessModule = None

try:
    from .darkweb import DarkWebModule, create_darkweb_module
except ImportError:
    DarkWebModule = None

try:
    from .injection import InjectionModule, create_injection_module
except ImportError:
    InjectionModule = None

try:
    from .payloads import PayloadsModule, create_payloads_module
except ImportError:
    PayloadsModule = None

try:
    from .ai_security import AISecurityModule, create_ai_security_module
except ImportError:
    AISecurityModule = None


class ExternalTools:
    """
    Master interface to all external security tools.

    Categories:
        - osint: OSINT and reconnaissance tools
        - web: Web security testing tools
        - defense: Defensive security tools
        - cloud: Cloud security tools
        - wireless: Network and wireless tools
        - darkweb: Dark web intelligence tools
        - injection: SQL/Command injection tools
        - payloads: Wordlists and payloads
        - ai: AI/ML security tools
    """

    def __init__(self):
        """Initialize all tool modules."""
        self._osint = None
        self._web = None
        self._defense = None
        self._cloud = None
        self._wireless = None
        self._darkweb = None
        self._injection = None
        self._payloads = None
        self._ai = None

    @property
    def osint(self) -> Optional['OSINTModule']:
        """OSINT and reconnaissance tools."""
        if self._osint is None and OSINTModule:
            self._osint = create_osint_module()
        return self._osint

    @property
    def web(self) -> Optional['WebSecurityModule']:
        """Web security testing tools."""
        if self._web is None and WebSecurityModule:
            self._web = create_websec_module()
        return self._web

    @property
    def defense(self) -> Optional['DefenseModule']:
        """Defensive security tools."""
        if self._defense is None and DefenseModule:
            self._defense = create_defense_module()
        return self._defense

    @property
    def cloud(self) -> Optional['CloudSecurityModule']:
        """Cloud security tools."""
        if self._cloud is None and CloudSecurityModule:
            self._cloud = create_cloud_module()
        return self._cloud

    @property
    def wireless(self) -> Optional['WirelessModule']:
        """Network and wireless tools."""
        if self._wireless is None and WirelessModule:
            self._wireless = create_wireless_module()
        return self._wireless

    @property
    def darkweb(self) -> Optional['DarkWebModule']:
        """Dark web intelligence tools."""
        if self._darkweb is None and DarkWebModule:
            self._darkweb = create_darkweb_module()
        return self._darkweb

    @property
    def injection(self) -> Optional['InjectionModule']:
        """SQL/Command injection tools."""
        if self._injection is None and InjectionModule:
            self._injection = create_injection_module()
        return self._injection

    @property
    def payloads(self) -> Optional['PayloadsModule']:
        """Wordlists and payloads."""
        if self._payloads is None and PayloadsModule:
            self._payloads = create_payloads_module()
        return self._payloads

    @property
    def ai(self) -> Optional['AISecurityModule']:
        """AI/ML security tools."""
        if self._ai is None and AISecurityModule:
            self._ai = create_ai_security_module()
        return self._ai

    def get_all_available_tools(self) -> Dict[str, List[str]]:
        """Get all available tools organized by category."""
        tools = {}

        if self.osint:
            tools["osint"] = self.osint.get_available_tools()
        if self.web:
            tools["web"] = self.web.get_available_tools()
        if self.defense:
            tools["defense"] = self.defense.get_available_tools()
        if self.cloud:
            tools["cloud"] = self.cloud.get_available_tools()
        if self.wireless:
            tools["wireless"] = self.wireless.get_available_tools()
        if self.darkweb:
            tools["darkweb"] = self.darkweb.get_available_tools()
        if self.injection:
            tools["injection"] = self.injection.get_available_tools()
        if self.payloads:
            tools["payloads"] = self.payloads.get_available_collections()
        if self.ai:
            tools["ai"] = self.ai.get_available_tools()

        return tools

    def get_tool_count(self) -> int:
        """Get total count of available tools."""
        all_tools = self.get_all_available_tools()
        return sum(len(tools) for tools in all_tools.values())

    def print_summary(self):
        """Print summary of available tools."""
        all_tools = self.get_all_available_tools()

        print("=" * 60)
        print("BlackBox External Tools Summary")
        print("=" * 60)

        for category, tools in all_tools.items():
            print(f"\n{category.upper()} ({len(tools)} tools):")
            for tool in tools[:10]:  # Show first 10
                print(f"  - {tool}")
            if len(tools) > 10:
                print(f"  ... and {len(tools) - 10} more")

        print(f"\n{'=' * 60}")
        print(f"Total Tools Available: {self.get_tool_count()}")
        print("=" * 60)


def create_external_tools() -> ExternalTools:
    """Create and return an ExternalTools instance."""
    return ExternalTools()


__all__ = [
    "ExternalTools",
    "create_external_tools",
]
