"""
BlackBox Modules
================

Native BlackBox modules for security operations.
All external tools have been removed - this is pure Python.

Categories:
- pentest: Penetration testing automation
- scraper: Web scraping and data extraction
- security: Security analysis tools
- intel: Threat intelligence
- command: Intelligence agents
- integrations: External service integrations
- payloads: Payload generation
- reporting: Report generation
- methodology: Testing methodology
- bugbounty: Bug bounty automation
"""

from .base import ToolWrapper, ToolResult
from .cli import CLIToolWrapper, get_wrapper
from .docker import DockerToolWrapper

__all__ = [
    # Base classes
    "ToolWrapper",
    "ToolResult",
    "CLIToolWrapper",
    "DockerToolWrapper",
    "get_wrapper",
]

__version__ = "2.0.0"
__author__ = "DeadManOfficial"
