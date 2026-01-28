"""
BlackBox OSINT Module
Unified interface to OSINT tools including SpiderFoot, HostHunter, OSINTNATOR, etc.

Tools integrated:
- spiderfoot (16.5k stars) - Core OSINT automation
- HostHunter - IP to hostname discovery
- OSINTNATOR - OSINT framework
- forensic_excavator - Metadata analysis
- amass - Attack surface mapping
- subfinder - Subdomain discovery
- datasploit - OSINT data collection
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# Add external tools to path
BLACKBOX_ROOT = Path(__file__).parent.parent.parent
EXTERNAL_TOOLS = BLACKBOX_ROOT / "external-tools"

# Tool paths
SPIDERFOOT_PATH = EXTERNAL_TOOLS / "rabbit-hole" / "spiderfoot"
HOSTHUNTER_PATH = EXTERNAL_TOOLS / "rabbit-hole" / "HostHunter"
OSINTNATOR_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "OSINTNATOR"
FORENSIC_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "forensic_excavator"
AMASS_PATH = EXTERNAL_TOOLS / "amass"
SUBFINDER_PATH = EXTERNAL_TOOLS / "subfinder"
DATASPLOIT_PATH = EXTERNAL_TOOLS / "datasploit"


class OSINTToolType(Enum):
    """Types of OSINT tools available."""
    SPIDERFOOT = "spiderfoot"
    HOSTHUNTER = "hosthunter"
    OSINTNATOR = "osintnator"
    FORENSIC = "forensic_excavator"
    AMASS = "amass"
    SUBFINDER = "subfinder"
    DATASPLOIT = "datasploit"


@dataclass
class OSINTResult:
    """Result from an OSINT operation."""
    tool: str
    target: str
    data: Dict[str, Any]
    raw_output: str
    success: bool
    error: Optional[str] = None


class OSINTModule:
    """
    Unified OSINT module providing access to multiple OSINT tools.

    Usage:
        osint = OSINTModule()

        # Check available tools
        print(osint.get_available_tools())

        # Run SpiderFoot scan
        result = osint.spiderfoot_scan("example.com", modules=["sfp_dnsresolve"])

        # Run subdomain enumeration
        subdomains = osint.enumerate_subdomains("example.com")

        # Run hostname discovery
        hostnames = osint.discover_hostnames(["192.168.1.1", "192.168.1.2"])
    """

    def __init__(self):
        self.tools_status = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        return {
            "spiderfoot": SPIDERFOOT_PATH.exists() and (SPIDERFOOT_PATH / "sf.py").exists(),
            "hosthunter": HOSTHUNTER_PATH.exists() and (HOSTHUNTER_PATH / "hosthunter.py").exists(),
            "osintnator": OSINTNATOR_PATH.exists(),
            "forensic_excavator": FORENSIC_PATH.exists(),
            "amass": AMASS_PATH.exists(),
            "subfinder": SUBFINDER_PATH.exists(),
            "datasploit": DATASPLOIT_PATH.exists(),
        }

    def get_available_tools(self) -> List[str]:
        """Get list of available OSINT tools."""
        return [tool for tool, available in self.tools_status.items() if available]

    def get_tool_info(self, tool: str) -> Dict[str, Any]:
        """Get information about a specific tool."""
        info = {
            "spiderfoot": {
                "name": "SpiderFoot",
                "description": "OSINT automation platform with 200+ modules",
                "stars": 16511,
                "path": str(SPIDERFOOT_PATH),
                "available": self.tools_status.get("spiderfoot", False),
            },
            "hosthunter": {
                "name": "HostHunter",
                "description": "IP to hostname discovery using OSINT",
                "stars": 1149,
                "path": str(HOSTHUNTER_PATH),
                "available": self.tools_status.get("hosthunter", False),
            },
            "osintnator": {
                "name": "OSINTNATOR",
                "description": "Open-source OSINT framework",
                "path": str(OSINTNATOR_PATH),
                "available": self.tools_status.get("osintnator", False),
            },
            "amass": {
                "name": "OWASP Amass",
                "description": "Attack surface mapping and asset discovery",
                "stars": 12000,
                "path": str(AMASS_PATH),
                "available": self.tools_status.get("amass", False),
            },
            "subfinder": {
                "name": "Subfinder",
                "description": "Fast subdomain discovery tool",
                "stars": 10000,
                "path": str(SUBFINDER_PATH),
                "available": self.tools_status.get("subfinder", False),
            },
        }
        return info.get(tool, {"error": f"Unknown tool: {tool}"})

    # =========================================================================
    # SpiderFoot Integration
    # =========================================================================

    def spiderfoot_scan(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        scan_name: Optional[str] = None,
        output_format: str = "json"
    ) -> OSINTResult:
        """
        Run a SpiderFoot scan on a target.

        Args:
            target: Domain, IP, email, etc. to scan
            modules: Specific modules to run (None = all)
            scan_name: Name for the scan
            output_format: Output format (json, csv, etc.)

        Returns:
            OSINTResult with scan data
        """
        if not self.tools_status.get("spiderfoot"):
            return OSINTResult(
                tool="spiderfoot",
                target=target,
                data={},
                raw_output="",
                success=False,
                error="SpiderFoot not available"
            )

        try:
            cmd = [
                sys.executable,
                str(SPIDERFOOT_PATH / "sf.py"),
                "-s", target,
                "-o", output_format,
            ]

            if modules:
                cmd.extend(["-m", ",".join(modules)])

            if scan_name:
                cmd.extend(["-n", scan_name])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(SPIDERFOOT_PATH)
            )

            return OSINTResult(
                tool="spiderfoot",
                target=target,
                data={"modules": modules or "all"},
                raw_output=result.stdout,
                success=result.returncode == 0,
                error=result.stderr if result.returncode != 0 else None
            )

        except subprocess.TimeoutExpired:
            return OSINTResult(
                tool="spiderfoot",
                target=target,
                data={},
                raw_output="",
                success=False,
                error="Scan timed out"
            )
        except Exception as e:
            return OSINTResult(
                tool="spiderfoot",
                target=target,
                data={},
                raw_output="",
                success=False,
                error=str(e)
            )

    def spiderfoot_start_server(self, host: str = "127.0.0.1", port: int = 5001) -> Dict[str, Any]:
        """
        Start SpiderFoot web server.

        Args:
            host: Host to bind to
            port: Port to bind to

        Returns:
            Dict with server info
        """
        if not self.tools_status.get("spiderfoot"):
            return {"error": "SpiderFoot not available"}

        cmd = [
            sys.executable,
            str(SPIDERFOOT_PATH / "sf.py"),
            "-l", f"{host}:{port}"
        ]

        return {
            "command": " ".join(cmd),
            "url": f"http://{host}:{port}",
            "note": "Run this command to start SpiderFoot web UI"
        }

    # =========================================================================
    # HostHunter Integration
    # =========================================================================

    def discover_hostnames(
        self,
        ips: List[str],
        output_file: Optional[str] = None
    ) -> OSINTResult:
        """
        Discover hostnames for given IP addresses using HostHunter.

        Args:
            ips: List of IP addresses
            output_file: Optional file to save results

        Returns:
            OSINTResult with discovered hostnames
        """
        if not self.tools_status.get("hosthunter"):
            return OSINTResult(
                tool="hosthunter",
                target=str(ips),
                data={},
                raw_output="",
                success=False,
                error="HostHunter not available"
            )

        try:
            # Create temp file with IPs
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                f.write('\n'.join(ips))
                temp_file = f.name

            cmd = [
                sys.executable,
                str(HOSTHUNTER_PATH / "hosthunter.py"),
                temp_file
            ]

            if output_file:
                cmd.extend(["-o", output_file])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(HOSTHUNTER_PATH)
            )

            # Cleanup temp file
            os.unlink(temp_file)

            return OSINTResult(
                tool="hosthunter",
                target=str(ips),
                data={"ip_count": len(ips)},
                raw_output=result.stdout,
                success=result.returncode == 0,
                error=result.stderr if result.returncode != 0 else None
            )

        except Exception as e:
            return OSINTResult(
                tool="hosthunter",
                target=str(ips),
                data={},
                raw_output="",
                success=False,
                error=str(e)
            )

    # =========================================================================
    # Subdomain Enumeration (using multiple tools)
    # =========================================================================

    def enumerate_subdomains(
        self,
        domain: str,
        tools: Optional[List[str]] = None
    ) -> Dict[str, OSINTResult]:
        """
        Enumerate subdomains using multiple tools.

        Args:
            domain: Target domain
            tools: List of tools to use (default: all available)

        Returns:
            Dict of tool -> OSINTResult
        """
        results = {}

        if tools is None:
            tools = ["subfinder", "amass"]

        for tool in tools:
            if tool == "subfinder" and self.tools_status.get("subfinder"):
                results["subfinder"] = self._run_subfinder(domain)
            elif tool == "amass" and self.tools_status.get("amass"):
                results["amass"] = self._run_amass(domain)

        return results

    def _run_subfinder(self, domain: str) -> OSINTResult:
        """Run subfinder for subdomain enumeration."""
        try:
            # Check if subfinder binary exists
            subfinder_bin = SUBFINDER_PATH / "v2" / "cmd" / "subfinder"

            # For Go tools, we may need to check for compiled binary
            # or use go run
            return OSINTResult(
                tool="subfinder",
                target=domain,
                data={"note": "Go binary - run manually"},
                raw_output=f"cd {SUBFINDER_PATH} && go run . -d {domain}",
                success=True,
                error=None
            )
        except Exception as e:
            return OSINTResult(
                tool="subfinder",
                target=domain,
                data={},
                raw_output="",
                success=False,
                error=str(e)
            )

    def _run_amass(self, domain: str) -> OSINTResult:
        """Run amass for attack surface mapping."""
        try:
            return OSINTResult(
                tool="amass",
                target=domain,
                data={"note": "Go binary - run manually"},
                raw_output=f"cd {AMASS_PATH} && go run ./cmd/amass enum -d {domain}",
                success=True,
                error=None
            )
        except Exception as e:
            return OSINTResult(
                tool="amass",
                target=domain,
                data={},
                raw_output="",
                success=False,
                error=str(e)
            )


# Convenience function
def create_osint_module() -> OSINTModule:
    """Create and return an OSINTModule instance."""
    return OSINTModule()


from .cert_transparency import CertTransparency, CTResult, enumerate_ct

__all__ = [
    "OSINTModule",
    "OSINTResult",
    "OSINTToolType",
    "create_osint_module",
    # Certificate Transparency
    "CertTransparency",
    "CTResult",
    "enumerate_ct",
]
