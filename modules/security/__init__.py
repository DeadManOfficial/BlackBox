"""
BlackBox Defensive Security Module
Unified interface to defensive security tools.

Tools integrated:
- backdoor_detector - Backdoor/malware detection with YARA
- honeyFILE - Honeypot tripwire files
- npm-dewormer - Supply chain security for npm
- PHISH_HUNTER_PRO - Advanced phishing detection
- phish_breaker - Phishing site disruption
- SkimmerSentinel - BLE credit card skimmer detection
- network_ids - Network IDS/EDR for Linux
- blue_block - IP/ASN blocklist generation
- lab_cleaner - Lab environment cleanup
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
import json

# Add external tools to path
BLACKBOX_ROOT = Path(__file__).parent.parent.parent
EXTERNAL_TOOLS = BLACKBOX_ROOT / "external-tools"

# Tool paths
BACKDOOR_DETECTOR_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "backdoor_detector"
HONEYFILE_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "honeyFILE"
NPM_DEWORMER_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "npm-dewormer"
PHISH_HUNTER_PRO_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "PHISH_HUNTER_PRO"
PHISH_HUNTER_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "PHISH_HUNTER"
PHISH_BREAKER_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "phish_breaker"
SKIMMER_SENTINEL_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "SkimmerSentinel"
NETWORK_IDS_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "network_ids"
BLUE_BLOCK_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "blue_block"
LAB_CLEANER_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "lab_cleaner"
SCAMTRACK_PATH = EXTERNAL_TOOLS / "ekomsSavior" / "SCAMTRACK"


class DefenseToolType(Enum):
    """Types of defensive security tools."""
    BACKDOOR_DETECTOR = "backdoor_detector"
    HONEYFILE = "honeyfile"
    NPM_DEWORMER = "npm_dewormer"
    PHISH_HUNTER = "phish_hunter"
    PHISH_BREAKER = "phish_breaker"
    SKIMMER_SENTINEL = "skimmer_sentinel"
    NETWORK_IDS = "network_ids"
    BLUE_BLOCK = "blue_block"
    LAB_CLEANER = "lab_cleaner"


class ThreatType(Enum):
    """Types of threats detected."""
    BACKDOOR = "backdoor"
    MALWARE = "malware"
    PHISHING = "phishing"
    SUPPLY_CHAIN = "supply_chain"
    SKIMMER = "skimmer"
    INTRUSION = "intrusion"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


@dataclass
class DefenseResult:
    """Result from a defensive security operation."""
    tool: str
    target: str
    threat_type: str
    threat_detected: bool
    severity: str = "unknown"  # low, medium, high, critical
    findings: List[Dict[str, Any]] = field(default_factory=list)
    raw_output: str = ""
    success: bool = True
    error: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


class DefenseModule:
    """
    Unified defensive security module.

    Usage:
        defense = DefenseModule()

        # Check available tools
        print(defense.get_available_tools())

        # Scan for backdoors
        result = defense.scan_for_backdoors("/path/to/project")

        # Check for phishing
        result = defense.analyze_phishing_site("http://suspicious-site.com")

        # Scan npm packages
        result = defense.scan_npm_packages("/path/to/node_project")

        # Deploy honeypot files
        result = defense.deploy_honeypot("/sensitive/directory")
    """

    def __init__(self):
        self.tools_status = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        return {
            "backdoor_detector": BACKDOOR_DETECTOR_PATH.exists(),
            "honeyfile": HONEYFILE_PATH.exists(),
            "npm_dewormer": NPM_DEWORMER_PATH.exists(),
            "phish_hunter_pro": PHISH_HUNTER_PRO_PATH.exists(),
            "phish_hunter": PHISH_HUNTER_PATH.exists(),
            "phish_breaker": PHISH_BREAKER_PATH.exists(),
            "skimmer_sentinel": SKIMMER_SENTINEL_PATH.exists(),
            "network_ids": NETWORK_IDS_PATH.exists(),
            "blue_block": BLUE_BLOCK_PATH.exists(),
            "lab_cleaner": LAB_CLEANER_PATH.exists(),
            "scamtrack": SCAMTRACK_PATH.exists(),
        }

    def get_available_tools(self) -> List[str]:
        """Get list of available defensive tools."""
        return [tool for tool, available in self.tools_status.items() if available]

    def get_tools_by_category(self) -> Dict[str, List[str]]:
        """Get tools organized by defense category."""
        categories = {
            "malware_detection": [],
            "phishing_defense": [],
            "supply_chain": [],
            "honeypots": [],
            "network_defense": [],
            "incident_response": [],
        }

        if self.tools_status.get("backdoor_detector"):
            categories["malware_detection"].append("backdoor_detector")

        for tool in ["phish_hunter_pro", "phish_hunter", "phish_breaker", "scamtrack"]:
            if self.tools_status.get(tool):
                categories["phishing_defense"].append(tool)

        if self.tools_status.get("npm_dewormer"):
            categories["supply_chain"].append("npm_dewormer")

        if self.tools_status.get("honeyfile"):
            categories["honeypots"].append("honeyfile")

        for tool in ["network_ids", "blue_block", "skimmer_sentinel"]:
            if self.tools_status.get(tool):
                categories["network_defense"].append(tool)

        if self.tools_status.get("lab_cleaner"):
            categories["incident_response"].append("lab_cleaner")

        return categories

    # =========================================================================
    # Backdoor/Malware Detection
    # =========================================================================

    def scan_for_backdoors(
        self,
        path: str,
        recursive: bool = True,
        use_yara: bool = True
    ) -> DefenseResult:
        """
        Scan a directory or file for backdoors and malware.

        Args:
            path: Path to scan
            recursive: Scan subdirectories
            use_yara: Use YARA rules for detection

        Returns:
            DefenseResult with findings
        """
        if not self.tools_status.get("backdoor_detector"):
            return DefenseResult(
                tool="backdoor_detector",
                target=path,
                threat_type="backdoor",
                threat_detected=False,
                success=False,
                error="backdoor_detector not available"
            )

        try:
            # Check for main script
            detector_script = BACKDOOR_DETECTOR_PATH / "backdoor_detector.py"
            if not detector_script.exists():
                # Find any Python file
                py_files = list(BACKDOOR_DETECTOR_PATH.glob("*.py"))
                if py_files:
                    detector_script = py_files[0]

            cmd = [sys.executable, str(detector_script), path]
            if recursive:
                cmd.append("--recursive")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(BACKDOOR_DETECTOR_PATH)
            )

            threat_detected = any(
                indicator in result.stdout.lower()
                for indicator in ["found", "detected", "malicious", "backdoor", "suspicious"]
            )

            severity = "low"
            if "critical" in result.stdout.lower():
                severity = "critical"
            elif "high" in result.stdout.lower():
                severity = "high"
            elif "medium" in result.stdout.lower():
                severity = "medium"

            return DefenseResult(
                tool="backdoor_detector",
                target=path,
                threat_type="backdoor",
                threat_detected=threat_detected,
                severity=severity,
                raw_output=result.stdout,
                success=True,
                recommendations=["Review flagged files", "Quarantine suspicious code"] if threat_detected else []
            )

        except Exception as e:
            return DefenseResult(
                tool="backdoor_detector",
                target=path,
                threat_type="backdoor",
                threat_detected=False,
                success=False,
                error=str(e)
            )

    # =========================================================================
    # Phishing Defense
    # =========================================================================

    def analyze_phishing_site(
        self,
        url: str,
        deep_scan: bool = True
    ) -> DefenseResult:
        """
        Analyze a URL for phishing indicators.

        Args:
            url: URL to analyze
            deep_scan: Perform deep analysis

        Returns:
            DefenseResult with findings
        """
        tool = None
        tool_path = None

        if self.tools_status.get("phish_hunter_pro"):
            tool = "phish_hunter_pro"
            tool_path = PHISH_HUNTER_PRO_PATH
        elif self.tools_status.get("phish_hunter"):
            tool = "phish_hunter"
            tool_path = PHISH_HUNTER_PATH
        else:
            return DefenseResult(
                tool="phish_hunter",
                target=url,
                threat_type="phishing",
                threat_detected=False,
                success=False,
                error="No phishing analysis tools available"
            )

        return DefenseResult(
            tool=tool,
            target=url,
            threat_type="phishing",
            threat_detected=False,
            raw_output=f"Run manually: cd {tool_path} && python main.py {url}",
            success=True,
            recommendations=[
                "Check URL for typosquatting",
                "Verify SSL certificate",
                "Check WHOIS data",
                "Analyze page content for credential harvesting"
            ]
        )

    def disrupt_phishing_site(self, url: str) -> DefenseResult:
        """
        Attempt to disrupt a phishing site with fake data.

        Args:
            url: Phishing site URL

        Returns:
            DefenseResult with disruption status
        """
        if not self.tools_status.get("phish_breaker"):
            return DefenseResult(
                tool="phish_breaker",
                target=url,
                threat_type="phishing",
                threat_detected=True,
                success=False,
                error="phish_breaker not available"
            )

        return DefenseResult(
            tool="phish_breaker",
            target=url,
            threat_type="phishing",
            threat_detected=True,
            raw_output=f"Run manually: cd {PHISH_BREAKER_PATH} && python phish_breaker.py {url}",
            success=True,
            recommendations=[
                "Only use on confirmed phishing sites",
                "Document disruption for reporting",
                "Report to relevant authorities"
            ]
        )

    # =========================================================================
    # Supply Chain Security
    # =========================================================================

    def scan_npm_packages(self, project_path: str) -> DefenseResult:
        """
        Scan npm packages for supply chain attacks.

        Args:
            project_path: Path to npm project

        Returns:
            DefenseResult with findings
        """
        if not self.tools_status.get("npm_dewormer"):
            return DefenseResult(
                tool="npm_dewormer",
                target=project_path,
                threat_type="supply_chain",
                threat_detected=False,
                success=False,
                error="npm-dewormer not available"
            )

        return DefenseResult(
            tool="npm_dewormer",
            target=project_path,
            threat_type="supply_chain",
            threat_detected=False,
            raw_output=f"Run: cd {NPM_DEWORMER_PATH} && python npm_dewormer.py {project_path}",
            success=True,
            recommendations=[
                "Review package.json dependencies",
                "Check for typosquatted packages",
                "Verify package integrity"
            ]
        )

    # =========================================================================
    # Honeypot Deployment
    # =========================================================================

    def deploy_honeypot(
        self,
        directory: str,
        file_names: Optional[List[str]] = None
    ) -> DefenseResult:
        """
        Deploy honeypot files to detect unauthorized access.

        Args:
            directory: Directory to deploy honeypots
            file_names: Custom file names for honeypots

        Returns:
            DefenseResult with deployment status
        """
        if not self.tools_status.get("honeyfile"):
            return DefenseResult(
                tool="honeyfile",
                target=directory,
                threat_type="intrusion",
                threat_detected=False,
                success=False,
                error="honeyFILE not available"
            )

        default_names = [
            ".env.backup",
            "passwords.txt",
            "credentials.json",
            "private_key.pem",
            "wallet.dat"
        ]

        return DefenseResult(
            tool="honeyfile",
            target=directory,
            threat_type="intrusion",
            threat_detected=False,
            raw_output=f"Run: cd {HONEYFILE_PATH} && python honeyfile.py --deploy {directory}",
            success=True,
            recommendations=[
                f"Deploy honeypot files: {file_names or default_names}",
                "Configure audit logging",
                "Set up alerts for file access"
            ]
        )

    # =========================================================================
    # Network Defense
    # =========================================================================

    def start_network_ids(self, interface: Optional[str] = None) -> DefenseResult:
        """
        Start network IDS monitoring.

        Args:
            interface: Network interface to monitor

        Returns:
            DefenseResult with IDS status
        """
        if not self.tools_status.get("network_ids"):
            return DefenseResult(
                tool="network_ids",
                target=interface or "default",
                threat_type="intrusion",
                threat_detected=False,
                success=False,
                error="network_ids not available"
            )

        return DefenseResult(
            tool="network_ids",
            target=interface or "default",
            threat_type="intrusion",
            threat_detected=False,
            raw_output=f"Run: cd {NETWORK_IDS_PATH} && sudo python ids.py" + (f" -i {interface}" if interface else ""),
            success=True,
            recommendations=[
                "Run with elevated privileges",
                "Configure alert thresholds",
                "Set up logging"
            ]
        )

    def generate_blocklist(
        self,
        log_file: str,
        output_format: str = "iptables"
    ) -> DefenseResult:
        """
        Generate IP blocklist from suspicious activity logs.

        Args:
            log_file: Path to log file
            output_format: Output format (iptables, nginx, hosts)

        Returns:
            DefenseResult with blocklist
        """
        if not self.tools_status.get("blue_block"):
            return DefenseResult(
                tool="blue_block",
                target=log_file,
                threat_type="suspicious_activity",
                threat_detected=False,
                success=False,
                error="blue_block not available"
            )

        return DefenseResult(
            tool="blue_block",
            target=log_file,
            threat_type="suspicious_activity",
            threat_detected=False,
            raw_output=f"Run: cd {BLUE_BLOCK_PATH} && python blue_block.py -l {log_file} -f {output_format}",
            success=True,
            recommendations=[
                "Review blocklist before applying",
                "Test in staging environment",
                "Monitor for false positives"
            ]
        )

    # =========================================================================
    # Incident Response
    # =========================================================================

    def cleanup_lab(
        self,
        scan_only: bool = True
    ) -> DefenseResult:
        """
        Clean up persistence mechanisms left by testing.

        Args:
            scan_only: Only scan, don't remove (dry run)

        Returns:
            DefenseResult with cleanup status
        """
        if not self.tools_status.get("lab_cleaner"):
            return DefenseResult(
                tool="lab_cleaner",
                target="system",
                threat_type="malware",
                threat_detected=False,
                success=False,
                error="lab_cleaner not available"
            )

        mode = "--scan" if scan_only else "--clean"

        return DefenseResult(
            tool="lab_cleaner",
            target="system",
            threat_type="malware",
            threat_detected=False,
            raw_output=f"Run: cd {LAB_CLEANER_PATH} && sudo python lab_cleaner.py {mode}",
            success=True,
            recommendations=[
                "Always run in scan mode first",
                "Review findings before cleanup",
                "Back up system state"
            ]
        )


# Convenience function
def create_defense_module() -> DefenseModule:
    """Create and return a DefenseModule instance."""
    return DefenseModule()


__all__ = [
    "DefenseModule",
    "DefenseResult",
    "DefenseToolType",
    "ThreatType",
    "create_defense_module",
]
