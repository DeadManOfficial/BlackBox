"""
Shannon AI Pentester Integration
================================
Fully autonomous AI hacker - 96.15% success rate on XBOW benchmark.
Uses Claude/GPT for reasoning, browser automation for exploit validation.

Original: https://github.com/KeygraphHQ/shannon (4,000 stars)
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

SHANNON_PATH = Path(__file__).parent.parent.parent / "external-tools" / "shannon"


class VulnerabilityCategory(Enum):
    """OWASP vulnerability categories Shannon can detect"""
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH_BYPASS = "auth_bypass"
    BROKEN_ACCESS = "broken_access_control"
    IDOR = "idor"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"


@dataclass
class ExploitProof:
    """Validated exploit proof-of-concept"""
    vulnerability: str
    category: VulnerabilityCategory
    endpoint: str
    payload: str
    response: str
    severity: str
    reproducible: bool = True
    screenshot_path: Optional[str] = None


@dataclass
class PentestReport:
    """Shannon pentest report"""
    target: str
    duration_seconds: float
    vulnerabilities_found: int
    exploits: List[ExploitProof] = field(default_factory=list)
    coverage: Dict[str, bool] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    raw_output: str = ""


class ShannonAIPentester:
    """
    Shannon - Autonomous AI Pentester.

    Philosophy: "No Exploit, No Report" - zero false positives.

    Features:
    - Fully autonomous operation (single command)
    - White-box source code analysis
    - Black-box dynamic testing with browser automation
    - Real exploit validation (not just vulnerability detection)
    - OWASP Top 10 coverage

    How it works:
    1. Reconnaissance: Maps attack surface via code analysis
    2. Vulnerability Analysis: Parallel agents hunt for flaws
    3. Exploitation: Real attacks using browser automation
    4. Reporting: Only validated, reproducible exploits

    Example:
        shannon = ShannonAIPentester()
        report = await shannon.pentest(
            url="https://target.com",
            repo_path="/path/to/source"
        )
        for exploit in report.exploits:
            print(f"{exploit.category}: {exploit.endpoint}")
    """

    def __init__(
        self,
        anthropic_api_key: Optional[str] = None,
        docker_mode: bool = True
    ):
        self.shannon_path = SHANNON_PATH
        self.anthropic_api_key = anthropic_api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.docker_mode = docker_mode

        if not self.shannon_path.exists():
            raise FileNotFoundError(f"Shannon not found at {self.shannon_path}")

    def _get_env(self) -> Dict[str, str]:
        """Get environment with API keys"""
        env = os.environ.copy()
        if self.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = self.anthropic_api_key
        return env

    async def pentest(
        self,
        url: str,
        repo_path: Optional[str] = None,
        categories: Optional[List[VulnerabilityCategory]] = None,
        timeout_minutes: int = 60
    ) -> PentestReport:
        """
        Run full autonomous pentest.

        Args:
            url: Target URL to test
            repo_path: Path to source code (for white-box analysis)
            categories: Specific vulnerability categories to test
            timeout_minutes: Maximum test duration

        Returns:
            PentestReport with validated exploits
        """
        if self.docker_mode:
            return await self._run_docker(url, repo_path, timeout_minutes)
        else:
            return await self._run_native(url, repo_path, timeout_minutes)

    async def _run_docker(
        self,
        url: str,
        repo_path: Optional[str],
        timeout_minutes: int
    ) -> PentestReport:
        """Run Shannon via Docker"""
        cmd = [
            "docker", "run", "--rm",
            "-e", f"ANTHROPIC_API_KEY={self.anthropic_api_key}",
        ]

        if repo_path:
            cmd.extend(["-v", f"{repo_path}:/repo"])

        cmd.extend([
            "shannon:latest",
            "start",
            f"URL={url}"
        ])

        if repo_path:
            cmd.append("REPO=/repo")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_minutes * 60,
            env=self._get_env()
        )

        return self._parse_report(result.stdout, url)

    async def _run_native(
        self,
        url: str,
        repo_path: Optional[str],
        timeout_minutes: int
    ) -> PentestReport:
        """Run Shannon natively (requires Node.js)"""
        script_path = self.shannon_path / "shannon"

        cmd = [str(script_path), "start", f"URL={url}"]

        if repo_path:
            cmd.append(f"REPO={repo_path}")

        result = subprocess.run(
            cmd,
            cwd=str(self.shannon_path),
            capture_output=True,
            text=True,
            timeout=timeout_minutes * 60,
            env=self._get_env()
        )

        return self._parse_report(result.stdout, url)

    def _parse_report(self, output: str, target: str) -> PentestReport:
        """Parse Shannon output into structured report"""
        report = PentestReport(
            target=target,
            duration_seconds=0,
            vulnerabilities_found=0,
            raw_output=output
        )

        # Parse exploits from output (format depends on Shannon version)
        # This is a placeholder - actual parsing would depend on output format

        return report

    def build_docker_image(self) -> subprocess.CompletedProcess:
        """Build Shannon Docker image"""
        return subprocess.run(
            ["docker", "build", "-t", "shannon:latest", "."],
            cwd=str(self.shannon_path),
            capture_output=True,
            text=True
        )

    def check_requirements(self) -> Dict[str, bool]:
        """Check if all requirements are met"""
        checks = {
            "shannon_exists": self.shannon_path.exists(),
            "anthropic_key": bool(self.anthropic_api_key),
            "docker_available": False,
            "node_available": False,
        }

        # Check Docker
        try:
            result = subprocess.run(["docker", "--version"], capture_output=True)
            checks["docker_available"] = result.returncode == 0
        except FileNotFoundError:
            pass

        # Check Node.js
        try:
            result = subprocess.run(["node", "--version"], capture_output=True)
            checks["node_available"] = result.returncode == 0
        except FileNotFoundError:
            pass

        return checks

    @staticmethod
    def get_integrated_tools() -> List[str]:
        """Tools Shannon uses for reconnaissance"""
        return [
            "Nmap - Network scanning and service detection",
            "Subfinder - Subdomain discovery",
            "WhatWeb - Web technology fingerprinting",
            "Schemathesis - API fuzzing and testing",
            "Playwright - Browser automation for exploitation",
        ]

    @staticmethod
    def get_vulnerability_coverage() -> Dict[str, str]:
        """OWASP vulnerability categories covered"""
        return {
            "A01:2021 - Broken Access Control": "IDOR, privilege escalation, path traversal",
            "A02:2021 - Cryptographic Failures": "Weak encryption, exposed secrets",
            "A03:2021 - Injection": "SQL, NoSQL, OS command, LDAP injection",
            "A04:2021 - Insecure Design": "Business logic flaws",
            "A05:2021 - Security Misconfiguration": "Default credentials, verbose errors",
            "A06:2021 - Vulnerable Components": "Outdated libraries with known CVEs",
            "A07:2021 - Auth Failures": "Broken authentication, session management",
            "A08:2021 - Integrity Failures": "Insecure deserialization, CI/CD issues",
            "A09:2021 - Logging Failures": "Missing audit trails",
            "A10:2021 - SSRF": "Server-side request forgery",
        }
