"""
Nuclei Vulnerability Scanner Integration
========================================

Enterprise-grade vulnerability scanning with 10,000+ community templates.
Integrates with DeadMan Ultimate Scraper for automated security assessments.

Author: DeadMan Security Research
License: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Optional

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class TemplateCategory(Enum):
    """Nuclei template categories."""
    CVES = "cves"
    VULNERABILITIES = "vulnerabilities"
    EXPOSURES = "exposures"
    MISCONFIGURATIONS = "misconfiguration"
    TECHNOLOGIES = "technologies"
    DEFAULT_LOGINS = "default-logins"
    TAKEOVERS = "takeovers"
    FILE = "file"
    NETWORK = "network"
    HEADLESS = "headless"
    SSL = "ssl"
    DNS = "dns"


@dataclass
class NucleiVulnerability:
    """Represents a vulnerability found by Nuclei."""
    template_id: str
    template_name: str
    severity: Severity
    host: str
    matched_at: str
    ip: str = ""
    timestamp: str = ""
    matcher_name: str = ""
    extracted_results: list[str] = field(default_factory=list)
    curl_command: str = ""
    request: str = ""
    response: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def cvss_score(self) -> float:
        """Estimate CVSS score based on severity."""
        scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
            Severity.UNKNOWN: 0.0
        }
        return scores.get(self.severity, 0.0)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity.value,
            "host": self.host,
            "matched_at": self.matched_at,
            "ip": self.ip,
            "timestamp": self.timestamp,
            "matcher_name": self.matcher_name,
            "extracted_results": self.extracted_results,
            "curl_command": self.curl_command,
            "cvss_estimate": self.cvss_score,
            "metadata": self.metadata
        }


@dataclass
class ScanConfig:
    """Configuration for Nuclei scan."""
    templates: list[str] = field(default_factory=list)
    template_categories: list[TemplateCategory] = field(default_factory=list)
    severity_filter: list[Severity] = field(default_factory=list)
    exclude_templates: list[str] = field(default_factory=list)
    rate_limit: int = 150
    bulk_size: int = 25
    concurrency: int = 25
    timeout: int = 10
    retries: int = 1
    max_host_errors: int = 30
    headless: bool = False
    follow_redirects: bool = True
    include_response: bool = False
    custom_headers: dict[str, str] = field(default_factory=dict)
    proxy: str = ""


@dataclass
class ScanResult:
    """Complete scan result."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: list[NucleiVulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    templates_executed: int = 0
    requests_made: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def summary(self) -> dict:
        """Get vulnerability summary by severity."""
        summary = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "summary": self.summary,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "errors": self.errors,
            "templates_executed": self.templates_executed,
            "requests_made": self.requests_made
        }


class NucleiScanner:
    """
    Nuclei vulnerability scanner integration.

    Features:
    - Async scanning with real-time results
    - Custom template support
    - Severity filtering
    - Rate limiting and concurrency control
    - Proxy support (including TOR)
    - Result correlation and deduplication
    """

    def __init__(
        self,
        templates_path: Optional[Path] = None,
        nuclei_path: Optional[str] = None
    ):
        """
        Initialize Nuclei scanner.

        Args:
            templates_path: Path to nuclei-templates directory
            nuclei_path: Path to nuclei binary (auto-detected if not provided)
        """
        self.templates_path = templates_path or Path.home() / "nuclei-templates"
        self.nuclei_path = nuclei_path or shutil.which("nuclei")
        self._custom_templates: list[str] = []

    def is_installed(self) -> bool:
        """Check if Nuclei is installed."""
        return self.nuclei_path is not None and Path(self.nuclei_path).exists()

    def get_version(self) -> Optional[str]:
        """Get Nuclei version."""
        if not self.is_installed():
            return None
        try:
            result = asyncio.run(self._run_command(["nuclei", "-version"]))
            return result[0].strip()
        except Exception:
            return None

    async def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        if not self.is_installed():
            logger.error("Nuclei is not installed")
            return False

        try:
            stdout, stderr, code = await self._run_command(
                ["nuclei", "-update-templates"],
                timeout=300
            )
            return code == 0
        except Exception as e:
            logger.error(f"Failed to update templates: {e}")
            return False

    async def scan(
        self,
        target: str,
        config: Optional[ScanConfig] = None,
        callback: Optional[Callable[[NucleiVulnerability], None]] = None
    ) -> ScanResult:
        """
        Run Nuclei scan against target.

        Args:
            target: URL or file containing URLs
            config: Scan configuration
            callback: Optional callback for real-time vulnerability notifications

        Returns:
            ScanResult with all findings
        """
        if not self.is_installed():
            raise RuntimeError("Nuclei is not installed. Run: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")

        config = config or ScanConfig()
        result = ScanResult(target=target, start_time=datetime.now())

        cmd = self._build_command(target, config)

        try:
            async for vuln in self._execute_scan(cmd):
                result.vulnerabilities.append(vuln)
                if callback:
                    callback(vuln)

        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Scan error: {e}")

        result.end_time = datetime.now()
        return result

    async def scan_multiple(
        self,
        targets: list[str],
        config: Optional[ScanConfig] = None
    ) -> list[ScanResult]:
        """Scan multiple targets concurrently."""
        tasks = [self.scan(target, config) for target in targets]
        return await asyncio.gather(*tasks)

    async def scan_with_custom_template(
        self,
        target: str,
        template_content: str,
        config: Optional[ScanConfig] = None
    ) -> ScanResult:
        """
        Run scan with a custom template.

        Args:
            target: Target URL
            template_content: YAML content of custom template
            config: Additional scan configuration
        """
        config = config or ScanConfig()

        # Write template to temp file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.yaml',
            delete=False
        ) as f:
            f.write(template_content)
            template_path = f.name

        try:
            config.templates = [template_path]
            return await self.scan(target, config)
        finally:
            Path(template_path).unlink(missing_ok=True)

    def add_custom_template(self, template_path: str) -> None:
        """Add a custom template to use in scans."""
        if Path(template_path).exists():
            self._custom_templates.append(template_path)

    def _build_command(self, target: str, config: ScanConfig) -> list[str]:
        """Build Nuclei command with configuration."""
        cmd = [
            "nuclei",
            "-u", target,
            "-json",
            "-silent",
            "-rate-limit", str(config.rate_limit),
            "-bulk-size", str(config.bulk_size),
            "-concurrency", str(config.concurrency),
            "-timeout", str(config.timeout),
            "-retries", str(config.retries),
            "-max-host-error", str(config.max_host_errors),
        ]

        # Templates
        if config.templates:
            cmd.extend(["-t", ",".join(config.templates)])
        elif config.template_categories:
            categories = [c.value for c in config.template_categories]
            cmd.extend(["-t", ",".join(categories)])

        # Add custom templates
        for template in self._custom_templates:
            cmd.extend(["-t", template])

        # Severity filter
        if config.severity_filter:
            severities = [s.value for s in config.severity_filter]
            cmd.extend(["-severity", ",".join(severities)])

        # Exclude templates
        if config.exclude_templates:
            cmd.extend(["-exclude", ",".join(config.exclude_templates)])

        # Options
        if config.headless:
            cmd.append("-headless")

        if config.follow_redirects:
            cmd.extend(["-follow-redirects"])

        if config.include_response:
            cmd.append("-include-rr")

        # Headers
        for key, value in config.custom_headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

        # Proxy
        if config.proxy:
            cmd.extend(["-proxy", config.proxy])

        return cmd

    async def _execute_scan(
        self,
        cmd: list[str]
    ) -> AsyncIterator[NucleiVulnerability]:
        """Execute Nuclei scan and yield vulnerabilities."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        async for line in process.stdout:
            try:
                data = json.loads(line.decode().strip())
                yield self._parse_result(data)
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Failed to parse result: {e}")
                continue

        await process.wait()

    def _parse_result(self, data: dict) -> NucleiVulnerability:
        """Parse Nuclei JSON output into vulnerability object."""
        info = data.get("info", {})

        severity_str = info.get("severity", "unknown").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.UNKNOWN

        return NucleiVulnerability(
            template_id=data.get("template-id", ""),
            template_name=info.get("name", ""),
            severity=severity,
            host=data.get("host", ""),
            matched_at=data.get("matched-at", ""),
            ip=data.get("ip", ""),
            timestamp=data.get("timestamp", ""),
            matcher_name=data.get("matcher-name", ""),
            extracted_results=data.get("extracted-results", []),
            curl_command=data.get("curl-command", ""),
            request=data.get("request", ""),
            response=data.get("response", ""),
            metadata=info.get("metadata", {})
        )

    async def _run_command(
        self,
        cmd: list[str],
        timeout: int = 60
    ) -> tuple[str, str, int]:
        """Run command and return output."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return stdout.decode(), stderr.decode(), process.returncode
        except asyncio.TimeoutError:
            process.kill()
            raise


# Pre-built custom templates for common checks
CUSTOM_TEMPLATES = {
    "api_exposure": """
id: api-endpoint-exposure
info:
  name: API Endpoint Exposure Check
  author: deadman
  severity: medium
  description: Checks for exposed API endpoints
  tags: api,exposure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api"
      - "{{BaseURL}}/api/v1"
      - "{{BaseURL}}/api/v2"
      - "{{BaseURL}}/graphql"
      - "{{BaseURL}}/api/swagger"
      - "{{BaseURL}}/api/docs"
      - "{{BaseURL}}/api/health"
      - "{{BaseURL}}/api/status"
      - "{{BaseURL}}/api/config"
      - "{{BaseURL}}/api/debug"

    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
          - 401
          - 403

      - type: word
        words:
          - "swagger"
          - "openapi"
          - "graphql"
        condition: or
""",

    "admin_panels": """
id: admin-panel-detection
info:
  name: Admin Panel Detection
  author: deadman
  severity: info
  description: Detects common admin panel paths
  tags: admin,panel

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/admin/login"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/manage"
      - "{{BaseURL}}/backend"
      - "{{BaseURL}}/_admin"

    matchers-condition: or
    matchers:
      - type: status
        status:
          - 200
          - 301
          - 302
          - 401
          - 403

      - type: word
        words:
          - "login"
          - "password"
          - "admin"
          - "dashboard"
        condition: or
""",

    "sensitive_files": """
id: sensitive-file-exposure
info:
  name: Sensitive File Exposure
  author: deadman
  severity: high
  description: Checks for exposed sensitive files
  tags: exposure,files

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
      - "{{BaseURL}}/.git/config"
      - "{{BaseURL}}/.git/HEAD"
      - "{{BaseURL}}/config.php"
      - "{{BaseURL}}/config.json"
      - "{{BaseURL}}/settings.py"
      - "{{BaseURL}}/database.yml"
      - "{{BaseURL}}/wp-config.php"
      - "{{BaseURL}}/.htpasswd"
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/dump.sql"
      - "{{BaseURL}}/.DS_Store"
      - "{{BaseURL}}/composer.json"
      - "{{BaseURL}}/package.json"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        words:
          - "DB_PASSWORD"
          - "SECRET_KEY"
          - "API_KEY"
          - "password"
          - "PRIVATE"
          - "mysql"
          - "postgres"
        condition: or
""",

    "cors_misconfig": """
id: cors-misconfiguration
info:
  name: CORS Misconfiguration
  author: deadman
  severity: medium
  description: Checks for CORS misconfigurations
  tags: cors,misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Origin: https://evil.com

    matchers-condition: and
    matchers:
      - type: word
        part: header
        words:
          - "Access-Control-Allow-Origin: https://evil.com"
          - "Access-Control-Allow-Origin: *"
          - "Access-Control-Allow-Credentials: true"
        condition: or
""",

    "security_headers": """
id: missing-security-headers
info:
  name: Missing Security Headers
  author: deadman
  severity: info
  description: Checks for missing security headers
  tags: headers,security

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers-condition: or
    matchers:
      - type: word
        part: header
        words:
          - "X-Frame-Options"
        negative: true

      - type: word
        part: header
        words:
          - "X-Content-Type-Options"
        negative: true

      - type: word
        part: header
        words:
          - "Content-Security-Policy"
        negative: true
"""
}


async def quick_scan(
    target: str,
    severity: list[str] = None
) -> ScanResult:
    """
    Quick scan utility function.

    Args:
        target: Target URL
        severity: List of severities to include (default: critical, high)
    """
    scanner = NucleiScanner()

    severity_filter = [Severity(s) for s in (severity or ["critical", "high"])]

    config = ScanConfig(
        severity_filter=severity_filter,
        rate_limit=100,
        concurrency=10
    )

    return await scanner.scan(target, config)


async def full_scan(target: str) -> ScanResult:
    """Run comprehensive scan with all templates."""
    scanner = NucleiScanner()

    config = ScanConfig(
        template_categories=[
            TemplateCategory.CVES,
            TemplateCategory.VULNERABILITIES,
            TemplateCategory.EXPOSURES,
            TemplateCategory.MISCONFIGURATIONS,
        ],
        rate_limit=150,
        concurrency=25
    )

    return await scanner.scan(target, config)


if __name__ == "__main__":
    # Example usage
    async def main():
        scanner = NucleiScanner()

        if not scanner.is_installed():
            print("Nuclei not installed!")
            print("Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return

        # Quick scan
        result = await quick_scan("https://example.com")
        print(f"Found {len(result.vulnerabilities)} vulnerabilities")

        for vuln in result.vulnerabilities:
            print(f"  [{vuln.severity.value}] {vuln.template_name} at {vuln.matched_at}")

    asyncio.run(main())
