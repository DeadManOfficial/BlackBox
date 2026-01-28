"""
Enhanced Reconnaissance Pipeline
================================

Unified security assessment pipeline orchestrating all tools.
Provides comprehensive vulnerability scanning, JS analysis, and AI testing.

Author: DeadMan Security Research
License: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

# Import our tools - support both relative and absolute imports
try:
    from .nuclei_scanner import NucleiScanner, ScanConfig, Severity as NucleiSeverity
    from .js_analyzer import JSSecurityAnalyzer, JSAnalysisReport
    from .ai_security import AISecurityTester, SecurityReport as AISecurityReport
    from .recon_tools import (
        ReconTarget,
        SubfinderTool,
        HttpxTool,
        KatanaTool,
        FFufTool,
        ReconOrchestrator
    )
except ImportError:
    # Running directly (e.g., via scanner-bridge.js)
    from nuclei_scanner import NucleiScanner, ScanConfig, Severity as NucleiSeverity
    from js_analyzer import JSSecurityAnalyzer, JSAnalysisReport
    from ai_security import AISecurityTester, SecurityReport as AISecurityReport
    from recon_tools import (
        ReconTarget,
        SubfinderTool,
        HttpxTool,
        KatanaTool,
        FFufTool,
        ReconOrchestrator
    )

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Phases of the security scan."""
    RECONNAISSANCE = "reconnaissance"
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    CONTENT_DISCOVERY = "content_discovery"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    VULNERABILITY_SCAN = "vulnerability_scan"
    AI_SECURITY = "ai_security"
    REPORTING = "reporting"


class ScanStatus(Enum):
    """Status of a scan phase."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PhaseResult:
    """Result of a scan phase."""
    phase: ScanPhase
    status: ScanStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    findings_count: int = 0
    data: Any = None
    errors: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0


@dataclass
class PipelineConfig:
    """Configuration for the security pipeline."""
    # Target configuration
    target: str
    include_subdomains: bool = True
    max_subdomains: int = 100

    # Phase toggles
    run_subdomain_enum: bool = True
    run_content_discovery: bool = True
    run_js_analysis: bool = True
    run_vulnerability_scan: bool = True
    run_ai_security: bool = False  # Requires AI endpoint

    # Scanning options
    rate_limit: int = 100
    concurrency: int = 20
    timeout: int = 30

    # Nuclei options
    nuclei_severity: list[str] = field(default_factory=lambda: ["critical", "high", "medium"])
    nuclei_templates: list[str] = field(default_factory=list)

    # JavaScript analysis
    analyze_external_js: bool = False
    js_max_size: int = 5 * 1024 * 1024  # 5MB

    # AI security (if enabled)
    ai_endpoint: str = ""
    ai_auth_token: str = ""

    # Output options
    output_dir: Optional[Path] = None
    save_screenshots: bool = True
    verbose: bool = False


@dataclass
class PipelineReport:
    """Complete pipeline report."""
    target: str
    config: PipelineConfig
    start_time: datetime
    end_time: Optional[datetime] = None
    phases: dict[ScanPhase, PhaseResult] = field(default_factory=dict)

    # Aggregated results
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)
    js_findings: list[dict] = field(default_factory=list)
    ai_findings: list[dict] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.vulnerabilities) + len(self.js_findings) + len(self.ai_findings)

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def severity_summary(self) -> dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1

        for finding in self.js_findings:
            severity = finding.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "subdomains_found": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "endpoints_discovered": len(self.endpoints),
                "js_files_analyzed": len(self.js_files),
                "total_findings": self.total_findings,
                "severity_breakdown": self.severity_summary
            },
            "phases": {
                phase.value: {
                    "status": result.status.value,
                    "duration": result.duration_seconds,
                    "findings": result.findings_count,
                    "errors": result.errors
                }
                for phase, result in self.phases.items()
            },
            "vulnerabilities": self.vulnerabilities,
            "js_findings": self.js_findings,
            "ai_findings": self.ai_findings,
            "errors": self.errors
        }

    def to_markdown(self) -> str:
        """Generate markdown report."""
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {self.target}",
            f"**Date:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {self.duration_seconds:.1f} seconds",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Subdomains Found | {len(self.subdomains)} |",
            f"| Live Hosts | {len(self.live_hosts)} |",
            f"| Endpoints Discovered | {len(self.endpoints)} |",
            f"| JS Files Analyzed | {len(self.js_files)} |",
            f"| Total Findings | {self.total_findings} |",
            f"",
            f"### Severity Breakdown",
            f"",
        ]

        for severity, count in self.severity_summary.items():
            if count > 0:
                lines.append(f"- **{severity.upper()}:** {count}")

        lines.extend([
            f"",
            f"---",
            f"",
            f"## Phase Results",
            f"",
        ])

        for phase, result in self.phases.items():
            status_icon = "!" if result.status == ScanStatus.COMPLETED else "x"
            lines.append(f"### {phase.value.replace('_', ' ').title()}")
            lines.append(f"- **Status:** {result.status.value}")
            lines.append(f"- **Duration:** {result.duration_seconds:.1f}s")
            lines.append(f"- **Findings:** {result.findings_count}")
            if result.errors:
                lines.append(f"- **Errors:** {len(result.errors)}")
            lines.append(f"")

        if self.vulnerabilities:
            lines.extend([
                f"---",
                f"",
                f"## Vulnerabilities",
                f"",
            ])
            for vuln in self.vulnerabilities[:20]:  # Limit to 20
                lines.append(f"### [{vuln.get('severity', 'N/A').upper()}] {vuln.get('name', 'Unknown')}")
                lines.append(f"- **Template:** {vuln.get('template_id', 'N/A')}")
                lines.append(f"- **Host:** {vuln.get('host', 'N/A')}")
                lines.append(f"- **Matched At:** {vuln.get('matched_at', 'N/A')}")
                lines.append(f"")

        if self.js_findings:
            lines.extend([
                f"---",
                f"",
                f"## JavaScript Findings",
                f"",
            ])
            for finding in self.js_findings[:20]:
                lines.append(f"- [{finding.get('severity', 'info').upper()}] {finding.get('pattern_name', 'Unknown')}: {finding.get('value', '')[:50]}")

        return "\n".join(lines)


class EnhancedSecurityPipeline:
    """
    Unified security assessment pipeline.

    Orchestrates:
    - Subdomain enumeration
    - Content discovery
    - JavaScript analysis
    - Vulnerability scanning
    - AI security testing

    Features:
    - Parallel execution where possible
    - Progress callbacks
    - Comprehensive reporting
    - Result correlation
    """

    def __init__(self, config: PipelineConfig):
        """
        Initialize the pipeline.

        Args:
            config: Pipeline configuration
        """
        self.config = config
        self.report = PipelineReport(
            target=config.target,
            config=config,
            start_time=datetime.now()
        )

        # Initialize tools
        self.nuclei = NucleiScanner()
        self.js_analyzer = JSSecurityAnalyzer(
            timeout=config.timeout,
            max_size=config.js_max_size
        )
        self.ai_tester = AISecurityTester(timeout=config.timeout)
        self.recon = ReconOrchestrator()

        # Callbacks
        self._progress_callback: Optional[Callable[[ScanPhase, str], None]] = None

    def on_progress(self, callback: Callable[[ScanPhase, str], None]) -> None:
        """Set progress callback."""
        self._progress_callback = callback

    def _notify(self, phase: ScanPhase, message: str) -> None:
        """Notify progress."""
        if self._progress_callback:
            self._progress_callback(phase, message)
        if self.config.verbose:
            logger.info(f"[{phase.value}] {message}")

    async def run(self) -> PipelineReport:
        """
        Run the complete security assessment pipeline.

        Returns:
            PipelineReport with all findings
        """
        self._notify(ScanPhase.RECONNAISSANCE, f"Starting assessment of {self.config.target}")

        try:
            # Phase 1: Subdomain Enumeration
            if self.config.run_subdomain_enum:
                await self._run_subdomain_enum()

            # Phase 2: Content Discovery
            if self.config.run_content_discovery:
                await self._run_content_discovery()

            # Phase 3: JavaScript Analysis
            if self.config.run_js_analysis:
                await self._run_js_analysis()

            # Phase 4: Vulnerability Scanning
            if self.config.run_vulnerability_scan:
                await self._run_vulnerability_scan()

            # Phase 5: AI Security Testing
            if self.config.run_ai_security and self.config.ai_endpoint:
                await self._run_ai_security()

        except Exception as e:
            self.report.errors.append(f"Pipeline error: {str(e)}")
            logger.error(f"Pipeline error: {e}")

        self.report.end_time = datetime.now()

        # Generate and save report
        if self.config.output_dir:
            await self._save_report()

        return self.report

    async def _run_subdomain_enum(self) -> None:
        """Run subdomain enumeration phase."""
        phase = ScanPhase.SUBDOMAIN_ENUM
        result = PhaseResult(phase=phase, status=ScanStatus.RUNNING, start_time=datetime.now())
        self.report.phases[phase] = result

        self._notify(phase, "Starting subdomain enumeration...")

        try:
            # Extract domain from target
            parsed = urlparse(self.config.target)
            domain = parsed.netloc or parsed.path

            # Use subfinder if available
            subfinder = SubfinderTool()
            if subfinder.is_installed():
                target = ReconTarget(domain=domain, timeout=self.config.timeout)
                subfinder_result = await subfinder.run(target)

                if subfinder_result.success:
                    self.report.subdomains = subfinder_result.data[:self.config.max_subdomains]
                    result.findings_count = len(self.report.subdomains)
                else:
                    result.errors.append(subfinder_result.error or "Subfinder failed")
            else:
                # Fallback: just use the main domain
                self.report.subdomains = [domain]
                result.findings_count = 1

            self._notify(phase, f"Found {len(self.report.subdomains)} subdomains")
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        result.end_time = datetime.now()

    async def _run_content_discovery(self) -> None:
        """Run content discovery phase."""
        phase = ScanPhase.CONTENT_DISCOVERY
        result = PhaseResult(phase=phase, status=ScanStatus.RUNNING, start_time=datetime.now())
        self.report.phases[phase] = result

        self._notify(phase, "Starting content discovery...")

        try:
            # Probe live hosts
            httpx = HttpxTool()
            if httpx.is_installed() and self.report.subdomains:
                target = ReconTarget(
                    domain=self.config.target,
                    timeout=self.config.timeout
                )
                # Probe subdomains
                live_hosts = []
                for subdomain in self.report.subdomains[:50]:  # Limit
                    probe_target = ReconTarget(domain=subdomain, timeout=self.config.timeout)
                    probe_result = await httpx.run(probe_target)
                    if probe_result.success:
                        live_hosts.extend(probe_result.data)

                self.report.live_hosts = list(set(live_hosts))
            else:
                # Fallback: assume target is live
                self.report.live_hosts = [self.config.target]

            # Crawl for endpoints using Katana
            katana = KatanaTool()
            if katana.is_installed():
                for host in self.report.live_hosts[:10]:
                    crawl_target = ReconTarget(domain=host, depth=2, timeout=self.config.timeout)
                    crawl_result = await katana.run(crawl_target)
                    if crawl_result.success:
                        self.report.endpoints.extend(crawl_result.data)

            # Deduplicate endpoints
            self.report.endpoints = list(set(self.report.endpoints))
            result.findings_count = len(self.report.endpoints)

            # Extract JS files
            self.report.js_files = [
                url for url in self.report.endpoints
                if url.endswith('.js') or '/static/js/' in url or '/_next/' in url
            ]

            self._notify(phase, f"Discovered {len(self.report.endpoints)} endpoints, {len(self.report.js_files)} JS files")
            result.status = ScanStatus.COMPLETED

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        result.end_time = datetime.now()

    async def _run_js_analysis(self) -> None:
        """Run JavaScript analysis phase."""
        phase = ScanPhase.JAVASCRIPT_ANALYSIS
        result = PhaseResult(phase=phase, status=ScanStatus.RUNNING, start_time=datetime.now())
        self.report.phases[phase] = result

        self._notify(phase, f"Analyzing {len(self.report.js_files)} JavaScript files...")

        try:
            findings = []

            # Analyze each JS file
            for js_url in self.report.js_files[:30]:  # Limit to 30 files
                try:
                    # Skip external JS unless configured
                    if not self.config.analyze_external_js:
                        parsed = urlparse(js_url)
                        target_parsed = urlparse(self.config.target)
                        if parsed.netloc and parsed.netloc != target_parsed.netloc:
                            continue

                    js_report = await self.js_analyzer.analyze_url(js_url)

                    for finding in js_report.findings:
                        findings.append({
                            "url": js_url,
                            "type": finding.type.value,
                            "severity": finding.severity.value,
                            "value": finding.value,
                            "pattern_name": finding.pattern_name,
                            "line_number": finding.line_number,
                            "confidence": finding.confidence
                        })

                except Exception as e:
                    result.errors.append(f"Error analyzing {js_url}: {e}")

            self.report.js_findings = findings
            result.findings_count = len(findings)
            result.status = ScanStatus.COMPLETED

            self._notify(phase, f"Found {len(findings)} JavaScript security findings")

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        result.end_time = datetime.now()

    async def _run_vulnerability_scan(self) -> None:
        """Run vulnerability scanning phase."""
        phase = ScanPhase.VULNERABILITY_SCAN
        result = PhaseResult(phase=phase, status=ScanStatus.RUNNING, start_time=datetime.now())
        self.report.phases[phase] = result

        self._notify(phase, "Starting vulnerability scanning...")

        try:
            if not self.nuclei.is_installed():
                result.status = ScanStatus.SKIPPED
                result.errors.append("Nuclei not installed")
                self._notify(phase, "Nuclei not installed - skipping vulnerability scan")
                result.end_time = datetime.now()
                return

            # Configure scan
            severity_filter = [
                NucleiSeverity(s) for s in self.config.nuclei_severity
            ]

            scan_config = ScanConfig(
                templates=self.config.nuclei_templates,
                severity_filter=severity_filter,
                rate_limit=self.config.rate_limit,
                concurrency=self.config.concurrency,
                timeout=self.config.timeout
            )

            # Scan target
            scan_result = await self.nuclei.scan(
                self.config.target,
                scan_config,
                callback=lambda v: self._notify(
                    phase,
                    f"[{v.severity.value.upper()}] {v.template_name}"
                )
            )

            # Convert to dict format
            for vuln in scan_result.vulnerabilities:
                self.report.vulnerabilities.append(vuln.to_dict())

            result.findings_count = len(scan_result.vulnerabilities)
            result.status = ScanStatus.COMPLETED

            self._notify(phase, f"Found {len(scan_result.vulnerabilities)} vulnerabilities")

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        result.end_time = datetime.now()

    async def _run_ai_security(self) -> None:
        """Run AI security testing phase."""
        phase = ScanPhase.AI_SECURITY
        result = PhaseResult(phase=phase, status=ScanStatus.RUNNING, start_time=datetime.now())
        self.report.phases[phase] = result

        self._notify(phase, "Starting AI security testing...")

        try:
            ai_report = await self.ai_tester.test_http_endpoint(
                url=self.config.ai_endpoint,
                auth_token=self.config.ai_auth_token
            )

            for test_result in ai_report.results:
                if test_result.vulnerable:
                    self.report.ai_findings.append(test_result.to_dict())

            result.findings_count = len(self.report.ai_findings)
            result.status = ScanStatus.COMPLETED

            self._notify(phase, f"Found {len(self.report.ai_findings)} AI security issues")

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))

        result.end_time = datetime.now()

    async def _save_report(self) -> None:
        """Save report to output directory."""
        if not self.config.output_dir:
            return

        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON report
        json_path = output_dir / f"security_report_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(self.report.to_dict(), f, indent=2, default=str)

        # Save Markdown report
        md_path = output_dir / f"security_report_{timestamp}.md"
        with open(md_path, 'w') as f:
            f.write(self.report.to_markdown())

        self._notify(ScanPhase.REPORTING, f"Reports saved to {output_dir}")


async def quick_scan(target: str, output_dir: Optional[str] = None) -> PipelineReport:
    """
    Run a quick security scan.

    Args:
        target: Target URL
        output_dir: Optional output directory

    Returns:
        PipelineReport with findings
    """
    config = PipelineConfig(
        target=target,
        run_subdomain_enum=False,  # Skip for quick scan
        run_content_discovery=True,
        run_js_analysis=True,
        run_vulnerability_scan=True,
        run_ai_security=False,
        nuclei_severity=["critical", "high"],
        output_dir=Path(output_dir) if output_dir else None
    )

    pipeline = EnhancedSecurityPipeline(config)
    return await pipeline.run()


async def full_scan(
    target: str,
    output_dir: str,
    ai_endpoint: Optional[str] = None,
    ai_token: Optional[str] = None
) -> PipelineReport:
    """
    Run a comprehensive security scan.

    Args:
        target: Target URL
        output_dir: Output directory for reports
        ai_endpoint: Optional AI endpoint for testing
        ai_token: Optional AI auth token

    Returns:
        PipelineReport with all findings
    """
    config = PipelineConfig(
        target=target,
        run_subdomain_enum=True,
        run_content_discovery=True,
        run_js_analysis=True,
        run_vulnerability_scan=True,
        run_ai_security=bool(ai_endpoint),
        ai_endpoint=ai_endpoint or "",
        ai_auth_token=ai_token or "",
        nuclei_severity=["critical", "high", "medium"],
        output_dir=Path(output_dir),
        verbose=True
    )

    pipeline = EnhancedSecurityPipeline(config)

    # Add progress logging
    pipeline.on_progress(lambda phase, msg: print(f"[{phase.value}] {msg}"))

    return await pipeline.run()


if __name__ == "__main__":
    # Example usage
    async def main():
        print("Enhanced Security Pipeline")
        print("=" * 50)

        # Quick scan example
        report = await quick_scan(
            "https://example.com",
            output_dir="./security_reports"
        )

        print(f"\nScan completed in {report.duration_seconds:.1f} seconds")
        print(f"Total findings: {report.total_findings}")
        print(f"\nSeverity breakdown:")
        for severity, count in report.severity_summary.items():
            if count > 0:
                print(f"  {severity}: {count}")

    asyncio.run(main())
