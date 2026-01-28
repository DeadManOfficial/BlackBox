#!/usr/bin/env python3
"""
BlackBox AI - Findings Tracker
================================

Track, manage, and report security findings during assessments.
"""

import os
import json
import yaml
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich import box

console = Console()

# Data directory
DATA_DIR = Path(__file__).parent.parent / "data"
FINDINGS_DIR = DATA_DIR / "findings"
REPORTS_DIR = DATA_DIR / "reports"


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class Status(Enum):
    """Finding status."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    FIXED = "fixed"
    WONTFIX = "wontfix"
    DUPLICATE = "duplicate"


@dataclass
class Finding:
    """Security finding data class."""
    id: str
    title: str
    severity: str
    target: str
    description: str
    impact: str
    steps_to_reproduce: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    status: str = "open"
    phase: str = ""
    tier: str = ""
    multipliers: List[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    evidence_files: List[str] = field(default_factory=list)
    notes: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        return cls(**data)


class FindingsTracker:
    """Manages security findings for an assessment."""

    def __init__(self, session_name: str = None):
        self.session_name = session_name or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session_dir = FINDINGS_DIR / self.session_name
        self.findings: List[Finding] = []
        self._ensure_directories()
        self._load_findings()

    def _ensure_directories(self):
        """Create necessary directories."""
        self.session_dir.mkdir(parents=True, exist_ok=True)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def _load_findings(self):
        """Load existing findings from session directory."""
        findings_file = self.session_dir / "findings.yaml"
        if findings_file.exists():
            with open(findings_file, 'r') as f:
                data = yaml.safe_load(f) or {}
                self.findings = [Finding.from_dict(f) for f in data.get('findings', [])]

    def _save_findings(self):
        """Save findings to session directory with validation."""
        findings_file = self.session_dir / "findings.yaml"

        # Validate and sanitize findings before serialization
        validated_findings = []
        for f in self.findings:
            finding_dict = f.to_dict()
            # Ensure all values are safe YAML types
            sanitized = self._sanitize_for_yaml(finding_dict)
            validated_findings.append(sanitized)

        data = {
            'session': self.session_name,
            'updated_at': datetime.now().isoformat(),
            'findings': validated_findings
        }

        with open(findings_file, 'w') as f:
            # Use safe_dump with SafeDumper for security
            yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    def _sanitize_for_yaml(self, obj: Any) -> Any:
        """Sanitize object for safe YAML serialization."""
        if isinstance(obj, dict):
            return {str(k): self._sanitize_for_yaml(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_for_yaml(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, Enum):
            return obj.value
        else:
            return str(obj)

    def _generate_id(self, title: str) -> str:
        """Generate unique finding ID."""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        hash_input = f"{title}{timestamp}"
        short_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        return f"FIND-{short_hash.upper()}"

    def add_finding(self, finding: Finding) -> str:
        """Add a new finding."""
        if not finding.id:
            finding.id = self._generate_id(finding.title)

        self.findings.append(finding)
        self._save_findings()

        console.print(f"[green]✓ Finding added: {finding.id}[/green]")
        return finding.id

    def create_finding(
        self,
        title: str,
        severity: str,
        target: str,
        description: str,
        impact: str,
        **kwargs
    ) -> Finding:
        """Create and add a new finding."""
        finding = Finding(
            id="",
            title=title,
            severity=severity,
            target=target,
            description=description,
            impact=impact,
            **kwargs
        )
        self.add_finding(finding)
        return finding

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        for f in self.findings:
            if f.id == finding_id:
                return f
        return None

    def update_finding(self, finding_id: str, **updates) -> bool:
        """Update an existing finding."""
        finding = self.get_finding(finding_id)
        if not finding:
            return False

        for key, value in updates.items():
            if hasattr(finding, key):
                setattr(finding, key, value)

        finding.updated_at = datetime.now().isoformat()
        self._save_findings()
        return True

    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding."""
        for i, f in enumerate(self.findings):
            if f.id == finding_id:
                del self.findings[i]
                self._save_findings()
                return True
        return False

    def list_findings(self, severity: str = None, status: str = None) -> List[Finding]:
        """List findings with optional filters."""
        results = self.findings

        if severity:
            results = [f for f in results if f.severity.lower() == severity.lower()]

        if status:
            results = [f for f in results if f.status.lower() == status.lower()]

        return results

    def get_summary(self) -> Dict[str, Any]:
        """Get findings summary."""
        summary = {
            'total': len(self.findings),
            'by_severity': {},
            'by_status': {},
            'by_target': {}
        }

        for sev in Severity:
            count = len([f for f in self.findings if f.severity == sev.value])
            if count > 0:
                summary['by_severity'][sev.value] = count

        for status in Status:
            count = len([f for f in self.findings if f.status == status.value])
            if count > 0:
                summary['by_status'][status.value] = count

        for f in self.findings:
            if f.target not in summary['by_target']:
                summary['by_target'][f.target] = 0
            summary['by_target'][f.target] += 1

        return summary

    def display_findings(self, findings: List[Finding] = None):
        """Display findings in a table."""
        findings = findings or self.findings

        if not findings:
            console.print("[yellow]No findings recorded.[/yellow]")
            return

        table = Table(title=f"Findings ({len(findings)})", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=15)
        table.add_column("Title", style="white", width=35)
        table.add_column("Severity", width=10)
        table.add_column("Target", style="dim", width=20)
        table.add_column("Status", width=10)

        severity_colors = {
            'critical': 'red bold',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'informational': 'dim'
        }

        for f in findings:
            sev_style = severity_colors.get(f.severity.lower(), 'white')
            table.add_row(
                f.id,
                f.title[:33] + ('...' if len(f.title) > 33 else ''),
                f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
                f.target[:18] + ('...' if len(f.target) > 18 else ''),
                f.status.upper()
            )

        console.print(table)

    def display_finding_detail(self, finding: Finding):
        """Display detailed finding information."""
        severity_colors = {
            'critical': 'red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'informational': 'dim'
        }
        sev_color = severity_colors.get(finding.severity.lower(), 'white')

        content = f"""
## {finding.title}

**ID:** {finding.id}
**Severity:** [{sev_color}]{finding.severity.upper()}[/{sev_color}]
**Status:** {finding.status.upper()}
**Target:** {finding.target}
**Phase:** {finding.phase or 'N/A'}
**Tier:** {finding.tier or 'N/A'}
**CVSS:** {finding.cvss_score or 'N/A'}
**CWE:** {finding.cwe_id or 'N/A'}

### Description
{finding.description}

### Impact
{finding.impact}

### Steps to Reproduce
"""
        for i, step in enumerate(finding.steps_to_reproduce, 1):
            content += f"{i}. {step}\n"

        if finding.proof_of_concept:
            content += f"\n### Proof of Concept\n```\n{finding.proof_of_concept}\n```\n"

        if finding.remediation:
            content += f"\n### Remediation\n{finding.remediation}\n"

        if finding.multipliers:
            content += f"\n### Multipliers\n"
            for m in finding.multipliers:
                content += f"- {m}\n"

        if finding.references:
            content += f"\n### References\n"
            for ref in finding.references:
                content += f"- {ref}\n"

        if finding.notes:
            content += f"\n### Notes\n{finding.notes}\n"

        content += f"\n---\n*Created: {finding.created_at}*\n*Updated: {finding.updated_at}*"

        console.print(Panel(Markdown(content), title=finding.id, border_style=sev_color))

    def display_summary(self):
        """Display findings summary."""
        summary = self.get_summary()

        console.print(Panel(
            f"[bold]Session: {self.session_name}[/bold]\n"
            f"Total Findings: {summary['total']}",
            title="Findings Summary"
        ))

        if summary['by_severity']:
            table = Table(title="By Severity", box=box.SIMPLE)
            table.add_column("Severity", style="cyan")
            table.add_column("Count", style="green")

            severity_order = ['critical', 'high', 'medium', 'low', 'informational']
            for sev in severity_order:
                if sev in summary['by_severity']:
                    table.add_row(sev.upper(), str(summary['by_severity'][sev]))

            console.print(table)

    def generate_report(self, format: str = "markdown") -> str:
        """Generate assessment report."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_name = f"report_{self.session_name}_{timestamp}"

        if format == "markdown":
            return self._generate_markdown_report(report_name)
        elif format == "json":
            return self._generate_json_report(report_name)
        else:
            raise ValueError(f"Unknown format: {format}")

    def _generate_markdown_report(self, report_name: str) -> str:
        """Generate markdown report."""
        summary = self.get_summary()

        report = f"""# Security Assessment Report

**Session:** {self.session_name}
**Generated:** {datetime.now().isoformat()}
**Total Findings:** {summary['total']}

## Executive Summary

This report contains {summary['total']} security findings identified during the assessment.

### Findings by Severity

| Severity | Count |
|----------|-------|
"""
        severity_order = ['critical', 'high', 'medium', 'low', 'informational']
        for sev in severity_order:
            count = summary['by_severity'].get(sev, 0)
            report += f"| {sev.upper()} | {count} |\n"

        report += "\n## Detailed Findings\n\n"

        # Sort findings by severity
        severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_priority.get(f.severity.lower(), 5)
        )

        for finding in sorted_findings:
            report += f"""### {finding.id}: {finding.title}

**Severity:** {finding.severity.upper()}
**Target:** {finding.target}
**Status:** {finding.status.upper()}
**CVSS:** {finding.cvss_score or 'N/A'}

#### Description
{finding.description}

#### Impact
{finding.impact}

#### Steps to Reproduce
"""
            for i, step in enumerate(finding.steps_to_reproduce, 1):
                report += f"{i}. {step}\n"

            if finding.proof_of_concept:
                report += f"\n#### Proof of Concept\n```\n{finding.proof_of_concept}\n```\n"

            if finding.remediation:
                report += f"\n#### Remediation\n{finding.remediation}\n"

            report += "\n---\n\n"

        # Save report
        report_file = REPORTS_DIR / f"{report_name}.md"
        with open(report_file, 'w') as f:
            f.write(report)

        console.print(f"[green]✓ Report saved: {report_file}[/green]")
        return str(report_file)

    def _generate_json_report(self, report_name: str) -> str:
        """Generate JSON report."""
        report = {
            'session': self.session_name,
            'generated_at': datetime.now().isoformat(),
            'summary': self.get_summary(),
            'findings': [f.to_dict() for f in self.findings]
        }

        report_file = REPORTS_DIR / f"{report_name}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        console.print(f"[green]✓ Report saved: {report_file}[/green]")
        return str(report_file)


# Global tracker instance
_tracker: Optional[FindingsTracker] = None


def get_tracker(session_name: str = None) -> FindingsTracker:
    """Get or create findings tracker."""
    global _tracker
    if _tracker is None or (session_name and _tracker.session_name != session_name):
        _tracker = FindingsTracker(session_name)
    return _tracker
