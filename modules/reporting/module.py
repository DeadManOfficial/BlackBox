#!/usr/bin/env python3
"""
BlackBox AI - Reporting Module
================================

Generates security assessment reports in multiple formats.
Supports vulnerability reports, executive summaries, and technical details.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

from modules.base import BaseModule, ModuleCategory, ToolDefinition, RouteDefinition


class ReportingModule(BaseModule):
    """Security report generation module"""

    name = "reporting"
    version = "1.0.0"
    category = ModuleCategory.UTILITY
    description = "Security assessment report generation"
    author = "DeadMan Security Research"
    tags = ["reports", "documentation", "export", "findings"]

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.templates_path = Path(self.config.get("templates_path", "templates/reports"))
        self.output_path = Path(self.config.get("output_path", "reports"))

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        """Register reporting MCP tools"""
        self._mcp = mcp
        self._client = client

        @mcp.tool()
        def report_generate(
            target: str,
            report_type: str = "full",
            format: str = "markdown",
            include_evidence: bool = True
        ) -> str:
            """
            Generate a security assessment report.

            Args:
                target: Target project name
                report_type: Type of report (full, executive, technical, findings)
                format: Output format (markdown, html, json)
                include_evidence: Include evidence in report

            Returns:
                JSON with report path and summary
            """
            return self._generate_report(target, report_type, format, include_evidence)

        @mcp.tool()
        def report_finding(
            title: str,
            severity: str,
            description: str,
            impact: str,
            reproduction: str,
            remediation: str,
            references: str = ""
        ) -> str:
            """
            Generate a single vulnerability finding report.

            Args:
                title: Vulnerability title
                severity: Severity level (critical, high, medium, low, info)
                description: Detailed description
                impact: Business/security impact
                reproduction: Steps to reproduce
                remediation: Recommended fix
                references: Related CVEs, CWEs, links

            Returns:
                Formatted vulnerability report in markdown
            """
            return self._generate_finding_report(
                title, severity, description, impact,
                reproduction, remediation, references
            )

        @mcp.tool()
        def report_executive_summary(
            target: str,
            findings_summary: str,
            risk_rating: str,
            recommendations: str
        ) -> str:
            """
            Generate an executive summary report.

            Args:
                target: Target name
                findings_summary: Summary of findings
                risk_rating: Overall risk rating (critical, high, medium, low)
                recommendations: Key recommendations

            Returns:
                Executive summary in markdown
            """
            return self._generate_executive_summary(
                target, findings_summary, risk_rating, recommendations
            )

        @mcp.tool()
        def report_list_templates() -> str:
            """
            List available report templates.

            Returns:
                JSON list of available templates
            """
            return self._list_templates()

        @mcp.tool()
        def report_export(
            target: str,
            format: str = "json",
            include_metadata: bool = True
        ) -> str:
            """
            Export findings data in specified format.

            Args:
                target: Target project name
                format: Export format (json, csv, yaml)
                include_metadata: Include metadata in export

            Returns:
                Path to exported file
            """
            return self._export_findings(target, format, include_metadata)

        tools = [
            ToolDefinition("report_generate", "Generate assessment report", report_generate),
            ToolDefinition("report_finding", "Generate finding report", report_finding),
            ToolDefinition("report_executive_summary", "Generate executive summary", report_executive_summary),
            ToolDefinition("report_list_templates", "List report templates", report_list_templates),
            ToolDefinition("report_export", "Export findings data", report_export),
        ]
        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        """Register reporting API routes"""
        self._app = app
        from flask import request, jsonify, send_file

        @app.route('/api/reports/generate', methods=['POST'])
        def api_generate_report():
            """Generate a report"""
            data = request.json
            result = json.loads(self._generate_report(
                data.get('target'),
                data.get('report_type', 'full'),
                data.get('format', 'markdown'),
                data.get('include_evidence', True)
            ))
            return jsonify(result)

        @app.route('/api/reports/templates', methods=['GET'])
        def api_list_templates():
            """List available templates"""
            result = json.loads(self._list_templates())
            return jsonify(result)

        @app.route('/api/reports/export/<target>', methods=['GET'])
        def api_export(target):
            """Export findings"""
            format = request.args.get('format', 'json')
            result = json.loads(self._export_findings(target, format, True))
            return jsonify(result)

        routes = [
            RouteDefinition('/api/reports/generate', ['POST'], api_generate_report, "Generate report"),
            RouteDefinition('/api/reports/templates', ['GET'], api_list_templates, "List templates"),
            RouteDefinition('/api/reports/export/<target>', ['GET'], api_export, "Export findings"),
        ]
        self._routes = routes
        return routes

    def _generate_report(self, target: str, report_type: str, format: str, include_evidence: bool) -> str:
        """Generate a full security assessment report"""
        # Look for project in common locations
        projects_paths = [
            Path("projects"),
            Path("~/.claude-home/BlackBox/reports"),
            Path("~/.claude-home/BlackBox/reports")
        ]

        findings_file = None
        scope_file = None
        target_path = None

        for base in projects_paths:
            if (base / target / "findings.json").exists():
                target_path = base / target
                findings_file = target_path / "findings.json"
                scope_file = target_path / "config" / "scope.yaml"
                break

        if not findings_file or not findings_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        # Load data
        with open(findings_file) as f:
            findings_data = json.load(f)

        scope_data = {}
        if scope_file and scope_file.exists():
            with open(scope_file) as f:
                scope_data = yaml.safe_load(f)

        findings = findings_data.get("findings", [])

        # Sort by severity
        findings.sort(key=lambda x: self.SEVERITY_ORDER.get(x.get("severity", "info"), 5))

        # Generate report based on type
        if report_type == "executive":
            report = self._build_executive_report(target, findings, scope_data)
        elif report_type == "technical":
            report = self._build_technical_report(target, findings, scope_data, include_evidence)
        elif report_type == "findings":
            report = self._build_findings_only_report(findings, include_evidence)
        else:  # full
            report = self._build_full_report(target, findings, scope_data, include_evidence)

        # Save report
        output_dir = target_path / "reports" if target_path else self.output_path
        output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target}_{report_type}_{timestamp}"

        if format == "html":
            output_file = output_dir / f"{filename}.html"
            report = self._markdown_to_html(report)
        elif format == "json":
            output_file = output_dir / f"{filename}.json"
            report = json.dumps({
                "target": target,
                "type": report_type,
                "generated": datetime.now().isoformat(),
                "findings": findings,
                "scope": scope_data
            }, indent=2)
        else:
            output_file = output_dir / f"{filename}.md"

        with open(output_file, "w") as f:
            f.write(report)

        return json.dumps({
            "success": True,
            "report_path": str(output_file),
            "type": report_type,
            "format": format,
            "findings_count": len(findings)
        })

    def _build_full_report(self, target: str, findings: List[Dict], scope: Dict, include_evidence: bool) -> str:
        """Build full security assessment report"""
        now = datetime.now()

        # Stats
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = f"""# Security Assessment Report
## {target}

**Generated:** {now.strftime("%Y-%m-%d %H:%M:%S")}
**Report Type:** Full Assessment

---

## Executive Summary

This report presents the findings of a security assessment conducted against {target}.

### Scope

**Platform:** {scope.get('target', {}).get('platform', 'N/A')}
**Program URL:** {scope.get('target', {}).get('program_url', 'N/A')}

**In-Scope Domains:**
{chr(10).join(f"- {d}" for d in scope.get('scope', {}).get('in_scope', []))}

### Finding Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |
| **Total** | **{len(findings)}** |

---

## Detailed Findings

"""
        for i, finding in enumerate(findings, 1):
            report += self._format_finding(finding, i, include_evidence)

        report += """
---

## Recommendations

1. Address critical and high severity findings immediately
2. Implement security monitoring for affected endpoints
3. Conduct regular security assessments
4. Review and update security policies

---

## Methodology

This assessment followed industry-standard methodologies including:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- MITRE ATT&CK Framework

---

*Report generated by BlackBox AI*
"""
        return report

    def _build_executive_report(self, target: str, findings: List[Dict], scope: Dict) -> str:
        """Build executive summary report"""
        critical_high = sum(1 for f in findings if f.get("severity") in ["critical", "high"])

        risk_level = "Critical" if any(f.get("severity") == "critical" for f in findings) else \
                     "High" if any(f.get("severity") == "high" for f in findings) else \
                     "Medium" if any(f.get("severity") == "medium" for f in findings) else "Low"

        return f"""# Executive Summary
## Security Assessment: {target}

**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Overall Risk Level:** {risk_level}

---

## Key Findings

- **Total Vulnerabilities:** {len(findings)}
- **Critical/High Severity:** {critical_high}
- **Immediate Action Required:** {"Yes" if critical_high > 0 else "No"}

## Risk Overview

{"CRITICAL: Immediate remediation required for critical vulnerabilities." if any(f.get("severity") == "critical" for f in findings) else ""}
{"HIGH: Priority remediation needed for high severity issues." if any(f.get("severity") == "high" for f in findings) else ""}

## Top Recommendations

1. Remediate all critical and high severity vulnerabilities
2. Implement security monitoring
3. Conduct follow-up assessment

---

*Generated by BlackBox AI*
"""

    def _build_technical_report(self, target: str, findings: List[Dict], scope: Dict, include_evidence: bool) -> str:
        """Build technical details report"""
        report = f"""# Technical Security Report
## {target}

**Generated:** {datetime.now().isoformat()}

---

## Technical Findings

"""
        for i, finding in enumerate(findings, 1):
            report += self._format_finding(finding, i, include_evidence)
            report += "\n---\n\n"

        return report

    def _build_findings_only_report(self, findings: List[Dict], include_evidence: bool) -> str:
        """Build findings-only report"""
        report = "# Vulnerability Findings\n\n"
        for i, finding in enumerate(findings, 1):
            report += self._format_finding(finding, i, include_evidence)
        return report

    def _format_finding(self, finding: Dict, index: int, include_evidence: bool) -> str:
        """Format a single finding"""
        severity_emoji = {
            "critical": "[CRITICAL]",
            "high": "[HIGH]",
            "medium": "[MEDIUM]",
            "low": "[LOW]",
            "info": "[INFO]"
        }

        sev = finding.get("severity", "info")

        formatted = f"""
### {index}. {finding.get('title', 'Untitled')}

**ID:** {finding.get('id', 'N/A')}
**Severity:** {severity_emoji.get(sev, '[?]')} {sev.upper()}
**Type:** {finding.get('type', 'N/A')}
**Status:** {finding.get('status', 'new')}
**Endpoint:** {finding.get('endpoint', 'N/A')}

#### Description

{finding.get('description', 'No description provided.')}
"""
        if include_evidence and finding.get('evidence'):
            formatted += f"""
#### Evidence

```
{finding.get('evidence')}
```
"""
        return formatted

    def _generate_finding_report(self, title: str, severity: str, description: str,
                                  impact: str, reproduction: str, remediation: str,
                                  references: str) -> str:
        """Generate a standalone finding report"""
        return f"""# Vulnerability Report: {title}

**Severity:** {severity.upper()}
**Date:** {datetime.now().strftime("%Y-%m-%d")}

---

## Description

{description}

---

## Impact

{impact}

---

## Steps to Reproduce

{reproduction}

---

## Remediation

{remediation}

---

## References

{references if references else "N/A"}

---

*Generated by BlackBox AI*
"""

    def _generate_executive_summary(self, target: str, findings_summary: str,
                                     risk_rating: str, recommendations: str) -> str:
        """Generate executive summary"""
        return f"""# Executive Summary
## {target}

**Date:** {datetime.now().strftime("%Y-%m-%d")}
**Risk Rating:** {risk_rating.upper()}

---

## Findings Summary

{findings_summary}

---

## Recommendations

{recommendations}

---

*Generated by BlackBox AI*
"""

    def _list_templates(self) -> str:
        """List available report templates"""
        templates = [
            {"name": "full", "description": "Complete security assessment report"},
            {"name": "executive", "description": "Executive summary for leadership"},
            {"name": "technical", "description": "Technical details for engineers"},
            {"name": "findings", "description": "Findings only, no summary"},
            {"name": "vulnerability", "description": "Single vulnerability report"}
        ]
        return json.dumps({"templates": templates})

    def _export_findings(self, target: str, format: str, include_metadata: bool) -> str:
        """Export findings in specified format"""
        projects_paths = [
            Path("projects"),
            Path("~/.claude-home/BlackBox/reports"),
            Path("~/.claude-home/BlackBox/reports")
        ]

        for base in projects_paths:
            findings_file = base / target / "findings.json"
            if findings_file.exists():
                with open(findings_file) as f:
                    data = json.load(f)

                output_dir = base / target / "reports"
                output_dir.mkdir(parents=True, exist_ok=True)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

                if format == "yaml":
                    output_file = output_dir / f"export_{timestamp}.yaml"
                    with open(output_file, "w") as f:
                        yaml.dump(data, f, default_flow_style=False)
                elif format == "csv":
                    output_file = output_dir / f"export_{timestamp}.csv"
                    import csv
                    with open(output_file, "w", newline="") as f:
                        if data.get("findings"):
                            writer = csv.DictWriter(f, fieldnames=data["findings"][0].keys())
                            writer.writeheader()
                            writer.writerows(data["findings"])
                else:  # json
                    output_file = output_dir / f"export_{timestamp}.json"
                    with open(output_file, "w") as f:
                        json.dump(data, f, indent=2)

                return json.dumps({
                    "success": True,
                    "path": str(output_file),
                    "format": format,
                    "count": len(data.get("findings", []))
                })

        return json.dumps({"error": f"Target '{target}' not found"})

    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown to HTML"""
        # Basic conversion - in production use markdown library
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #555; }}
        h3 {{ color: #666; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f4f4f4; }}
        pre {{ background-color: #f4f4f4; padding: 10px; overflow-x: auto; }}
        code {{ background-color: #f4f4f4; padding: 2px 5px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
    </style>
</head>
<body>
<pre>{markdown}</pre>
</body>
</html>"""
        return html
