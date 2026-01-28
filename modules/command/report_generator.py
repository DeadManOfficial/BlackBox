"""
Report Generator
================

Generates security assessment reports in various formats.
"""

import json
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

from config import DATABASE_PATH, SEVERITY_SCORES

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Report generation configuration"""
    include_evidence: bool = True
    include_remediation: bool = True
    include_attack_paths: bool = True
    max_findings: int = 1000
    severity_filter: List[str] = None
    format: str = "json"


class ReportGenerator:
    """Generate security assessment reports"""

    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    def generate(self, config: ReportConfig = None) -> Dict:
        """Generate report"""
        config = config or ReportConfig()

        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()

        try:
            # Get scan info
            cursor.execute('SELECT * FROM scans WHERE scan_id = ?', (self.scan_id,))
            scan_row = cursor.fetchone()

            if not scan_row:
                return {"error": "Scan not found"}

            scan_columns = ['scan_id', 'target', 'start_time', 'end_time', 'status', 'phase', 'vulnerabilities_count', 'parameters']
            scan_data = dict(zip(scan_columns, scan_row))

            # Get findings
            query = 'SELECT * FROM findings WHERE scan_id = ?'
            params = [self.scan_id]

            if config.severity_filter:
                placeholders = ','.join(['?' for _ in config.severity_filter])
                query += f' AND severity IN ({placeholders})'
                params.extend(config.severity_filter)

            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(config.max_findings)

            cursor.execute(query, params)
            finding_columns = [desc[0] for desc in cursor.description]
            findings = [dict(zip(finding_columns, row)) for row in cursor.fetchall()]

            # Get attack paths
            attack_paths = []
            if config.include_attack_paths:
                cursor.execute('SELECT path_json FROM attack_paths WHERE scan_id = ?', (self.scan_id,))
                attack_paths = [json.loads(row[0]) for row in cursor.fetchall() if row[0]]

            # Build report
            report = self._build_report(scan_data, findings, attack_paths, config)

            return report

        finally:
            conn.close()

    def _build_report(
        self,
        scan_data: Dict,
        findings: List[Dict],
        attack_paths: List[Dict],
        config: ReportConfig
    ) -> Dict:
        """Build the report structure"""
        # Calculate statistics
        severity_counts = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        for finding in findings:
            sev = (finding.get('severity') or 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate risk score
        risk_score = sum(
            severity_counts[sev] * score
            for sev, score in SEVERITY_SCORES.items()
        )
        risk_score = min(risk_score, 100)

        # Determine risk level
        if risk_score >= 70:
            risk_level = 'CRITICAL'
        elif risk_score >= 50:
            risk_level = 'HIGH'
        elif risk_score >= 30:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        # Build report
        report = {
            "metadata": {
                "report_id": f"PENTEST-{self.scan_id[:8].upper()}",
                "generated_at": datetime.now().isoformat(),
                "generator": "Pentest Mission Control",
                "version": "1.0.0"
            },
            "scan": {
                "scan_id": scan_data.get('scan_id'),
                "target": scan_data.get('target'),
                "start_time": scan_data.get('start_time'),
                "end_time": scan_data.get('end_time'),
                "status": scan_data.get('status'),
                "parameters": json.loads(scan_data.get('parameters') or '{}')
            },
            "executive_summary": {
                "risk_level": risk_level,
                "risk_score": risk_score,
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "attack_paths_identified": len(attack_paths)
            },
            "findings": self._format_findings(findings, config),
            "attack_paths": attack_paths if config.include_attack_paths else [],
            "recommendations": self._generate_recommendations(findings, severity_counts)
        }

        return report

    def _format_findings(self, findings: List[Dict], config: ReportConfig) -> List[Dict]:
        """Format findings for report"""
        formatted = []

        for finding in findings:
            item = {
                "id": finding.get('finding_id'),
                "title": finding.get('title'),
                "severity": finding.get('severity'),
                "description": finding.get('description'),
                "target_url": finding.get('target_url'),
                "agent": finding.get('agent_id'),
                "timestamp": finding.get('timestamp'),
                "cvss_score": finding.get('cvss_score'),
                "cve_id": finding.get('cve_id')
            }

            if config.include_evidence:
                item["evidence"] = finding.get('evidence')

            if config.include_remediation:
                item["remediation"] = finding.get('remediation')

            # Parse metadata if present
            metadata = finding.get('metadata')
            if metadata and isinstance(metadata, str):
                try:
                    item["metadata"] = json.loads(metadata)
                except json.JSONDecodeError:
                    pass

            formatted.append(item)

        return formatted

    def _generate_recommendations(self, findings: List[Dict], severity_counts: Dict) -> List[Dict]:
        """Generate remediation recommendations"""
        recommendations = []

        # Critical findings
        if severity_counts['critical'] > 0:
            recommendations.append({
                "priority": "URGENT",
                "title": "Address Critical Vulnerabilities",
                "description": f"Immediately remediate {severity_counts['critical']} critical severity findings. These pose immediate risk to the organization.",
                "timeline": "24-48 hours"
            })

        # High findings
        if severity_counts['high'] > 0:
            recommendations.append({
                "priority": "HIGH",
                "title": "Remediate High Severity Issues",
                "description": f"Address {severity_counts['high']} high severity vulnerabilities as soon as possible.",
                "timeline": "1-2 weeks"
            })

        # LLM-specific findings
        llm_findings = [f for f in findings if 'LLM' in (f.get('title') or '')]
        if llm_findings:
            recommendations.append({
                "priority": "HIGH",
                "title": "Implement AI/LLM Security Controls",
                "description": "Deploy prompt injection defenses, output sanitization, and rate limiting for AI endpoints.",
                "timeline": "2-4 weeks"
            })

        # WAF findings
        waf_findings = [f for f in findings if 'WAF' in (f.get('title') or '')]
        if waf_findings:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Review WAF/CDN Configuration",
                "description": "Ensure origin IP is properly protected and WAF rules are up to date.",
                "timeline": "1-2 weeks"
            })

        # General recommendations
        if severity_counts['medium'] > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Address Medium Severity Findings",
                "description": f"Plan remediation for {severity_counts['medium']} medium severity issues.",
                "timeline": "1-3 months"
            })

        return recommendations

    def generate_html(self, config: ReportConfig = None) -> str:
        """Generate HTML report"""
        report = self.generate(config)

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {report['scan']['target']}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: #fff; padding: 30px; border-radius: 8px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: #fff; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card.critical {{ border-top: 4px solid #ff0000; }}
        .summary-card.high {{ border-top: 4px solid #ff6b35; }}
        .summary-card.medium {{ border-top: 4px solid #ffa500; }}
        .summary-card.low {{ border-top: 4px solid #00d4ff; }}
        .summary-card.info {{ border-top: 4px solid #8a2be2; }}
        .count {{ font-size: 36px; font-weight: bold; }}
        .label {{ font-size: 12px; text-transform: uppercase; color: #666; }}
        .finding {{ background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .finding-header {{ display: flex; justify-content: space-between; margin-bottom: 10px; }}
        .severity {{ padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; color: #fff; }}
        .severity.critical {{ background: #ff0000; }}
        .severity.high {{ background: #ff6b35; }}
        .severity.medium {{ background: #ffa500; color: #000; }}
        .severity.low {{ background: #00d4ff; color: #000; }}
        .severity.info {{ background: #8a2be2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Target: {report['scan']['target']}</p>
        <p>Report ID: {report['metadata']['report_id']}</p>
        <p>Generated: {report['metadata']['generated_at']}</p>
    </div>

    <div class="summary">
        <div class="summary-card critical">
            <div class="count">{report['executive_summary']['severity_breakdown']['critical']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card high">
            <div class="count">{report['executive_summary']['severity_breakdown']['high']}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card medium">
            <div class="count">{report['executive_summary']['severity_breakdown']['medium']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card low">
            <div class="count">{report['executive_summary']['severity_breakdown']['low']}</div>
            <div class="label">Low</div>
        </div>
        <div class="summary-card info">
            <div class="count">{report['executive_summary']['severity_breakdown']['info']}</div>
            <div class="label">Info</div>
        </div>
    </div>

    <h2>Findings</h2>
"""

        for finding in report['findings']:
            severity = (finding.get('severity') or 'info').lower()
            html += f"""
    <div class="finding">
        <div class="finding-header">
            <strong>{finding.get('title', 'Unknown')}</strong>
            <span class="severity {severity}">{severity.upper()}</span>
        </div>
        <p>{finding.get('description', '')}</p>
        <p><small>Target: {finding.get('target_url', '-')}</small></p>
    </div>
"""

        html += """
</body>
</html>
"""
        return html
