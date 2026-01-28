"""
HackerOne Bridge - Finding to Report Converter
==============================================

Converts scan findings to HackerOne-ready draft reports.
Human review required before submission.

Usage:
    from modules.h1_bridge import H1Bridge

    bridge = H1Bridge()
    drafts = bridge.convert_findings("path/to/findings.json")
    bridge.export_drafts("drafts/")

    # Review drafts, then submit
    bridge.submit_draft("drafts/draft_001.json", client)

Author: DeadMan Toolkit v5.3
"""

import json, re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# CWE mappings for common vulnerability types
CWE_MAP = {
    'xss': 79, 'sqli': 89, 'ssrf': 918, 'idor': 639, 'csrf': 352, 'xxe': 611,
    'rce': 94, 'lfi': 98, 'rfi': 98, 'open-redirect': 601, 'info-disclosure': 200,
    'auth-bypass': 287, 'broken-auth': 287, 'injection': 74, 'deserialization': 502,
    'cors': 942, 'crlf': 93, 'ssti': 1336, 'path-traversal': 22, 'command-injection': 78,
}

SEVERITY_MAP = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low', 'info': 'none'}

@dataclass
class H1Draft:
    id: str
    program: str
    title: str
    severity: str
    cwe: Optional[int]
    summary: str
    steps: str
    impact: str
    source_finding: Dict
    created: str
    status: str = "draft"

    def to_dict(self) -> Dict: return asdict(self)

class H1Bridge:
    """Converts findings to HackerOne draft reports."""

    TEMPLATES = {
        'ssrf': {'title': 'SSRF via {param} at {endpoint}', 'impact': 'Server-Side Request Forgery allows attackers to make requests from the server, potentially accessing internal services, cloud metadata (169.254.169.254), or performing port scanning.'},
        'xss': {'title': 'XSS via {param} at {endpoint}', 'impact': 'Cross-Site Scripting allows attackers to execute JavaScript in victim browsers, enabling session hijacking, credential theft, or malicious actions on behalf of users.'},
        'sqli': {'title': 'SQL Injection via {param} at {endpoint}', 'impact': 'SQL Injection allows attackers to read, modify, or delete database contents, potentially leading to full data breach or authentication bypass.'},
        'idor': {'title': 'IDOR at {endpoint}', 'impact': 'Insecure Direct Object Reference allows unauthorized access to other users\' data by manipulating object identifiers.'},
        'rce': {'title': 'Remote Code Execution at {endpoint}', 'impact': 'Remote Code Execution allows attackers to execute arbitrary commands on the server, leading to full system compromise.'},
        'lfi': {'title': 'Local File Inclusion at {endpoint}', 'impact': 'Local File Inclusion allows reading sensitive server files including configuration, credentials, or source code.'},
        'open-redirect': {'title': 'Open Redirect at {endpoint}', 'impact': 'Open Redirect can be used for phishing attacks by redirecting users to malicious sites while appearing to originate from a trusted domain.'},
        'info-disclosure': {'title': 'Information Disclosure at {endpoint}', 'impact': 'Sensitive information exposure that could aid further attacks or violate user privacy.'},
        'default': {'title': '{vuln_type} at {endpoint}', 'impact': 'Security vulnerability that could be exploited by attackers.'},
    }

    def __init__(self, default_program: str = ""):
        self.default_program = default_program
        self.drafts: List[H1Draft] = []

    def _detect_vuln_type(self, finding: Dict) -> str:
        """Detect vulnerability type from finding data."""
        searchable = json.dumps(finding).lower()
        for vtype in CWE_MAP:
            if vtype in searchable: return vtype
        template_id = finding.get('template-id', finding.get('template', '')).lower()
        for vtype in CWE_MAP:
            if vtype in template_id: return vtype
        return 'default'

    def _extract_endpoint(self, finding: Dict) -> str:
        """Extract endpoint from finding."""
        return finding.get('matched-at', finding.get('host', finding.get('url', 'Unknown endpoint')))

    def _extract_param(self, finding: Dict) -> str:
        """Extract vulnerable parameter if present."""
        matched = finding.get('matched-at', '')
        if '?' in matched:
            params = matched.split('?')[1].split('&')
            return params[0].split('=')[0] if params else 'parameter'
        return finding.get('matcher-name', 'input')

    def _generate_steps(self, finding: Dict, vtype: str) -> str:
        """Generate reproduction steps."""
        endpoint = self._extract_endpoint(finding)
        curl_cmd = finding.get('curl-command', '')

        steps = f"## Steps to Reproduce\n\n1. Navigate to: `{endpoint}`\n"

        if curl_cmd:
            steps += f"\n2. Or use the following curl command:\n```bash\n{curl_cmd}\n```\n"

        if finding.get('extracted-results'):
            steps += f"\n3. Observe the response containing: `{finding.get('extracted-results')}`\n"
        elif finding.get('matcher-name'):
            steps += f"\n3. Observe the {finding.get('matcher-name')} in the response\n"
        else:
            steps += "\n3. Observe the vulnerable behavior in the response\n"

        return steps

    def _generate_summary(self, finding: Dict, vtype: str) -> str:
        """Generate vulnerability summary."""
        info = finding.get('info', {})
        desc = info.get('description', '')
        endpoint = self._extract_endpoint(finding)

        summary = f"## Summary\n\nA {vtype.upper()} vulnerability was identified at `{endpoint}`.\n\n"
        if desc: summary += f"**Details:** {desc}\n\n"
        summary += f"**Severity:** {info.get('severity', 'medium').upper()}\n"
        summary += f"**Template:** {finding.get('template-id', 'manual')}\n"

        return summary

    def convert_finding(self, finding: Dict, program: str = None) -> H1Draft:
        """Convert a single finding to H1 draft."""
        vtype = self._detect_vuln_type(finding)
        endpoint = self._extract_endpoint(finding)
        param = self._extract_param(finding)
        info = finding.get('info', {})

        template = self.TEMPLATES.get(vtype, self.TEMPLATES['default'])
        title = template['title'].format(endpoint=endpoint, param=param, vuln_type=vtype.upper())

        draft = H1Draft(
            id=f"draft_{len(self.drafts)+1:03d}_{datetime.now().strftime('%H%M%S')}",
            program=program or self.default_program,
            title=title[:100],  # H1 title limit
            severity=SEVERITY_MAP.get(info.get('severity', 'medium').lower(), 'medium'),
            cwe=CWE_MAP.get(vtype),
            summary=self._generate_summary(finding, vtype),
            steps=self._generate_steps(finding, vtype),
            impact=template['impact'],
            source_finding=finding,
            created=datetime.now().isoformat()
        )
        self.drafts.append(draft)
        return draft

    def convert_findings(self, findings_path: str, program: str = None) -> List[H1Draft]:
        """Convert all findings from a JSON file."""
        path = Path(findings_path)
        if not path.exists(): raise FileNotFoundError(f"Findings not found: {path}")

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle different formats
        findings = data if isinstance(data, list) else data.get('findings', data.get('vulnerabilities', []))

        # Filter to high/critical by default
        actionable = [f for f in findings if f.get('info', {}).get('severity', '').lower() in ['critical', 'high', 'medium']]

        for finding in actionable:
            self.convert_finding(finding, program)

        return self.drafts

    def export_drafts(self, output_dir: str) -> List[str]:
        """Export all drafts to JSON files for review."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = []

        for draft in self.drafts:
            path = out / f"{draft.id}.json"
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(draft.to_dict(), f, indent=2)
            paths.append(str(path))

        # Also create summary
        summary = {
            'generated': datetime.now().isoformat(),
            'total_drafts': len(self.drafts),
            'by_severity': {},
            'drafts': [{'id': d.id, 'title': d.title, 'severity': d.severity} for d in self.drafts]
        }
        for d in self.drafts:
            summary['by_severity'][d.severity] = summary['by_severity'].get(d.severity, 0) + 1

        with open(out / "_summary.json", 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        return paths

    def load_draft(self, draft_path: str) -> H1Draft:
        """Load a draft for submission."""
        with open(draft_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return H1Draft(**data)

    def submit_draft(self, draft_path: str, client) -> Dict:
        """Submit a reviewed draft to HackerOne."""
        draft = self.load_draft(draft_path)

        if not draft.program: raise ValueError("Program not set - edit draft before submission")
        if draft.status != "draft": raise ValueError(f"Draft already {draft.status}")

        vuln_info = f"{draft.summary}\n\n{draft.steps}\n\n## Impact\n\n{draft.impact}"

        result = client.submit_report(
            program=draft.program,
            title=draft.title,
            vulnerability_information=vuln_info,
            severity_rating=draft.severity,
            weakness_id=draft.cwe,
            impact=draft.impact
        )

        # Update draft status
        draft.status = "submitted"
        with open(draft_path, 'w', encoding='utf-8') as f:
            json.dump(draft.to_dict(), f, indent=2)

        return result

    def preview_draft(self, draft: H1Draft) -> str:
        """Generate markdown preview of draft for review."""
        return f"""# {draft.title}

**Program:** {draft.program or '[SET BEFORE SUBMIT]'}
**Severity:** {draft.severity}
**CWE:** {draft.cwe or 'N/A'}

{draft.summary}

{draft.steps}

## Impact

{draft.impact}

---
*Draft ID: {draft.id} | Created: {draft.created}*
"""

__all__ = ['H1Bridge', 'H1Draft', 'CWE_MAP', 'SEVERITY_MAP']
