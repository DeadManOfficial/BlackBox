"""
HackerOne Integration - API Client, Reports, Programs, Learning
===============================================================

Author: DeadMan Toolkit v5.3
"""

import os, json, base64, re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import urllib.request, urllib.error

# =============================================================================
# API CLIENT
# =============================================================================

@dataclass
class HackerOneConfig:
    api_key: str; username: str = "api"; base_url: str = "https://api.hackerone.com/v1"

class HackerOneAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code, self.message = status_code, message
        super().__init__(f"HackerOne API Error {status_code}: {message}")

class HackerOneClient:
    def __init__(self, config: Optional[HackerOneConfig] = None):
        if config: self.config = config
        else:
            api_key = os.environ.get('HACKERONE_API_KEY')
            if not api_key: raise ValueError("HACKERONE_API_KEY environment variable required")
            self.config = HackerOneConfig(api_key=api_key)
        self._auth_header = f"Basic {base64.b64encode(f'{self.config.username}:{self.config.api_key}'.encode()).decode()}"

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict:
        url = f"{self.config.base_url}{endpoint}" + (f"?{'&'.join(f'{k}={v}' for k,v in params.items())}" if params else "")
        req = urllib.request.Request(url, data=json.dumps(data).encode() if data else None,
            headers={'Authorization': self._auth_header, 'Content-Type': 'application/json', 'Accept': 'application/json'}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as response: return json.loads(response.read().decode())
        except urllib.error.HTTPError as e: raise HackerOneAPIError(e.code, e.read().decode() if e.fp else "")

    def list_programs(self, page: int = 1, per_page: int = 25) -> List[Dict]:
        return self._request('GET', '/hackers/programs', params={'page[number]': page, 'page[size]': per_page}).get('data', [])

    def get_program(self, handle: str) -> Dict: return self._request('GET', f'/hackers/programs/{handle}').get('data', {})
    def search_programs(self, query: str) -> List[Dict]: return self._request('GET', '/hackers/programs', params={'filter[query]': query}).get('data', [])

    def list_reports(self, program: Optional[str] = None, state: Optional[str] = None, page: int = 1) -> List[Dict]:
        params = {'page[number]': page}
        if program: params['filter[program][]'] = program
        if state: params['filter[state][]'] = state
        return self._request('GET', '/hackers/reports', params=params).get('data', [])

    def get_report(self, report_id: str) -> Dict: return self._request('GET', f'/hackers/reports/{report_id}').get('data', {})

    def submit_report(self, program: str, title: str, vulnerability_information: str, severity_rating: str = "medium", weakness_id: Optional[int] = None, impact: Optional[str] = None) -> Dict:
        data = {'data': {'type': 'report', 'attributes': {'team_handle': program, 'title': title, 'vulnerability_information': vulnerability_information, 'severity_rating': severity_rating}}}
        if weakness_id: data['data']['attributes']['weakness_id'] = weakness_id
        if impact: data['data']['attributes']['impact'] = impact
        return self._request('POST', '/hackers/reports', data=data).get('data', {})

    def add_comment(self, report_id: str, message: str, internal: bool = False) -> Dict:
        return self._request('POST', f'/reports/{report_id}/activities', data={'data': {'type': 'activity-comment', 'attributes': {'message': message, 'internal': internal}}}).get('data', {})

    def list_bounties(self, page: int = 1) -> List[Dict]: return self._request('GET', '/hackers/payments/balance', params={'page[number]': page}).get('data', [])

    def list_disclosed_reports(self, program: Optional[str] = None, severity: Optional[str] = None, page: int = 1) -> List[Dict]:
        params = {'page[number]': page}
        if program: params['filter[program][]'] = program
        if severity: params['filter[severity_rating][]'] = severity
        return self._request('GET', '/hackers/hacktivity', params=params).get('data', [])

# =============================================================================
# REPORT MANAGER
# =============================================================================

@dataclass
class VulnerabilityReport:
    title: str; program: str; severity: str; weakness_cwe: Optional[int]; asset: str
    summary: str; steps_to_reproduce: str; impact: str
    remediation: Optional[str] = None; poc_code: Optional[str] = None; attachments: List[str] = field(default_factory=list)

CWE_MAP = {'xss': 79, 'sqli': 89, 'ssrf': 918, 'idor': 639, 'csrf': 352, 'xxe': 611, 'rce': 94, 'auth_bypass': 287, 'info_disclosure': 200}

REPORT_TEMPLATES = {
    'ssrf': {'title': 'SSRF in {endpoint}', 'summary': '## Summary\nSSRF in `{endpoint}` - parameter `{parameter}`', 'steps': '1. Go to {endpoint}\n2. Set `{parameter}` to `{payload}`\n3. Observe server request', 'impact': 'Access internal services, cloud metadata'},
    'xss': {'title': 'XSS in {endpoint}', 'summary': '## Summary\n{xss_type} XSS in `{endpoint}` - parameter `{parameter}`', 'steps': '1. Go to {endpoint}\n2. Enter `{payload}` in `{parameter}`\n3. Observe JS execution', 'impact': 'Session theft, account takeover'},
    'idor': {'title': 'IDOR in {endpoint}', 'summary': '## Summary\nIDOR in `{endpoint}` - parameter `{parameter}`', 'steps': '1. Login as User A\n2. Change `{parameter}` to User B value\n3. Access User B data', 'impact': 'Access other users data'},
    'auth_bypass': {'title': 'Auth Bypass in {endpoint}', 'summary': '## Summary\nAuth bypass via {bypass_method}', 'steps': '{steps}', 'impact': 'Unauthorized access'},
}

class ReportManager:
    def __init__(self, client=None): self.client, self.reports = client, []

    def create_from_template(self, template: str, program: str, details: Dict, severity: str = 'medium') -> VulnerabilityReport:
        if template not in REPORT_TEMPLATES: raise ValueError(f"Unknown template: {template}")
        t = REPORT_TEMPLATES[template]
        report = VulnerabilityReport(title=t['title'].format(**details), program=program, severity=severity, weakness_cwe=CWE_MAP.get(template),
            asset=details.get('endpoint', ''), summary=t['summary'].format(**details), steps_to_reproduce=t['steps'].format(**details), impact=t['impact'])
        self.reports.append(report); return report

    def format_markdown(self, r: VulnerabilityReport) -> str:
        return f"# {r.title}\n\n**Program:** {r.program}\n**Severity:** {r.severity}\n**CWE:** {r.weakness_cwe}\n\n{r.summary}\n\n{r.steps_to_reproduce}\n\n## Impact\n{r.impact}"

    def submit(self, r: VulnerabilityReport) -> Dict:
        if not self.client: raise ValueError("Client not configured")
        return self.client.submit_report(program=r.program, title=r.title, vulnerability_information=f"{r.summary}\n\n{r.steps_to_reproduce}", severity_rating=r.severity, weakness_id=r.weakness_cwe, impact=r.impact)

# =============================================================================
# PROGRAM MANAGER
# =============================================================================

@dataclass
class ProgramScope:
    asset_type: str; asset_identifier: str; eligible_for_bounty: bool; eligible_for_submission: bool; max_severity: str

@dataclass
class BountyProgram:
    handle: str; name: str; url: str; offers_bounties: bool; min_bounty: float; max_bounty: float
    response_time_avg: int; scope: List[ProgramScope]; out_of_scope: List[str]; policy_url: str

class ProgramManager:
    def __init__(self, client=None): self.client, self.programs_cache = client, {}

    def search(self, query: str) -> List[Dict]:
        if not self.client: raise ValueError("Client not configured")
        return self.client.search_programs(query)

    def get_program(self, handle: str, refresh: bool = False) -> Optional[BountyProgram]:
        if handle in self.programs_cache and not refresh: return self.programs_cache[handle]
        if not self.client: raise ValueError("Client not configured")
        data = self.client.get_program(handle)
        if not data: return None
        a = data.get('attributes', {})
        program = BountyProgram(handle=handle, name=a.get('name', handle), url=a.get('url', ''), offers_bounties=a.get('offers_bounties', False),
            min_bounty=a.get('bounty_table', {}).get('low', {}).get('min', 0), max_bounty=a.get('bounty_table', {}).get('critical', {}).get('max', 0),
            response_time_avg=a.get('average_time_to_first_response', 0), scope=[], out_of_scope=[], policy_url=a.get('policy_url', ''))
        self.programs_cache[handle] = program; return program

    def is_in_scope(self, handle: str, asset: str) -> bool:
        program = self.get_program(handle)
        return any(s.eligible_for_submission and (s.asset_identifier in asset or asset in s.asset_identifier) for s in (program.scope if program else []))

# =============================================================================
# DISCLOSURE LEARNER
# =============================================================================

@dataclass
class DisclosedReport:
    id: str; title: str; program: str; severity: str; bounty: float; vulnerability_type: str; disclosed_at: str; summary: str

@dataclass
class LearningInsight:
    category: str; insight: str; evidence: List[str]; confidence: float

VULN_PATTERNS = {
    'xss': [r'xss', r'cross.site.script'], 'ssrf': [r'ssrf', r'server.side.request'], 'sqli': [r'sql.inject'],
    'idor': [r'idor', r'insecure.direct'], 'auth_bypass': [r'auth.bypass'], 'rce': [r'rce', r'remote.code'],
    'csrf': [r'csrf'], 'info_disclosure': [r'information.disclos'], 'oauth': [r'oauth', r'redirect.uri'],
    'prompt_injection': [r'prompt.inject', r'llm']
}

class DisclosureLearner:
    def __init__(self, client=None): self.client, self.reports, self.insights = client, [], []

    def _classify_vulnerability(self, title: str) -> str:
        t = title.lower()
        for vtype, patterns in VULN_PATTERNS.items():
            if any(re.search(p, t) for p in patterns): return vtype
        return 'other'

    def fetch_disclosures(self, program: Optional[str] = None, count: int = 100) -> List[DisclosedReport]:
        if not self.client: raise ValueError("Client not configured")
        raw, page = [], 1
        while len(raw) < count:
            batch = self.client.list_disclosed_reports(program=program, page=page)
            if not batch: break
            raw.extend(batch); page += 1
        self.reports = [DisclosedReport(id=r.get('id', ''), title=r.get('attributes', {}).get('title', ''),
            program=r.get('attributes', {}).get('team', {}).get('handle', ''), severity=r.get('attributes', {}).get('severity_rating', ''),
            bounty=float(r.get('attributes', {}).get('bounty_amount', 0) or 0),
            vulnerability_type=self._classify_vulnerability(r.get('attributes', {}).get('title', '')),
            disclosed_at=r.get('attributes', {}).get('disclosed_at', ''), summary=r.get('attributes', {}).get('vulnerability_information', '')[:500]
        ) for r in raw[:count]]
        return self.reports

    def get_top_vulnerabilities(self, program: str, count: int = 50) -> Dict[str, int]:
        if not self.reports: self.fetch_disclosures(program=program, count=count)
        vc = defaultdict(int)
        for r in self.reports: vc[r.vulnerability_type] += 1
        return dict(sorted(vc.items(), key=lambda x: x[1], reverse=True))

    def get_bounty_stats(self, program: Optional[str] = None) -> Dict:
        if not self.reports: self.fetch_disclosures(program=program)
        bounties = [r.bounty for r in self.reports if r.bounty > 0]
        if not bounties: return {'total': 0, 'count': 0, 'average': 0, 'max': 0, 'min': 0}
        return {'total': sum(bounties), 'count': len(bounties), 'average': sum(bounties)/len(bounties), 'max': max(bounties), 'min': min(bounties)}

    def suggest_targets(self, program: str) -> List[Dict]:
        top = self.get_top_vulnerabilities(program)
        return [{'type': vt, 'count': c, 'recommendation': f"Focus on {vt} - {c} successful reports"} for vt, c in list(top.items())[:5]]

__all__ = ['HackerOneClient', 'HackerOneConfig', 'HackerOneAPIError', 'ReportManager', 'VulnerabilityReport', 'ProgramManager', 'BountyProgram', 'ProgramScope', 'DisclosureLearner', 'DisclosedReport', 'LearningInsight', 'CWE_MAP']
