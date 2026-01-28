"""
HackerOne API Integration for BlackBox.

Automates report submission and management via HackerOne Hacker API.

API Documentation:
- Getting Started: https://api.hackerone.com/getting-started/
- Hacker Resources: https://api.hackerone.com/hacker-resources/
- Reference: https://api.hackerone.com/hacker-reference/

Rate Limits:
- Read: 600 requests/minute (300 for report pages)
- Write: 25 requests per 20 seconds
"""

import os
import json
import base64
import requests
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path


@dataclass
class H1Report:
    """HackerOne report structure."""
    title: str
    vulnerability_type: str  # CWE or weakness ID
    severity: str  # none, low, medium, high, critical
    summary: str
    impact: str
    steps_to_reproduce: str
    target_asset: str
    cvss_vector: Optional[str] = None
    attachments: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API-compatible dict."""
        return {
            'data': {
                'type': 'report',
                'attributes': {
                    'title': self.title,
                    'vulnerability_information': self.summary,
                    'impact': self.impact,
                    'severity_rating': self.severity,
                    'weakness_id': self.vulnerability_type,
                }
            }
        }


class HackerOneAPI:
    """HackerOne API client for hackers."""

    BASE_URL = "https://api.hackerone.com/v1"

    def __init__(self, username: str = None, api_token: str = None):
        """
        Initialize HackerOne API client.

        Credentials can be passed directly or via environment variables:
        - H1_USERNAME
        - H1_API_TOKEN
        """
        self.username = username or os.environ.get('H1_USERNAME')
        self.api_token = api_token or os.environ.get('H1_API_TOKEN')

        if not self.username or not self.api_token:
            raise ValueError("HackerOne credentials required. Set H1_USERNAME and H1_API_TOKEN.")

        self.session = requests.Session()
        self.session.auth = (self.username, self.api_token)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def _request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make authenticated API request."""
        url = f"{self.BASE_URL}/hackers/{endpoint}"

        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                timeout=30
            )

            if response.status_code == 429:
                raise Exception("Rate limit exceeded. Wait and retry.")

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            return {'error': str(e), 'status_code': getattr(e.response, 'status_code', None)}

    def get_programs(self) -> List[Dict]:
        """Get programs you can submit to."""
        return self._request('GET', 'programs')

    def get_reports(self, page: int = 1) -> List[Dict]:
        """Get your submitted reports."""
        return self._request('GET', f'reports?page[number]={page}')

    def get_report(self, report_id: str) -> Dict:
        """Get specific report details."""
        return self._request('GET', f'reports/{report_id}')

    def create_report_intent(self, program_handle: str, title: str,
                             vulnerability_info: str) -> Dict:
        """
        Create a report intent (AI-assisted draft).

        New in September 2025.
        """
        data = {
            'data': {
                'type': 'report-intent',
                'attributes': {
                    'title': title,
                    'vulnerability_information': vulnerability_info
                },
                'relationships': {
                    'program': {
                        'data': {
                            'type': 'program',
                            'attributes': {
                                'handle': program_handle
                            }
                        }
                    }
                }
            }
        }
        return self._request('POST', 'report_intents', data)

    def get_report_intent(self, intent_id: str) -> Dict:
        """Get report intent status (poll until pipelines complete)."""
        return self._request('GET', f'report_intents/{intent_id}')

    def submit_report_intent(self, intent_id: str) -> Dict:
        """Submit a completed report intent as a full report."""
        return self._request('POST', f'report_intents/{intent_id}/submit')

    def submit_report(self, program_handle: str, report: H1Report) -> Dict:
        """
        Submit a report directly to a program.

        Args:
            program_handle: The program's handle (e.g., 'security')
            report: H1Report object with vulnerability details
        """
        data = report.to_dict()
        data['data']['relationships'] = {
            'program': {
                'data': {
                    'type': 'program',
                    'attributes': {
                        'handle': program_handle
                    }
                }
            }
        }
        return self._request('POST', 'reports', data)

    def add_attachment(self, report_id: str, file_path: str) -> Dict:
        """Add attachment to a report."""
        path = Path(file_path)
        if not path.exists():
            return {'error': f'File not found: {file_path}'}

        with open(path, 'rb') as f:
            content = base64.b64encode(f.read()).decode()

        data = {
            'data': {
                'type': 'attachment',
                'attributes': {
                    'file_name': path.name,
                    'content_type': 'application/octet-stream',
                    'file': content
                }
            }
        }
        return self._request('POST', f'reports/{report_id}/attachments', data)


def load_draft_to_report(draft_path: str) -> H1Report:
    """
    Load a BlackBox H1 draft markdown file into H1Report object.

    Parses the standard draft format from h1_drafts/*.md files.
    """
    with open(draft_path, 'r') as f:
        content = f.read()

    # Parse sections from markdown
    sections = {}
    current_section = None
    current_content = []

    for line in content.split('\n'):
        if line.startswith('## '):
            if current_section:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = line[3:].strip().lower()
            current_content = []
        else:
            current_content.append(line)

    if current_section:
        sections[current_section] = '\n'.join(current_content).strip()

    # Extract title
    title = ''
    for line in content.split('\n'):
        if line.startswith('# '):
            title = line[2:].strip()
            break

    # Map to H1Report
    return H1Report(
        title=title or sections.get('title', 'Untitled Report'),
        vulnerability_type=sections.get('weakness', 'CWE-200'),
        severity=sections.get('severity', 'medium').split()[0].lower(),
        summary=sections.get('summary', ''),
        impact=sections.get('impact', ''),
        steps_to_reproduce=sections.get('steps to reproduce', ''),
        target_asset=sections.get('asset', '')
    )


def batch_submit_drafts(drafts_dir: str, program_handle: str,
                        dry_run: bool = True) -> List[Dict]:
    """
    Batch submit all H1 drafts from a directory.

    Args:
        drafts_dir: Path to h1_drafts directory
        program_handle: Target program handle
        dry_run: If True, don't actually submit (default)

    Returns:
        List of submission results
    """
    results = []
    drafts_path = Path(drafts_dir)

    if not drafts_path.exists():
        return [{'error': f'Directory not found: {drafts_dir}'}]

    for draft_file in drafts_path.glob('*.md'):
        if draft_file.name.startswith('00_'):  # Skip index files
            continue

        try:
            report = load_draft_to_report(str(draft_file))

            if dry_run:
                results.append({
                    'file': draft_file.name,
                    'title': report.title,
                    'severity': report.severity,
                    'status': 'DRY_RUN - would submit'
                })
            else:
                api = HackerOneAPI()
                result = api.submit_report(program_handle, report)
                results.append({
                    'file': draft_file.name,
                    'title': report.title,
                    'result': result
                })

        except Exception as e:
            results.append({
                'file': draft_file.name,
                'error': str(e)
            })

    return results


# CLI usage
if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python hackerone_api.py <command> [args]")
        print("\nCommands:")
        print("  list-drafts <drafts_dir>     - List all drafts ready for submission")
        print("  dry-run <drafts_dir> <prog>  - Simulate batch submission")
        print("  submit <drafts_dir> <prog>   - Actually submit all drafts")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'list-drafts':
        drafts_dir = sys.argv[2] if len(sys.argv) > 2 else 'h1_drafts'
        for f in Path(drafts_dir).glob('*.md'):
            if not f.name.startswith('00_'):
                print(f"  {f.name}")

    elif command == 'dry-run':
        drafts_dir = sys.argv[2] if len(sys.argv) > 2 else 'h1_drafts'
        program = sys.argv[3] if len(sys.argv) > 3 else 'PROGRAM_HANDLE'
        results = batch_submit_drafts(drafts_dir, program, dry_run=True)
        for r in results:
            print(json.dumps(r, indent=2))

    elif command == 'submit':
        drafts_dir = sys.argv[2]
        program = sys.argv[3]
        print(f"Submitting drafts from {drafts_dir} to {program}...")
        results = batch_submit_drafts(drafts_dir, program, dry_run=False)
        for r in results:
            print(json.dumps(r, indent=2))
