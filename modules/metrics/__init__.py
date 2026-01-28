"""
Engagement Metrics & Dashboard
==============================

Tracks security engagement metrics and generates dashboards.

Learned from: TikTok engagement tracking

Author: DeadMan Toolkit v5.3
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class EngagementMetrics:
    """Metrics for a security engagement"""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    agents_spawned: int = 0
    files_generated: int = 0
    total_output_kb: float = 0
    endpoints_discovered: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities_by_tier: Dict[str, int] = field(default_factory=dict)
    estimated_bounty_min: int = 0
    estimated_bounty_max: int = 0
    reports_submitted: int = 0
    reports_accepted: int = 0
    actual_bounty: int = 0


class MetricsTracker:
    """
    Tracks engagement metrics.

    Usage:
        tracker = MetricsTracker("tiktok")

        # Log events
        tracker.log_agent_spawn("ai_analysis")
        tracker.log_file_generated("analysis.json", 1024)
        tracker.log_vulnerability("SSRF", "tier4")

        # Get summary
        summary = tracker.get_summary()

        # Export dashboard
        tracker.export_dashboard("dashboard.html")
    """

    def __init__(self, target: str):
        self.metrics = EngagementMetrics(
            target=target,
            start_time=datetime.now()
        )
        self.events: List[Dict] = []

    def log_event(self, event_type: str, details: Dict):
        """Log an event"""
        self.events.append({
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'details': details
        })

    def log_agent_spawn(self, agent_name: str):
        """Log agent spawn"""
        self.metrics.agents_spawned += 1
        self.log_event('agent_spawn', {'agent': agent_name})

    def log_agent_complete(self, agent_name: str, duration_seconds: float):
        """Log agent completion"""
        self.log_event('agent_complete', {
            'agent': agent_name,
            'duration': duration_seconds
        })

    def log_file_generated(self, filename: str, size_bytes: int):
        """Log file generation"""
        self.metrics.files_generated += 1
        self.metrics.total_output_kb += size_bytes / 1024
        self.log_event('file_generated', {
            'filename': filename,
            'size_bytes': size_bytes
        })

    def log_endpoint_discovered(self, endpoint: str, method: str = "GET"):
        """Log endpoint discovery"""
        self.metrics.endpoints_discovered += 1
        self.log_event('endpoint_discovered', {
            'endpoint': endpoint,
            'method': method
        })

    def log_vulnerability(
        self,
        title: str,
        tier: str,
        bounty_min: int = 0,
        bounty_max: int = 0
    ):
        """Log vulnerability finding"""
        self.metrics.vulnerabilities_found += 1
        self.metrics.vulnerabilities_by_tier[tier] = \
            self.metrics.vulnerabilities_by_tier.get(tier, 0) + 1
        self.metrics.estimated_bounty_min += bounty_min
        self.metrics.estimated_bounty_max += bounty_max

        self.log_event('vulnerability_found', {
            'title': title,
            'tier': tier,
            'bounty_min': bounty_min,
            'bounty_max': bounty_max
        })

    def log_report_submitted(self, report_id: str, title: str):
        """Log report submission"""
        self.metrics.reports_submitted += 1
        self.log_event('report_submitted', {
            'report_id': report_id,
            'title': title
        })

    def log_bounty_received(self, report_id: str, amount: int):
        """Log bounty payment"""
        self.metrics.reports_accepted += 1
        self.metrics.actual_bounty += amount
        self.log_event('bounty_received', {
            'report_id': report_id,
            'amount': amount
        })

    def complete(self):
        """Mark engagement as complete"""
        self.metrics.end_time = datetime.now()

    def get_duration(self) -> timedelta:
        """Get engagement duration"""
        end = self.metrics.end_time or datetime.now()
        return end - self.metrics.start_time

    def get_summary(self) -> Dict:
        """Get metrics summary"""
        duration = self.get_duration()

        return {
            'target': self.metrics.target,
            'duration': str(duration),
            'agents_spawned': self.metrics.agents_spawned,
            'files_generated': self.metrics.files_generated,
            'total_output_kb': round(self.metrics.total_output_kb, 2),
            'endpoints_discovered': self.metrics.endpoints_discovered,
            'vulnerabilities_found': self.metrics.vulnerabilities_found,
            'vulnerabilities_by_tier': self.metrics.vulnerabilities_by_tier,
            'estimated_bounty': f"${self.metrics.estimated_bounty_min:,} - ${self.metrics.estimated_bounty_max:,}",
            'reports_submitted': self.metrics.reports_submitted,
            'reports_accepted': self.metrics.reports_accepted,
            'actual_bounty': f"${self.metrics.actual_bounty:,}",
            'conversion_rate': f"{(self.metrics.reports_accepted / self.metrics.reports_submitted * 100) if self.metrics.reports_submitted else 0:.1f}%"
        }

    def export_json(self, filepath: str):
        """Export metrics to JSON"""
        data = {
            'summary': self.get_summary(),
            'events': self.events
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def export_dashboard(self, filepath: str):
        """Export HTML dashboard"""
        summary = self.get_summary()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>BlackBox Engagement Dashboard - {self.metrics.target}</title>
    <style>
        body {{ font-family: 'Courier New', monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #ff0000; border-bottom: 2px solid #ff0000; padding-bottom: 10px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }}
        .metric-card {{ background: #2a2a2a; border: 1px solid #00ff00; padding: 20px; border-radius: 5px; }}
        .metric-value {{ font-size: 2em; color: #00ff00; }}
        .metric-label {{ color: #888; margin-top: 5px; }}
        .tier-badge {{ display: inline-block; padding: 5px 10px; margin: 2px; border-radius: 3px; }}
        .tier5 {{ background: #ff0000; }}
        .tier4 {{ background: #ff6600; }}
        .tier3 {{ background: #ffcc00; color: #000; }}
        .tier2 {{ background: #00cc00; }}
        .tier1 {{ background: #666; }}
        .bounty {{ color: #00ff00; font-size: 1.5em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
        th {{ background: #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>BlackBox Engagement Dashboard</h1>
        <h2>Target: {self.metrics.target}</h2>
        <p>Duration: {summary['duration']}</p>

        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{summary['agents_spawned']}</div>
                <div class="metric-label">Agents Spawned</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['files_generated']}</div>
                <div class="metric-label">Files Generated</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['total_output_kb']:.1f} KB</div>
                <div class="metric-label">Total Output</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['endpoints_discovered']}</div>
                <div class="metric-label">Endpoints Discovered</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['vulnerabilities_found']}</div>
                <div class="metric-label">Vulnerabilities Found</div>
            </div>
            <div class="metric-card">
                <div class="metric-value bounty">{summary['estimated_bounty']}</div>
                <div class="metric-label">Estimated Bounty</div>
            </div>
        </div>

        <h3>Vulnerabilities by Tier</h3>
        <div>
            {"".join(f'<span class="tier-badge {tier}">{tier.upper()}: {count}</span>' for tier, count in summary['vulnerabilities_by_tier'].items())}
        </div>

        <h3>Report Status</h3>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Reports Submitted</td><td>{summary['reports_submitted']}</td></tr>
            <tr><td>Reports Accepted</td><td>{summary['reports_accepted']}</td></tr>
            <tr><td>Actual Bounty</td><td class="bounty">{summary['actual_bounty']}</td></tr>
            <tr><td>Conversion Rate</td><td>{summary['conversion_rate']}</td></tr>
        </table>

        <p style="margin-top: 40px; color: #666;">
            Generated by DeadMan Toolkit v5.3 | BlackBox Security Platform
        </p>
    </div>
</body>
</html>"""

        with open(filepath, 'w') as f:
            f.write(html)


def track_engagement(target: str) -> MetricsTracker:
    """Create a new metrics tracker for an engagement"""
    return MetricsTracker(target)
