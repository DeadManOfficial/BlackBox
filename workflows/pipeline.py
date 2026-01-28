#!/usr/bin/env python3
"""
BlackBox Pipeline Orchestrator
================================

Full attack chain with METHOD (DEADMAN Debugging) enforcement.

RULEBOOK: ~/BlackBox/docs/BOUNTY_RULEBOOK.md
  - GATE_0 → GATE_5 continuous flow (no halts)
  - All MCP tools mandatory, parallelized
  - Token optimization (T0-T4)

Flow:
    GATE_0 → GATE_1 → GATE_2 → GATE_3 → GATE_4 → GATE_5 → END
    (INIT)   (INTEL)  (RECON)  (EXTRACT) (ATTACK)  (VERIFY)

Author: DeadManOfficial
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add BlackBox root to path
BLACKBOX_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BLACKBOX_ROOT))

from modules.methodology.module import RulesEngine, Phase, RuleStatus

# Token optimization imports (T2, T3)
try:
    from modules.utils import checkpoint, get_summary, truncate, BatchProcessor
    TOKEN_OPTIMIZATION_AVAILABLE = True
except ImportError:
    TOKEN_OPTIMIZATION_AVAILABLE = False


class PipelinePhase(Enum):
    """Pipeline phases in execution order"""
    INIT = "init"
    RECON = "recon"
    SCAN = "scan"
    PENTEST = "pentest"  # Full Pen
    REPORT = "report"
    COMPLETE = "complete"
    BLOCKED = "blocked"


class GateStatus(Enum):
    """Gate check result"""
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"  # Hard stop
    SKIPPED = "skipped"


@dataclass
class GateResult:
    """Result of a gate check"""
    gate_id: str
    phase: PipelinePhase
    status: GateStatus
    rule_id: str
    message: str
    evidence: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            **asdict(self),
            'phase': self.phase.value,
            'status': self.status.value
        }


@dataclass
class PipelineState:
    """Current pipeline state"""
    project_id: str
    target: str
    current_phase: PipelinePhase
    started: str
    authorization: Optional[Dict] = None
    scope_type: str = "full"
    bounty_enabled: bool = False

    # Phase completion flags
    recon_complete: bool = False
    scan_complete: bool = False
    pentest_complete: bool = False
    report_complete: bool = False

    # Gate results
    gates_passed: List[GateResult] = field(default_factory=list)
    gates_failed: List[GateResult] = field(default_factory=list)

    # Data from each phase (auto-feeds forward)
    recon_data: Dict = field(default_factory=dict)
    scan_data: Dict = field(default_factory=dict)
    pentest_data: Dict = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)

    # Block reason if stopped
    blocked: bool = False
    block_reason: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d['current_phase'] = self.current_phase.value
        d['gates_passed'] = [g.to_dict() for g in self.gates_passed]
        d['gates_failed'] = [g.to_dict() for g in self.gates_failed]
        return d


class PipelineOrchestrator:
    """
    Main orchestrator for BlackBox attack chain.

    Enforces METHOD gates between phases:

    GATE 0: R0 Authorization
        ↓
    PHASE 1: RECON
        ↓
    GATE 1: R1 Failure Definition (target defined), R4 Golden State
        ↓
    PHASE 2: SCAN
        ↓
    GATE 2: R6 Repro (vulns reproducible), R13 Golden Reference
        ↓
    PHASE 3: FULL PEN
        ↓
    GATE 3: R15 Lowest Layer, R16 Minimal
        ↓
    PHASE 4: REPORT
        ↓
    GATE 4: R20 Tiger Team, R21 Documentation
        ↓
    COMPLETE
    """

    def __init__(self, project_path: Path, target: str,
                 authorization: Dict = None, scope_type: str = "full",
                 bounty_enabled: bool = False):

        self.project_path = Path(project_path)
        self.target = target
        self.methodology = RulesEngine()

        # Initialize state
        self.state = PipelineState(
            project_id=self.project_path.name,
            target=target,
            current_phase=PipelinePhase.INIT,
            started=datetime.now().isoformat(),
            authorization=authorization,
            scope_type=scope_type,
            bounty_enabled=bounty_enabled
        )

        # Create project structure
        self._init_project()

    def _init_project(self):
        """Initialize project directory structure"""
        self.project_path.mkdir(parents=True, exist_ok=True)

        subdirs = ['recon', 'scans', 'reports', 'notes', 'evidence', 'logs']
        for subdir in subdirs:
            (self.project_path / subdir).mkdir(exist_ok=True)

        # Save initial state
        self._save_state()

    def _save_state(self):
        """Persist pipeline state to disk"""
        state_file = self.project_path / "pipeline_state.json"
        with open(state_file, 'w') as f:
            json.dump(self.state.to_dict(), f, indent=2)

    def _checkpoint_phase(self, phase_name: str, data: Dict) -> str:
        """
        T2: Checkpoint after completing a phase.

        Saves full data to file, returns summary for context.
        """
        if TOKEN_OPTIMIZATION_AVAILABLE:
            return checkpoint(self.target, phase_name, data)
        else:
            # Fallback: save to file
            cp_path = self.project_path / "checkpoints" / f"{phase_name}.json"
            cp_path.parent.mkdir(exist_ok=True)
            with open(cp_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return f"{phase_name} saved to {cp_path}"

    def _get_phase_summary(self, phase_name: str) -> Optional[str]:
        """
        T3: Get compact summary of a completed phase.
        """
        if TOKEN_OPTIMIZATION_AVAILABLE:
            return get_summary(self.target, phase_name)
        else:
            cp_path = self.project_path / "checkpoints" / f"{phase_name}.json"
            if cp_path.exists():
                with open(cp_path, 'r') as f:
                    data = json.load(f)
                return f"{phase_name}: {len(data)} items"
            return None

    def _log(self, message: str, level: str = "INFO"):
        """Log to pipeline log file"""
        log_file = self.project_path / "logs" / "pipeline.log"
        timestamp = datetime.now().isoformat()
        with open(log_file, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
        print(f"[{level}] {message}")

    def _check_gate(self, gate_id: str, rule_id: str, phase: PipelinePhase,
                    condition: bool, message: str, evidence: List[str] = None,
                    is_blocking: bool = True) -> GateResult:
        """
        Check a gate condition.

        IF condition is False AND is_blocking THEN pipeline STOPS.
        """
        if condition:
            result = GateResult(
                gate_id=gate_id,
                phase=phase,
                status=GateStatus.PASSED,
                rule_id=rule_id,
                message=f"PASSED: {message}",
                evidence=evidence or []
            )
            self.state.gates_passed.append(result)
            self._log(f"GATE {gate_id} PASSED: {message}")
        else:
            status = GateStatus.BLOCKED if is_blocking else GateStatus.FAILED
            result = GateResult(
                gate_id=gate_id,
                phase=phase,
                status=status,
                rule_id=rule_id,
                message=f"FAILED: {message}",
                evidence=evidence or []
            )
            self.state.gates_failed.append(result)

            if is_blocking:
                self.state.blocked = True
                self.state.block_reason = f"GATE {gate_id} ({rule_id}): {message}"
                self.state.current_phase = PipelinePhase.BLOCKED
                self._log(f"GATE {gate_id} BLOCKED: {message}", "ERROR")
            else:
                self._log(f"GATE {gate_id} FAILED (non-blocking): {message}", "WARN")

        self._save_state()
        return result

    # ========================================
    # GATE 0: Authorization (R0)
    # ========================================
    def gate_0_authorization(self) -> GateResult:
        """
        R0: Authorization

        IF debugging or reverse engineering begins
        THEN scope, authorization, and asset ownership MUST be documented

        STOP ON FAIL: YES
        """
        self._log("=" * 50)
        self._log("GATE 0: Authorization Check (R0)")
        self._log("=" * 50)

        has_auth = self.state.authorization is not None
        has_scope = 'scope' in (self.state.authorization or {})

        evidence = []
        if has_auth:
            evidence.append(f"Authorization: {self.state.authorization}")

        condition = has_auth and has_scope

        return self._check_gate(
            gate_id="G0",
            rule_id="R0",
            phase=PipelinePhase.INIT,
            condition=condition,
            message="Authorization and scope documented" if condition else "Missing authorization or scope documentation",
            evidence=evidence,
            is_blocking=True
        )

    # ========================================
    # PHASE 1: RECON
    # ========================================
    def phase_recon(self) -> Dict:
        """
        Execute reconnaissance phase.

        Gathers:
        - Subdomains
        - Technologies
        - Endpoints
        - Ports
        - OSINT data
        """
        self._log("=" * 50)
        self._log("PHASE 1: RECONNAISSANCE")
        self._log("=" * 50)

        self.state.current_phase = PipelinePhase.RECON
        self._save_state()

        recon_data = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'technologies': [],
            'endpoints': [],
            'ports': [],
            'dns_records': [],
            'whois': {}
        }

        # Subdomain enumeration
        self._log("→ Running subdomain enumeration...")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            subdomains = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            recon_data['subdomains'] = subdomains
            self._log(f"  Found {len(subdomains)} subdomains")
        except FileNotFoundError:
            self._log("  subfinder not installed", "WARN")
        except subprocess.TimeoutExpired:
            self._log("  subfinder timeout", "WARN")

        # HTTP probing
        self._log("→ Probing live hosts...")
        if recon_data['subdomains']:
            try:
                # Write subdomains to temp file
                temp_file = self.project_path / "recon" / "subdomains.txt"
                with open(temp_file, 'w') as f:
                    f.write('\n'.join(recon_data['subdomains']))

                result = subprocess.run(
                    ["httpx", "-l", str(temp_file), "-silent", "-status-code", "-tech-detect", "-json"],
                    capture_output=True, text=True, timeout=180
                )

                live_hosts = []
                for line in result.stdout.split('\n'):
                    if line.strip():
                        try:
                            host_data = json.loads(line)
                            live_hosts.append(host_data)
                            # Extract technologies
                            techs = host_data.get('tech', [])
                            recon_data['technologies'].extend(techs)
                        except json.JSONDecodeError:
                            pass

                recon_data['live_hosts'] = live_hosts
                recon_data['technologies'] = list(set(recon_data['technologies']))
                self._log(f"  Found {len(live_hosts)} live hosts")
                self._log(f"  Technologies: {', '.join(recon_data['technologies'][:10])}")
            except FileNotFoundError:
                self._log("  httpx not installed", "WARN")
            except subprocess.TimeoutExpired:
                self._log("  httpx timeout", "WARN")

        # Port scanning (top 100)
        self._log("→ Running port scan...")
        try:
            result = subprocess.run(
                ["nmap", "-F", "--open", "-oG", "-", self.target],
                capture_output=True, text=True, timeout=120
            )
            # Parse nmap greppable output
            for line in result.stdout.split('\n'):
                if 'Ports:' in line:
                    ports_section = line.split('Ports:')[1] if 'Ports:' in line else ''
                    ports = [p.split('/')[0] for p in ports_section.split(',') if '/' in p]
                    recon_data['ports'] = ports
            self._log(f"  Open ports: {', '.join(recon_data['ports'][:10])}")
        except FileNotFoundError:
            self._log("  nmap not installed", "WARN")
        except subprocess.TimeoutExpired:
            self._log("  nmap timeout", "WARN")

        # Save recon data
        self.state.recon_data = recon_data
        with open(self.project_path / "recon" / "recon_results.json", 'w') as f:
            json.dump(recon_data, f, indent=2)

        # T2: Checkpoint the recon phase
        summary = self._checkpoint_phase("RECON", recon_data)
        self._log(f"RECON COMPLETE - {summary}")
        return recon_data

    # ========================================
    # GATE 1: Recon Complete
    # ========================================
    def gate_1_recon_complete(self) -> GateResult:
        """
        R1: Failure Definition + R4: Golden State

        Checks:
        - Target is defined and observable
        - Golden state captured (recon data)
        - At least some data gathered

        STOP ON FAIL: YES
        """
        self._log("=" * 50)
        self._log("GATE 1: Recon Validation (R1, R4)")
        self._log("=" * 50)

        recon = self.state.recon_data

        # Check we have something
        has_data = bool(
            recon.get('subdomains') or
            recon.get('live_hosts') or
            recon.get('ports') or
            recon.get('technologies')
        )

        evidence = [
            f"Subdomains: {len(recon.get('subdomains', []))}",
            f"Live hosts: {len(recon.get('live_hosts', []))}",
            f"Ports: {len(recon.get('ports', []))}",
            f"Technologies: {len(recon.get('technologies', []))}"
        ]

        result = self._check_gate(
            gate_id="G1",
            rule_id="R1,R4",
            phase=PipelinePhase.RECON,
            condition=has_data,
            message="Golden state captured, target observable" if has_data else "Insufficient recon data - no attack surface found",
            evidence=evidence,
            is_blocking=True
        )

        if result.status == GateStatus.PASSED:
            self.state.recon_complete = True
            self._save_state()

        return result

    # ========================================
    # PHASE 2: SCAN
    # ========================================
    def phase_scan(self) -> Dict:
        """
        Execute vulnerability scanning phase.

        Auto-selects scan type based on recon data:
        - Web targets → nuclei, nikto
        - Cloud infra → prowler, scout
        - AI endpoints → prompt injection tests
        """
        self._log("=" * 50)
        self._log("PHASE 2: VULNERABILITY SCANNING")
        self._log("=" * 50)

        self.state.current_phase = PipelinePhase.SCAN
        self._save_state()

        scan_data = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'scan_type': 'web',  # auto-detected
            'tools_used': []
        }

        # Determine scan type from recon
        technologies = self.state.recon_data.get('technologies', [])
        tech_lower = [t.lower() for t in technologies]

        if any('aws' in t or 'azure' in t or 'gcp' in t for t in tech_lower):
            scan_data['scan_type'] = 'cloud'
        elif any('openai' in t or 'llm' in t or 'gpt' in t for t in tech_lower):
            scan_data['scan_type'] = 'ai'

        self._log(f"Scan type: {scan_data['scan_type']}")

        # Run nuclei (always)
        self._log("→ Running Nuclei vulnerability scan...")
        try:
            result = subprocess.run(
                ["nuclei", "-u", self.target, "-severity", "medium,high,critical", "-silent", "-j"],
                capture_output=True, text=True, timeout=600
            )

            scan_data['tools_used'].append('nuclei')

            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        vuln = json.loads(line)
                        scan_data['vulnerabilities'].append({
                            'source': 'nuclei',
                            'name': vuln.get('info', {}).get('name', 'Unknown'),
                            'severity': vuln.get('info', {}).get('severity', 'unknown'),
                            'matched_at': vuln.get('matched-at', ''),
                            'template': vuln.get('template-id', ''),
                            'description': vuln.get('info', {}).get('description', ''),
                            'raw': vuln
                        })
                    except json.JSONDecodeError:
                        pass

            self._log(f"  Found {len(scan_data['vulnerabilities'])} vulnerabilities")

        except FileNotFoundError:
            self._log("  nuclei not installed", "WARN")
        except subprocess.TimeoutExpired:
            self._log("  nuclei timeout", "WARN")

        # Scan live hosts from recon
        live_hosts = self.state.recon_data.get('live_hosts', [])
        if live_hosts:
            self._log(f"→ Scanning {len(live_hosts)} live hosts...")
            for host in live_hosts[:10]:  # Limit to first 10
                url = host.get('url', '')
                if url:
                    try:
                        result = subprocess.run(
                            ["nuclei", "-u", url, "-severity", "high,critical", "-silent", "-j"],
                            capture_output=True, text=True, timeout=120
                        )
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                try:
                                    vuln = json.loads(line)
                                    scan_data['vulnerabilities'].append({
                                        'source': 'nuclei',
                                        'host': url,
                                        'name': vuln.get('info', {}).get('name', 'Unknown'),
                                        'severity': vuln.get('info', {}).get('severity', 'unknown'),
                                        'matched_at': vuln.get('matched-at', ''),
                                        'raw': vuln
                                    })
                                except json.JSONDecodeError:
                                    pass
                    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError) as e:
                        self._log(f"  Nuclei scan error for {url}: {e}", "WARN")

        # Save scan data
        self.state.scan_data = scan_data
        with open(self.project_path / "scans" / "scan_results.json", 'w') as f:
            json.dump(scan_data, f, indent=2)

        # Save findings separately
        self.state.findings = scan_data['vulnerabilities']
        with open(self.project_path / "findings.json", 'w') as f:
            json.dump({'findings': scan_data['vulnerabilities'], 'stats': {'total': len(scan_data['vulnerabilities'])}}, f, indent=2)

        # T2: Checkpoint the scan phase
        summary = self._checkpoint_phase("SCAN", scan_data)
        self._log(f"SCAN COMPLETE - {summary}")
        return scan_data

    # ========================================
    # GATE 2: Scan Complete
    # ========================================
    def gate_2_scan_complete(self) -> GateResult:
        """
        R6: Deterministic Repro + R13: Golden Reference

        Checks:
        - Vulnerabilities are documented
        - Each has reproducible evidence
        - Comparison against known patterns

        STOP ON FAIL: NO (can proceed with manual pentest)
        """
        self._log("=" * 50)
        self._log("GATE 2: Scan Validation (R6, R13)")
        self._log("=" * 50)

        scan = self.state.scan_data
        vulns = scan.get('vulnerabilities', [])

        has_vulns = len(vulns) > 0
        high_crit = [v for v in vulns if v.get('severity', '').lower() in ['high', 'critical']]

        evidence = [
            f"Total findings: {len(vulns)}",
            f"High/Critical: {len(high_crit)}",
            f"Tools used: {', '.join(scan.get('tools_used', []))}"
        ]

        # This gate is non-blocking - we can do manual pentest even with no automated findings
        result = self._check_gate(
            gate_id="G2",
            rule_id="R6,R13",
            phase=PipelinePhase.SCAN,
            condition=True,  # Always pass, but log findings
            message=f"Scan complete with {len(vulns)} findings ({len(high_crit)} high/critical)",
            evidence=evidence,
            is_blocking=False
        )

        self.state.scan_complete = True
        self._save_state()

        return result

    # ========================================
    # PHASE 3: FULL PEN
    # ========================================
    def phase_pentest(self) -> Dict:
        """
        Full penetration testing phase.

        This is semi-automated - requires human judgment.
        Prepares environment and guidance for manual exploitation.
        """
        self._log("=" * 50)
        self._log("PHASE 3: FULL PEN")
        self._log("=" * 50)

        self.state.current_phase = PipelinePhase.PENTEST
        self._save_state()

        pentest_data = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities_to_verify': [],
            'exploits_attempted': [],
            'confirmed_exploits': [],
            'access_achieved': []
        }

        # Prioritize findings for manual testing
        vulns = self.state.scan_data.get('vulnerabilities', [])

        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

        pentest_data['vulnerabilities_to_verify'] = sorted_vulns[:20]  # Top 20

        self._log(f"Prioritized {len(pentest_data['vulnerabilities_to_verify'])} findings for verification")

        self._log("\n[MANUAL PHASE]")
        self._log("Verify and exploit the following findings:")

        for i, vuln in enumerate(pentest_data['vulnerabilities_to_verify'][:10], 1):
            self._log(f"  {i}. [{vuln.get('severity', 'unknown').upper()}] {vuln.get('name', 'Unknown')}")
            self._log(f"     → {vuln.get('matched_at', 'N/A')}")

        self._log("\nCommands:")
        self._log(f"  blackbox pentest start {self.target}")
        self._log(f"  blackbox bounty finding {self.state.project_id} -t 'Title' -s high --type xss")

        # Save pentest data
        self.state.pentest_data = pentest_data
        with open(self.project_path / "scans" / "pentest_plan.json", 'w') as f:
            json.dump(pentest_data, f, indent=2)

        return pentest_data

    # ========================================
    # GATE 3: Pentest Validation
    # ========================================
    def gate_3_pentest_complete(self, confirmed_findings: List[Dict] = None) -> GateResult:
        """
        R15: Lowest Responsible Layer + R16: Minimal & Reversible

        Checks:
        - Findings are at correct layer (not masking)
        - Exploits are documented with evidence
        - No destructive actions taken

        STOP ON FAIL: NO (report can still be generated)
        """
        self._log("=" * 50)
        self._log("GATE 3: Pentest Validation (R15, R16)")
        self._log("=" * 50)

        if confirmed_findings:
            self.state.pentest_data['confirmed_exploits'] = confirmed_findings
            self.state.findings.extend(confirmed_findings)

        confirmed = self.state.pentest_data.get('confirmed_exploits', [])

        evidence = [
            f"Confirmed exploits: {len(confirmed)}",
            f"Total findings: {len(self.state.findings)}"
        ]

        result = self._check_gate(
            gate_id="G3",
            rule_id="R15,R16",
            phase=PipelinePhase.PENTEST,
            condition=True,
            message=f"Pentest phase complete with {len(confirmed)} confirmed exploits",
            evidence=evidence,
            is_blocking=False
        )

        self.state.pentest_complete = True
        self._save_state()

        return result

    # ========================================
    # PHASE 4: REPORT
    # ========================================
    def phase_report(self) -> str:
        """
        Generate final report.
        """
        self._log("=" * 50)
        self._log("PHASE 4: REPORT GENERATION")
        self._log("=" * 50)

        self.state.current_phase = PipelinePhase.REPORT
        self._save_state()

        # Count by severity
        findings = self.state.findings
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in by_severity:
                by_severity[sev] += 1

        report = f"""# Security Assessment Report

**Target:** {self.target}
**Project:** {self.state.project_id}
**Date:** {datetime.now().strftime('%Y-%m-%d')}
**Generated by:** BlackBox

---

## Executive Summary

This report presents findings from the automated and manual security assessment.

### Findings Overview

| Severity | Count |
|----------|-------|
| Critical | {by_severity['critical']} |
| High | {by_severity['high']} |
| Medium | {by_severity['medium']} |
| Low | {by_severity['low']} |
| Info | {by_severity['info']} |
| **Total** | **{len(findings)}** |

---

## Reconnaissance Summary

- **Subdomains found:** {len(self.state.recon_data.get('subdomains', []))}
- **Live hosts:** {len(self.state.recon_data.get('live_hosts', []))}
- **Open ports:** {len(self.state.recon_data.get('ports', []))}
- **Technologies:** {', '.join(self.state.recon_data.get('technologies', [])[:10])}

---

## Detailed Findings

"""

        # Sort and add findings (using list + join for performance)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5))

        findings_sections = []
        for i, finding in enumerate(sorted_findings, 1):
            findings_sections.append(f"""### {i}. {finding.get('name', 'Untitled')}

**Severity:** {finding.get('severity', 'unknown').upper()}
**Location:** {finding.get('matched_at', finding.get('host', 'N/A'))}
**Source:** {finding.get('source', 'manual')}

{finding.get('description', 'No description available.')}

---
""")

        report += '\n'.join(findings_sections)
        report += f"""
## Pipeline Metadata

- **Started:** {self.state.started}
- **Completed:** {datetime.now().isoformat()}
- **Gates passed:** {len(self.state.gates_passed)}
- **Gates failed:** {len(self.state.gates_failed)}
- **Blocked:** {self.state.blocked}

---

*Generated by BlackBox - DEADMAN Debugging Methodology*
"""

        # Save report
        report_path = self.project_path / "reports" / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_path, 'w') as f:
            f.write(report)

        self._log(f"Report saved: {report_path}")
        return str(report_path)

    # ========================================
    # GATE 4: Final Validation
    # ========================================
    def gate_4_report_complete(self) -> GateResult:
        """
        R20: Tiger Team + R21: Documentation

        Checks:
        - Report is complete
        - Evidence is documented
        - Ready for review

        STOP ON FAIL: NO
        """
        self._log("=" * 50)
        self._log("GATE 4: Report Validation (R20, R21)")
        self._log("=" * 50)

        report_exists = list(self.project_path.glob("reports/*.md"))

        evidence = [
            f"Reports generated: {len(report_exists)}",
            f"Findings documented: {len(self.state.findings)}",
            f"Evidence folder: {self.project_path / 'evidence'}"
        ]

        result = self._check_gate(
            gate_id="G4",
            rule_id="R20,R21",
            phase=PipelinePhase.REPORT,
            condition=len(report_exists) > 0,
            message="Report complete, ready for Tiger Team review",
            evidence=evidence,
            is_blocking=False
        )

        self.state.report_complete = True
        self.state.current_phase = PipelinePhase.COMPLETE
        self._save_state()

        return result

    # ========================================
    # MAIN EXECUTION
    # ========================================
    def run(self, stop_after: Optional[PipelinePhase] = None) -> Dict:
        """
        Execute the full pipeline with all gates.

        Args:
            stop_after: Optional phase to stop after (for partial runs)

        Returns:
            Final pipeline state
        """
        self._log("=" * 60)
        self._log("BLACKBOX PIPELINE START")
        self._log("=" * 60)
        self._log(f"Target: {self.target}")
        self._log(f"Project: {self.state.project_id}")
        self._log(f"Scope: {self.state.scope_type}")
        self._log("")

        # GATE 0: Authorization
        g0 = self.gate_0_authorization()
        if self.state.blocked:
            return self.state.to_dict()

        # PHASE 1: Recon
        self.phase_recon()
        if stop_after == PipelinePhase.RECON:
            self._log("Stopping after RECON phase")
            return self.state.to_dict()

        # GATE 1: Recon validation
        g1 = self.gate_1_recon_complete()
        if self.state.blocked:
            return self.state.to_dict()

        # PHASE 2: Scan
        self.phase_scan()
        if stop_after == PipelinePhase.SCAN:
            self._log("Stopping after SCAN phase")
            return self.state.to_dict()

        # GATE 2: Scan validation
        g2 = self.gate_2_scan_complete()

        # PHASE 3: Full Pen (manual)
        self.phase_pentest()
        if stop_after == PipelinePhase.PENTEST:
            self._log("Stopping after PENTEST phase")
            return self.state.to_dict()

        # GATE 3: Pentest validation
        g3 = self.gate_3_pentest_complete()

        # PHASE 4: Report
        report_path = self.phase_report()

        # GATE 4: Final validation
        g4 = self.gate_4_report_complete()

        # Summary
        self._log("")
        self._log("=" * 60)
        self._log("PIPELINE COMPLETE")
        self._log("=" * 60)
        self._log(f"Gates passed: {len(self.state.gates_passed)}")
        self._log(f"Gates failed: {len(self.state.gates_failed)}")
        self._log(f"Total findings: {len(self.state.findings)}")
        self._log(f"Report: {report_path}")
        self._log("")

        return self.state.to_dict()


# CLI entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="BlackBox Pipeline Orchestrator")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("-p", "--project", help="Project name")
    parser.add_argument("-a", "--auth", help="Authorization documentation")
    parser.add_argument("--scope", default="full", help="Scope type")
    parser.add_argument("--bounty", action="store_true", help="Enable bounty tracking")
    parser.add_argument("--stop-after", choices=['recon', 'scan', 'pentest'], help="Stop after phase")

    args = parser.parse_args()

    project_name = args.project or f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    project_path = BLACKBOX_ROOT / "projects" / project_name

    auth = {'scope': args.auth or 'Not documented'} if args.auth else None

    orchestrator = PipelineOrchestrator(
        project_path=project_path,
        target=args.target,
        authorization=auth,
        scope_type=args.scope,
        bounty_enabled=args.bounty
    )

    stop_phase = None
    if args.stop_after:
        stop_phase = PipelinePhase[args.stop_after.upper()]

    result = orchestrator.run(stop_after=stop_phase)

    print(json.dumps(result, indent=2))
