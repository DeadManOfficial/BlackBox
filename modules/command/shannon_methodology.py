"""
Shannon Methodology - 4-Phase Security Assessment Pattern
=========================================================

Based on KeygraphHQ/Shannon (96.15% XBOW benchmark success rate)

4-Phase Approach:
1. Reconnaissance - Target enumeration, surface mapping
2. Vulnerability Analysis - Deep analysis of attack vectors
3. Exploitation - Controlled exploitation with safety guardrails
4. Reporting - Structured findings with remediation

Integrates with Pentest Mission Control agents for enhanced orchestration.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class Phase(Enum):
    """Shannon 4-phase methodology phases"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"


class ConfidenceLevel(Enum):
    """Confidence levels for findings (from ODIN/moo.md patterns)"""
    AXIOM = 100      # Deterministic tool output
    HIGH = 95        # Multiple confirmations
    MODERATE = 75    # Single source
    UNCERTAIN = 50   # Needs verification
    UNKNOWN = 25     # Don't know


@dataclass
class PhaseFinding:
    """Finding with Shannon methodology metadata"""
    title: str
    severity: str
    description: str
    target_url: str
    phase: Phase
    confidence: ConfidenceLevel
    evidence: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    remediation: Optional[str] = None
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'target_url': self.target_url,
            'phase': self.phase.value,
            'confidence': self.confidence.value,
            'evidence': self.evidence,
            'attack_vector': self.attack_vector,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'metadata': self.metadata,
            'timestamp': self.timestamp
        }


@dataclass
class PhaseResult:
    """Result of a phase execution"""
    phase: Phase
    success: bool
    findings: List[PhaseFinding] = field(default_factory=list)
    duration_seconds: float = 0.0
    coverage: float = 0.0  # 0-1 percentage of target covered
    error: Optional[str] = None
    next_actions: List[str] = field(default_factory=list)
    handoff_context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AssessmentState:
    """Complete assessment state tracking"""
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    current_phase: Phase = Phase.RECONNAISSANCE
    phase_results: Dict[str, PhaseResult] = field(default_factory=dict)
    all_findings: List[PhaseFinding] = field(default_factory=list)
    attack_surface: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    safe_mode: bool = True

    def get_high_value_targets(self) -> List[str]:
        """Extract high-value targets from reconnaissance"""
        targets = []
        if 'endpoints' in self.attack_surface:
            targets.extend(self.attack_surface['endpoints'])
        if 'services' in self.attack_surface:
            targets.extend([s['url'] for s in self.attack_surface.get('services', [])])
        return targets[:10]  # Top 10


class ShannonPhaseExecutor:
    """
    Execute Shannon methodology phases with safety guardrails.

    Integrates with existing Pentest Mission Control agents
    to provide enhanced orchestration and confidence tracking.
    """

    def __init__(
        self,
        target: str,
        safe_mode: bool = True,
        on_finding: Optional[Callable[[PhaseFinding], None]] = None,
        on_phase_complete: Optional[Callable[[PhaseResult], None]] = None
    ):
        self.state = AssessmentState(target=target, safe_mode=safe_mode)
        self.on_finding = on_finding
        self.on_phase_complete = on_phase_complete

    def _report_finding(self, finding: PhaseFinding):
        """Report finding with callback"""
        self.state.all_findings.append(finding)
        if self.on_finding:
            self.on_finding(finding)

    def _complete_phase(self, result: PhaseResult):
        """Complete phase with callback"""
        self.state.phase_results[result.phase.value] = result
        if self.on_phase_complete:
            self.on_phase_complete(result)

    # ========== Phase 1: Reconnaissance ==========

    async def execute_reconnaissance(
        self,
        recon_data: Optional[Dict] = None
    ) -> PhaseResult:
        """
        Phase 1: Reconnaissance

        Objectives:
        - Enumerate target surface
        - Identify technologies
        - Map endpoints and services
        - Gather OSINT

        Args:
            recon_data: Optional pre-gathered reconnaissance data
        """
        self.state.current_phase = Phase.RECONNAISSANCE
        findings: List[PhaseFinding] = []
        start = datetime.now()

        try:
            # Build attack surface from recon data
            if recon_data:
                self.state.attack_surface.update(recon_data)

            # Report reconnaissance findings
            if 'technologies' in self.state.attack_surface:
                for tech in self.state.attack_surface['technologies']:
                    finding = PhaseFinding(
                        title=f"Technology Detected: {tech.get('name', 'Unknown')}",
                        severity='info',
                        description=f"Version: {tech.get('version', 'Unknown')}",
                        target_url=self.state.target,
                        phase=Phase.RECONNAISSANCE,
                        confidence=ConfidenceLevel.HIGH,
                        evidence=[f"Detected via: {tech.get('source', 'fingerprinting')}"],
                        metadata=tech
                    )
                    findings.append(finding)
                    self._report_finding(finding)

            if 'endpoints' in self.state.attack_surface:
                finding = PhaseFinding(
                    title=f"Attack Surface: {len(self.state.attack_surface['endpoints'])} Endpoints",
                    severity='info',
                    description="Endpoint enumeration complete",
                    target_url=self.state.target,
                    phase=Phase.RECONNAISSANCE,
                    confidence=ConfidenceLevel.AXIOM,
                    evidence=self.state.attack_surface['endpoints'][:5],
                    metadata={'total_endpoints': len(self.state.attack_surface['endpoints'])}
                )
                findings.append(finding)
                self._report_finding(finding)

            duration = (datetime.now() - start).total_seconds()
            result = PhaseResult(
                phase=Phase.RECONNAISSANCE,
                success=True,
                findings=findings,
                duration_seconds=duration,
                coverage=min(len(self.state.attack_surface.get('endpoints', [])) / 100, 1.0),
                next_actions=[
                    "Run vulnerability scanning on discovered endpoints",
                    "Analyze JavaScript for secrets and endpoints",
                    "Check for known CVEs in detected technologies"
                ],
                handoff_context={
                    'high_value_targets': self.state.get_high_value_targets(),
                    'technologies': self.state.attack_surface.get('technologies', [])
                }
            )

        except Exception as e:
            logger.error(f"Reconnaissance phase error: {e}")
            result = PhaseResult(
                phase=Phase.RECONNAISSANCE,
                success=False,
                error=str(e)
            )

        self._complete_phase(result)
        return result

    # ========== Phase 2: Vulnerability Analysis ==========

    async def execute_vulnerability_analysis(
        self,
        vuln_data: Optional[List[Dict]] = None
    ) -> PhaseResult:
        """
        Phase 2: Vulnerability Analysis

        Objectives:
        - Scan for CVEs
        - Analyze JS for secrets/endpoints
        - Test for misconfigurations
        - Correlate with threat intelligence

        Args:
            vuln_data: Optional vulnerability scan results
        """
        self.state.current_phase = Phase.VULNERABILITY_ANALYSIS
        findings: List[PhaseFinding] = []
        start = datetime.now()

        try:
            if vuln_data:
                for vuln in vuln_data:
                    # Determine confidence based on evidence
                    confidence = ConfidenceLevel.HIGH if vuln.get('verified') else ConfidenceLevel.MODERATE

                    finding = PhaseFinding(
                        title=vuln.get('title', 'Unknown Vulnerability'),
                        severity=vuln.get('severity', 'medium'),
                        description=vuln.get('description', ''),
                        target_url=vuln.get('target_url', self.state.target),
                        phase=Phase.VULNERABILITY_ANALYSIS,
                        confidence=confidence,
                        evidence=vuln.get('evidence', []),
                        attack_vector=vuln.get('attack_vector'),
                        cvss_score=vuln.get('cvss_score'),
                        cve_id=vuln.get('cve_id'),
                        remediation=vuln.get('remediation'),
                        metadata=vuln.get('metadata', {})
                    )
                    findings.append(finding)
                    self._report_finding(finding)

            # Identify exploitation candidates
            exploit_candidates = [
                f for f in findings
                if f.severity in ['critical', 'high'] and f.confidence.value >= 75
            ]

            duration = (datetime.now() - start).total_seconds()
            result = PhaseResult(
                phase=Phase.VULNERABILITY_ANALYSIS,
                success=True,
                findings=findings,
                duration_seconds=duration,
                coverage=len(findings) / max(len(vuln_data or []), 1),
                next_actions=[
                    f"Attempt exploitation of {len(exploit_candidates)} high-confidence vulnerabilities",
                    "Validate critical findings with manual testing",
                    "Check for chained attack paths"
                ],
                handoff_context={
                    'exploit_candidates': [f.to_dict() for f in exploit_candidates],
                    'severity_breakdown': self._count_by_severity(findings)
                }
            )

        except Exception as e:
            logger.error(f"Vulnerability analysis phase error: {e}")
            result = PhaseResult(
                phase=Phase.VULNERABILITY_ANALYSIS,
                success=False,
                error=str(e)
            )

        self._complete_phase(result)
        return result

    # ========== Phase 3: Exploitation ==========

    async def execute_exploitation(
        self,
        exploit_results: Optional[List[Dict]] = None
    ) -> PhaseResult:
        """
        Phase 3: Exploitation (with safety guardrails)

        Objectives:
        - Validate vulnerabilities through exploitation
        - Demonstrate impact
        - Capture evidence
        - Stay within scope and safe mode

        Args:
            exploit_results: Optional exploitation attempt results
        """
        self.state.current_phase = Phase.EXPLOITATION
        findings: List[PhaseFinding] = []
        start = datetime.now()

        try:
            if self.state.safe_mode:
                logger.info("Safe mode enabled - exploitation limited to validation")

            if exploit_results:
                for exploit in exploit_results:
                    # Only report successful exploits
                    if exploit.get('success'):
                        confidence = ConfidenceLevel.AXIOM  # Execution output = AXIOM

                        finding = PhaseFinding(
                            title=f"Exploited: {exploit.get('vulnerability', 'Unknown')}",
                            severity='critical',
                            description=exploit.get('description', 'Successful exploitation'),
                            target_url=exploit.get('target_url', self.state.target),
                            phase=Phase.EXPLOITATION,
                            confidence=confidence,
                            evidence=exploit.get('evidence', []),
                            attack_vector=exploit.get('attack_vector'),
                            remediation=exploit.get('remediation'),
                            metadata={
                                'exploit_type': exploit.get('type'),
                                'impact': exploit.get('impact'),
                                'safe_mode': self.state.safe_mode
                            }
                        )
                        findings.append(finding)
                        self._report_finding(finding)

            duration = (datetime.now() - start).total_seconds()
            result = PhaseResult(
                phase=Phase.EXPLOITATION,
                success=True,
                findings=findings,
                duration_seconds=duration,
                coverage=1.0 if findings else 0.0,
                next_actions=[
                    "Generate detailed report with evidence",
                    "Provide remediation recommendations",
                    "Calculate overall risk score"
                ],
                handoff_context={
                    'exploited_count': len(findings),
                    'safe_mode_active': self.state.safe_mode
                }
            )

        except Exception as e:
            logger.error(f"Exploitation phase error: {e}")
            result = PhaseResult(
                phase=Phase.EXPLOITATION,
                success=False,
                error=str(e)
            )

        self._complete_phase(result)
        return result

    # ========== Phase 4: Reporting ==========

    async def execute_reporting(self) -> PhaseResult:
        """
        Phase 4: Reporting

        Objectives:
        - Generate comprehensive assessment report
        - Prioritize findings by risk
        - Provide remediation roadmap
        - Calculate overall risk score
        """
        self.state.current_phase = Phase.REPORTING
        findings: List[PhaseFinding] = []
        start = datetime.now()

        try:
            # Calculate risk score
            self.state.risk_score = self._calculate_risk_score()

            # Generate summary finding
            severity_breakdown = self._count_by_severity(self.state.all_findings)

            # Identify attack chains
            attack_chains = self._identify_attack_chains()

            summary = PhaseFinding(
                title=f"Security Assessment Complete - Risk: {self._get_risk_level()}",
                severity=self._get_risk_level().lower() if self._get_risk_level() != 'LOW' else 'info',
                description=self._generate_executive_summary(severity_breakdown, attack_chains),
                target_url=self.state.target,
                phase=Phase.REPORTING,
                confidence=ConfidenceLevel.AXIOM,
                remediation=self._generate_remediation_roadmap(),
                metadata={
                    'risk_score': self.state.risk_score,
                    'risk_level': self._get_risk_level(),
                    'total_findings': len(self.state.all_findings),
                    'severity_breakdown': severity_breakdown,
                    'attack_chains': attack_chains,
                    'phase_coverage': {
                        p.value: self.state.phase_results.get(p.value, {}).get('coverage', 0)
                        for p in Phase
                    }
                }
            )
            findings.append(summary)
            self._report_finding(summary)

            duration = (datetime.now() - start).total_seconds()
            result = PhaseResult(
                phase=Phase.REPORTING,
                success=True,
                findings=findings,
                duration_seconds=duration,
                coverage=1.0,
                next_actions=[
                    "Review findings with security team",
                    "Begin remediation of critical issues",
                    "Schedule follow-up assessment"
                ],
                handoff_context={
                    'report_generated': True,
                    'risk_score': self.state.risk_score
                }
            )

        except Exception as e:
            logger.error(f"Reporting phase error: {e}")
            result = PhaseResult(
                phase=Phase.REPORTING,
                success=False,
                error=str(e)
            )

        self._complete_phase(result)
        return result

    # ========== Helper Methods ==========

    def _count_by_severity(self, findings: List[PhaseFinding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.severity.lower() if isinstance(f.severity, str) else f.severity
            if sev in counts:
                counts[sev] += 1
        return counts

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        severity_weights = {
            'critical': 25,
            'high': 15,
            'medium': 8,
            'low': 3,
            'info': 1
        }

        total = 0
        for finding in self.state.all_findings:
            sev = finding.severity.lower() if isinstance(finding.severity, str) else finding.severity
            weight = severity_weights.get(sev, 0)
            # Confidence multiplier
            confidence_mult = finding.confidence.value / 100
            total += weight * confidence_mult

        return min(total, 100)

    def _get_risk_level(self) -> str:
        """Get risk level from score"""
        score = self.state.risk_score
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'

    def _identify_attack_chains(self) -> List[Dict]:
        """Identify potential attack chains"""
        chains = []
        critical = [f for f in self.state.all_findings if f.severity == 'critical']
        high = [f for f in self.state.all_findings if f.severity == 'high']

        # Simple chain identification
        for h in high[:3]:
            for c in critical[:3]:
                if h.target_url == c.target_url or h.target_url in c.target_url:
                    chains.append({
                        'entry_point': h.title,
                        'escalation': c.title,
                        'likelihood': (h.confidence.value + c.confidence.value) / 200,
                        'impact': 'critical'
                    })

        return chains

    def _generate_executive_summary(
        self,
        severity_breakdown: Dict[str, int],
        attack_chains: List[Dict]
    ) -> str:
        """Generate executive summary"""
        total = sum(severity_breakdown.values())
        critical_high = severity_breakdown['critical'] + severity_breakdown['high']

        summary = f"""Security assessment of {self.state.target} identified {total} findings:
- Critical: {severity_breakdown['critical']}
- High: {severity_breakdown['high']}
- Medium: {severity_breakdown['medium']}
- Low: {severity_breakdown['low']}

{len(attack_chains)} potential attack chains were identified.
Overall risk score: {self.state.risk_score:.1f}/100 ({self._get_risk_level()})"""

        if critical_high > 0:
            summary += "\n\nImmediate attention required for critical/high severity findings."

        return summary

    def _generate_remediation_roadmap(self) -> str:
        """Generate prioritized remediation roadmap"""
        roadmap = ["Remediation Roadmap:"]

        # Group by severity
        critical = [f for f in self.state.all_findings if f.severity == 'critical']
        high = [f for f in self.state.all_findings if f.severity == 'high']

        if critical:
            roadmap.append("\n[IMMEDIATE - 24-48 hours]")
            for f in critical[:5]:
                roadmap.append(f"  - {f.title}: {f.remediation or 'Review and remediate'}")

        if high:
            roadmap.append("\n[SHORT-TERM - 1-2 weeks]")
            for f in high[:5]:
                roadmap.append(f"  - {f.title}: {f.remediation or 'Review and remediate'}")

        roadmap.append("\n[LONG-TERM - 1 month]")
        roadmap.append("  - Implement security monitoring")
        roadmap.append("  - Schedule follow-up assessment")

        return "\n".join(roadmap)


# ========== Integration with Pentest Mission Control ==========

def create_shannon_executor(
    target: str,
    safe_mode: bool = True,
    on_finding: Optional[Callable] = None,
    on_phase_complete: Optional[Callable] = None
) -> ShannonPhaseExecutor:
    """
    Factory function to create Shannon executor.

    Usage:
        executor = create_shannon_executor("https://example.com")

        # Phase 1
        recon_result = await executor.execute_reconnaissance(recon_data)

        # Phase 2
        vuln_result = await executor.execute_vulnerability_analysis(vuln_data)

        # Phase 3 (if safe mode allows)
        exploit_result = await executor.execute_exploitation(exploit_data)

        # Phase 4
        report_result = await executor.execute_reporting()
    """
    return ShannonPhaseExecutor(
        target=target,
        safe_mode=safe_mode,
        on_finding=on_finding,
        on_phase_complete=on_phase_complete
    )


async def run_shannon_assessment(
    target: str,
    recon_data: Optional[Dict] = None,
    vuln_data: Optional[List[Dict]] = None,
    exploit_data: Optional[List[Dict]] = None,
    safe_mode: bool = True,
    on_finding: Optional[Callable] = None
) -> AssessmentState:
    """
    Run complete Shannon 4-phase assessment.

    Returns:
        Complete assessment state with all findings and risk score
    """
    executor = create_shannon_executor(
        target=target,
        safe_mode=safe_mode,
        on_finding=on_finding
    )

    # Execute all phases
    await executor.execute_reconnaissance(recon_data)
    await executor.execute_vulnerability_analysis(vuln_data)

    if not safe_mode or exploit_data:
        await executor.execute_exploitation(exploit_data)

    await executor.execute_reporting()

    return executor.state
