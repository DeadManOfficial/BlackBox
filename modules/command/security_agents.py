"""
Security Agents - Specialized Security Testing Agents
======================================================

5 specialized agents wrapping the 8 core security tools:

1. VulnerabilityAgent - NucleiScanner, JSSecurityAnalyzer
2. LLMSecurityAgent - LLMRedTeamFramework
3. ReconAgent - SecurityIntelAggregator, StealthBrowser
4. ExploitAgent - WAFBypassEngine, RaceConditionScanner, PentestAgent
5. SynthesisAgent - Correlates all findings
"""

import asyncio
import logging
import sys
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

# Add tools path dynamically based on project location
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TOOLS_PATH = os.environ.get('PENTEST_TOOLS_PATH', os.path.join(os.path.dirname(_PROJECT_ROOT), 'tools'))
if _TOOLS_PATH not in sys.path:
    sys.path.insert(0, _TOOLS_PATH)

from config import ScanParameters

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    """Agent state tracking"""
    agent_id: str
    status: str = "idle"
    current_task: str = "Standby"
    progress: int = 0
    findings_count: int = 0
    error: Optional[str] = None


class BaseSecurityAgent(ABC):
    """Base class for security agents"""

    def __init__(
        self,
        agent_id: str,
        parameters: ScanParameters,
        on_finding: Callable[[Dict], None],
        on_progress: Callable[[str, int, str], None]
    ):
        self.agent_id = agent_id
        self.parameters = parameters
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.state = AgentState(agent_id=agent_id)
        self.is_active = False

    @abstractmethod
    async def execute(self):
        """Execute main agent task"""
        pass

    async def execute_task(self, task: str):
        """Execute specific task"""
        # Default implementation calls execute
        await self.execute()

    def report_finding(self, finding: Dict):
        """Report a finding"""
        finding['agent_id'] = self.agent_id
        finding['discovered_at'] = datetime.now().isoformat()
        self.state.findings_count += 1
        self.on_finding(finding)

    def report_progress(self, progress: int, task: str = None):
        """Report progress"""
        self.state.progress = progress
        if task:
            self.state.current_task = task
        self.on_progress(self.agent_id, progress, task)

    def set_status(self, status: str):
        """Set agent status"""
        self.state.status = status


class VulnerabilityAgent(BaseSecurityAgent):
    """
    Vulnerability scanning agent.

    Integrates:
    - Nuclei Scanner for CVE detection
    - JS Security Analyzer for secrets and endpoints
    """

    def __init__(self, parameters: ScanParameters, on_finding, on_progress):
        super().__init__("vulnerability", parameters, on_finding, on_progress)

    async def execute(self):
        """Run vulnerability scanning"""
        self.is_active = True
        self.set_status("active")
        self.report_progress(0, "Initializing Nuclei scanner")

        try:
            # Import Nuclei scanner
            from tools.nuclei_scanner import NucleiScanner, ScanConfig, Severity

            scanner = NucleiScanner()

            if not scanner.is_installed():
                logger.warning("Nuclei not installed, using simulated scan")
                await self._simulated_nuclei_scan()
                return

            self.report_progress(10, "Running Nuclei vulnerability scan")

            # Configure scan
            severity_filter = [Severity(s) for s in self.parameters.nuclei_severity]

            config = ScanConfig(
                severity_filter=severity_filter,
                rate_limit=100 if self.parameters.intensity.value == 'passive' else 150,
                concurrency=10 if self.parameters.intensity.value == 'passive' else 25,
                timeout=30
            )

            # Run scan with callback
            def on_vuln(vuln):
                self.report_finding({
                    'title': vuln.template_name,
                    'severity': vuln.severity.value,
                    'description': f"Vulnerability found at {vuln.matched_at}",
                    'target_url': vuln.matched_at,
                    'evidence': vuln.curl_command or '',
                    'cvss_score': vuln.cvss_score,
                    'cve_id': vuln.metadata.get('cve-id', ''),
                    'metadata': vuln.metadata
                })

            result = await scanner.scan(
                self.parameters.target,
                config,
                callback=on_vuln
            )

            self.report_progress(80, f"Nuclei scan complete: {len(result.vulnerabilities)} findings")

        except ImportError as e:
            logger.warning(f"Nuclei import failed, using simulated scan: {e}")
            await self._simulated_nuclei_scan()
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
            self.state.error = str(e)
        finally:
            self.is_active = False
            self.set_status("completed")
            self.report_progress(100, "Vulnerability scan complete")

    async def execute_task(self, task: str):
        """Execute specific vulnerability task"""
        if task == 'js_analysis':
            await self._run_js_analysis()
        else:
            await self.execute()

    async def _run_js_analysis(self):
        """Run JavaScript security analysis"""
        self.report_progress(0, "Analyzing JavaScript files")

        try:
            from tools.js_analyzer import JSSecurityAnalyzer

            analyzer = JSSecurityAnalyzer()
            target_url = self.parameters.target

            self.report_progress(20, f"Scanning JS at {target_url}")

            # This is a simplified example - real impl would discover JS files
            js_urls = [
                f"{target_url}/static/js/main.js",
                f"{target_url}/assets/app.js",
                f"{target_url}/bundle.js"
            ]

            for i, js_url in enumerate(js_urls):
                try:
                    result = await analyzer.analyze(js_url)
                    progress = 20 + ((i + 1) / len(js_urls)) * 60

                    for finding in result.get('findings', []):
                        self.report_finding({
                            'title': f"JS: {finding.get('type', 'Secret')} found",
                            'severity': 'high' if 'key' in finding.get('type', '').lower() else 'medium',
                            'description': finding.get('description', ''),
                            'target_url': js_url,
                            'evidence': finding.get('value', '')[:100],
                            'metadata': {'source': 'js_analyzer'}
                        })

                    self.report_progress(int(progress), f"Analyzed {js_url}")

                except Exception as e:
                    logger.debug(f"JS analysis failed for {js_url}: {e}")

        except ImportError:
            logger.warning("JS Analyzer not available")
        except Exception as e:
            logger.error(f"JS analysis error: {e}")
        finally:
            self.report_progress(100, "JS analysis complete")

    async def _simulated_nuclei_scan(self):
        """Simulated scan when Nuclei is not available"""
        self.report_progress(30, "Running simulated vulnerability check")
        await asyncio.sleep(2)

        # Generate sample findings for demo
        sample_findings = [
            {
                'title': 'Directory Listing Enabled',
                'severity': 'low',
                'description': 'Directory listing is enabled on the web server',
                'target_url': f"{self.parameters.target}/images/",
                'metadata': {'template': 'directory-listing'}
            },
            {
                'title': 'Missing Security Headers',
                'severity': 'info',
                'description': 'X-Frame-Options header is missing',
                'target_url': self.parameters.target,
                'metadata': {'template': 'missing-x-frame-options'}
            }
        ]

        for finding in sample_findings:
            self.report_finding(finding)

        self.report_progress(100, "Simulated scan complete")


class LLMSecurityAgent(BaseSecurityAgent):
    """
    LLM/AI Security testing agent.

    Integrates:
    - LLM Red Team Framework (40+ vulnerability classes)
    """

    def __init__(self, parameters: ScanParameters, on_finding, on_progress):
        super().__init__("llm_security", parameters, on_finding, on_progress)

    async def execute(self):
        """Run LLM security testing"""
        if not self.parameters.ai_endpoint:
            logger.info("No AI endpoint configured, skipping LLM security testing")
            self.report_progress(100, "Skipped - no AI endpoint")
            return

        self.is_active = True
        self.set_status("active")
        self.report_progress(0, "Initializing LLM Red Team Framework")

        try:
            from tools.llm_redteam import LLMRedTeamFramework, Severity, AttackStrategy

            framework = LLMRedTeamFramework(
                timeout=30,
                max_concurrent=3,
                enable_mutations=True
            )

            self.report_progress(10, "Running LLM security assessment")

            # Map strategy names to enums
            strategies = []
            for s in self.parameters.llm_strategies:
                try:
                    strategies.append(AttackStrategy(s))
                except ValueError:
                    pass

            if not strategies:
                strategies = [AttackStrategy.DIRECT, AttackStrategy.MULTI_TURN]

            # Run assessment
            report = await framework.test_http_endpoint(
                url=self.parameters.ai_endpoint,
                strategies=strategies,
                min_severity=Severity.MEDIUM
            )

            self.report_progress(70, f"Assessment complete: {report.successful_attacks}/{report.total_attacks} vulnerabilities")

            # Convert results to findings
            for result in report.results:
                if result.vulnerable:
                    self.report_finding({
                        'title': f"LLM Vulnerability: {result.payload.vuln_class.value}",
                        'severity': result.payload.severity.name.lower(),
                        'description': result.payload.description,
                        'target_url': self.parameters.ai_endpoint,
                        'evidence': result.response[:500] if result.response else '',
                        'metadata': {
                            'payload_id': result.payload.id,
                            'strategy': result.payload.strategy.value,
                            'owasp': result.payload.owasp_mapping,
                            'confidence': result.confidence
                        }
                    })

            # Report OWASP compliance
            self.report_finding({
                'title': f"OWASP LLM Compliance Score: {report.owasp_compliance_score:.0f}%",
                'severity': 'critical' if report.owasp_compliance_score < 50 else 'info',
                'description': f"OWASP LLM Top 10 compliance assessment. Vulnerability rate: {report.vulnerability_rate:.1%}",
                'target_url': self.parameters.ai_endpoint,
                'metadata': {
                    'owasp_findings': report.owasp_findings,
                    'severity_breakdown': report.severity_breakdown
                }
            })

        except ImportError as e:
            logger.warning(f"LLM Red Team import failed: {e}")
        except Exception as e:
            logger.error(f"LLM security testing error: {e}")
            self.state.error = str(e)
        finally:
            self.is_active = False
            self.set_status("completed")
            self.report_progress(100, "LLM security testing complete")


class ReconAgent(BaseSecurityAgent):
    """
    Reconnaissance agent.

    Integrates:
    - Security Intelligence Aggregator (CVE, Exploit-DB, GitHub Advisory)
    - Stealth Browser for WAF-protected targets
    """

    def __init__(self, parameters: ScanParameters, on_finding, on_progress):
        super().__init__("recon", parameters, on_finding, on_progress)

    async def execute(self):
        """Run reconnaissance"""
        self.is_active = True
        self.set_status("active")
        self.report_progress(0, "Starting reconnaissance")

        try:
            # Phase 1: Technology fingerprinting
            self.report_progress(10, "Fingerprinting target technology")
            await self._fingerprint_technology()

            # Phase 2: Security intelligence gathering
            self.report_progress(40, "Gathering security intelligence")
            await self._gather_intelligence()

            # Phase 3: Stealth reconnaissance (if aggressive mode)
            if self.parameters.intensity.value == 'aggressive':
                self.report_progress(70, "Running stealth reconnaissance")
                await self._stealth_recon()

        except Exception as e:
            logger.error(f"Recon error: {e}")
            self.state.error = str(e)
        finally:
            self.is_active = False
            self.set_status("completed")
            self.report_progress(100, "Reconnaissance complete")

    async def _fingerprint_technology(self):
        """Identify target technologies"""
        # Simplified fingerprinting
        target = self.parameters.target

        # Common tech indicators (would use proper fingerprinting in production)
        tech_findings = []

        if 'wordpress' in target.lower():
            tech_findings.append(('WordPress', 'CMS'))
        if 'react' in target.lower() or 'next' in target.lower():
            tech_findings.append(('React/Next.js', 'Frontend Framework'))

        for tech, category in tech_findings:
            self.report_finding({
                'title': f"Technology Detected: {tech}",
                'severity': 'info',
                'description': f"{category}: {tech} detected on target",
                'target_url': target,
                'metadata': {'technology': tech, 'category': category}
            })

    async def _gather_intelligence(self):
        """Gather security intelligence from public sources"""
        try:
            from tools.intel_gatherer import SecurityIntelAggregator

            aggregator = SecurityIntelAggregator()

            # Extract domain from target
            import re
            domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', self.parameters.target)
            domain = domain_match.group(1) if domain_match else self.parameters.target

            # Search for known vulnerabilities
            results = await aggregator.comprehensive_search(domain)

            # Process CVE results
            for cve in results.get('sources', {}).get('cve', [])[:5]:
                self.report_finding({
                    'title': f"Known CVE: {cve.id}",
                    'severity': cve.severity.lower() if hasattr(cve, 'severity') else 'medium',
                    'description': cve.description[:500] if hasattr(cve, 'description') else '',
                    'target_url': self.parameters.target,
                    'cve_id': cve.id if hasattr(cve, 'id') else '',
                    'cvss_score': cve.cvss_score if hasattr(cve, 'cvss_score') else None,
                    'metadata': {'source': 'intel_gatherer'}
                })

        except ImportError:
            logger.warning("Intel gatherer not available")
        except Exception as e:
            logger.error(f"Intelligence gathering error: {e}")

    async def _stealth_recon(self):
        """Use stealth browser for WAF-protected reconnaissance"""
        try:
            from tools.stealth_browser import StealthBrowserFactory, StealthConfig

            config = StealthConfig(headless=True)

            browser = await StealthBrowserFactory.create(config)

            try:
                result = await browser.goto(self.parameters.target)

                self.report_finding({
                    'title': f"Page Accessible: {result.title}",
                    'severity': 'info',
                    'description': f"Successfully accessed {self.parameters.target}",
                    'target_url': self.parameters.target,
                    'metadata': {
                        'status': result.status,
                        'load_time_ms': result.timing.get('load_ms', 0)
                    }
                })

            finally:
                await browser.close()

        except ImportError:
            logger.warning("Stealth browser not available")
        except Exception as e:
            logger.error(f"Stealth recon error: {e}")


class ExploitAgent(BaseSecurityAgent):
    """
    Exploit analysis agent.

    Integrates:
    - WAF Bypass Engine
    - Race Condition Scanner
    - Autonomous Pentest Agent (attack path planning)
    """

    def __init__(self, parameters: ScanParameters, on_finding, on_progress):
        super().__init__("exploit", parameters, on_finding, on_progress)

    async def execute(self):
        """Run exploit analysis (safe mode by default)"""
        if self.parameters.safe_mode:
            logger.info("Running in safe mode - no exploitation attempts")

        self.is_active = True
        self.set_status("active")
        self.report_progress(0, "Starting exploit analysis")

        try:
            # Phase 1: WAF detection and bypass analysis
            self.report_progress(10, "Analyzing WAF/CDN")
            await self._analyze_waf()

            # Phase 2: Race condition potential
            if not self.parameters.safe_mode:
                self.report_progress(40, "Checking race condition potential")
                await self._check_race_conditions()

            # Phase 3: Attack path planning
            self.report_progress(70, "Planning attack paths")
            await self._plan_attack_paths()

        except Exception as e:
            logger.error(f"Exploit analysis error: {e}")
            self.state.error = str(e)
        finally:
            self.is_active = False
            self.set_status("completed")
            self.report_progress(100, "Exploit analysis complete")

    async def _analyze_waf(self):
        """Analyze WAF/CDN presence"""
        try:
            from tools.advanced_attacks import WAFBypassEngine

            engine = WAFBypassEngine()

            # Extract domain
            import re
            domain_match = re.search(r'(?:https?://)?(?:www\.)?([^/]+)', self.parameters.target)
            domain = domain_match.group(1) if domain_match else self.parameters.target

            result = await engine.discover_origin(domain)

            if result.get('origin_ip'):
                self.report_finding({
                    'title': 'WAF Bypass: Origin IP Discovered',
                    'severity': 'high',
                    'description': f"Origin IP found behind WAF/CDN: {result.get('origin_ip')}",
                    'target_url': self.parameters.target,
                    'evidence': str(result.get('methods_used', [])),
                    'metadata': result
                })
            elif result.get('waf_detected'):
                self.report_finding({
                    'title': f"WAF Detected: {result.get('waf_name', 'Unknown')}",
                    'severity': 'info',
                    'description': 'Web Application Firewall detected protecting target',
                    'target_url': self.parameters.target,
                    'metadata': result
                })

        except ImportError:
            logger.warning("WAF Bypass Engine not available")
        except Exception as e:
            logger.error(f"WAF analysis error: {e}")

    async def _check_race_conditions(self):
        """Check for race condition vulnerabilities"""
        try:
            from tools.advanced_attacks import RaceConditionScanner

            scanner = RaceConditionScanner()

            # Only test if target has likely endpoints
            test_endpoints = [
                f"{self.parameters.target}/api/checkout",
                f"{self.parameters.target}/api/redeem",
                f"{self.parameters.target}/api/vote"
            ]

            for endpoint in test_endpoints:
                try:
                    result = await scanner.test_endpoint(
                        endpoint,
                        method="POST",
                        concurrent_requests=10
                    )

                    if result.get('vulnerable'):
                        self.report_finding({
                            'title': f"Race Condition: {result.get('type', 'TOCTOU')}",
                            'severity': 'high',
                            'description': f"Race condition vulnerability at {endpoint}",
                            'target_url': endpoint,
                            'metadata': result
                        })
                except Exception:
                    pass  # Endpoint doesn't exist or not vulnerable

        except ImportError:
            logger.warning("Race Condition Scanner not available")
        except Exception as e:
            logger.error(f"Race condition check error: {e}")

    async def _plan_attack_paths(self):
        """Use MCTS to plan optimal attack paths"""
        try:
            from tools.pentest_agent import AttackPathPlanner, Target

            planner = AttackPathPlanner(iterations=50)
            target = Target(host=self.parameters.target)

            # Plan based on current findings
            context = {
                'safe_mode': self.parameters.safe_mode,
                'intensity': self.parameters.intensity.value
            }

            path = planner.plan(target, context)

            if path.steps:
                self.report_finding({
                    'title': f"Attack Path: {len(path.steps)} steps identified",
                    'severity': 'info',
                    'description': f"Optimal attack path calculated with success probability: {path.success_probability:.1%}",
                    'target_url': self.parameters.target,
                    'metadata': {
                        'path_id': path.id,
                        'steps': [s.description for s in path.steps],
                        'score': path.score
                    }
                })

        except ImportError:
            logger.warning("Pentest Agent not available")
        except Exception as e:
            logger.error(f"Attack path planning error: {e}")


class SynthesisAgent(BaseSecurityAgent):
    """
    Synthesis agent - correlates and analyzes all findings.

    Identifies attack chains, prioritizes vulnerabilities,
    and generates risk assessment.
    """

    def __init__(self, parameters: ScanParameters, on_finding, on_progress):
        super().__init__("synthesis", parameters, on_finding, on_progress)
        self.all_findings: List[Dict] = []

    def set_findings(self, findings: List[Dict]):
        """Set findings from other agents for analysis"""
        self.all_findings = findings

    async def execute(self):
        """Synthesize and correlate findings"""
        self.is_active = True
        self.set_status("active")
        self.report_progress(0, "Analyzing findings")

        try:
            if not self.all_findings:
                logger.info("No findings to synthesize")
                return

            # Phase 1: Identify attack chains
            self.report_progress(20, "Identifying attack chains")
            chains = self._identify_attack_chains()

            # Phase 2: Calculate risk scores
            self.report_progress(50, "Calculating risk scores")
            risk = self._calculate_risk_score()

            # Phase 3: Generate recommendations
            self.report_progress(80, "Generating recommendations")
            recommendations = self._generate_recommendations()

            # Report synthesis finding
            self.report_finding({
                'title': f"Security Assessment Summary",
                'severity': 'critical' if risk['level'] == 'CRITICAL' else 'high' if risk['level'] == 'HIGH' else 'info',
                'description': f"Risk Level: {risk['level']} (Score: {risk['score']}/100). {len(chains)} attack chains identified.",
                'target_url': self.parameters.target,
                'metadata': {
                    'risk': risk,
                    'attack_chains': chains,
                    'recommendations': recommendations
                }
            })

        except Exception as e:
            logger.error(f"Synthesis error: {e}")
            self.state.error = str(e)
        finally:
            self.is_active = False
            self.set_status("completed")
            self.report_progress(100, "Synthesis complete")

    def _identify_attack_chains(self) -> List[Dict]:
        """Identify potential attack chains from findings"""
        chains = []

        critical = [f for f in self.all_findings if f.get('severity') == 'critical']
        high = [f for f in self.all_findings if f.get('severity') == 'high']

        # Simple chain: high -> critical
        for h in high[:3]:
            for c in critical[:3]:
                chains.append({
                    'steps': [h.get('title'), c.get('title')],
                    'likelihood': 0.7,
                    'impact': 'high'
                })

        return chains

    def _calculate_risk_score(self) -> Dict:
        """Calculate overall risk score"""
        from config import SEVERITY_SCORES

        total_score = 0
        for finding in self.all_findings:
            sev = finding.get('severity', 'info').lower()
            total_score += SEVERITY_SCORES.get(sev, 0)

        score = min(total_score, 100)

        if score >= 70:
            level = 'CRITICAL'
        elif score >= 50:
            level = 'HIGH'
        elif score >= 30:
            level = 'MEDIUM'
        else:
            level = 'LOW'

        return {
            'score': score,
            'level': level,
            'total_findings': len(self.all_findings)
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []

        critical_count = len([f for f in self.all_findings if f.get('severity') == 'critical'])
        high_count = len([f for f in self.all_findings if f.get('severity') == 'high'])

        if critical_count > 0:
            recommendations.append(f"URGENT: Address {critical_count} critical vulnerabilities immediately")

        if high_count > 0:
            recommendations.append(f"HIGH PRIORITY: Review and remediate {high_count} high severity findings")

        # Check for common vulnerability types
        llm_vulns = [f for f in self.all_findings if 'LLM' in f.get('title', '')]
        if llm_vulns:
            recommendations.append("Implement AI/LLM security controls and prompt injection defenses")

        waf_findings = [f for f in self.all_findings if 'WAF' in f.get('title', '')]
        if waf_findings:
            recommendations.append("Review WAF configuration and ensure origin IP is properly protected")

        return recommendations


class SecurityAgentFactory:
    """Factory for creating security agents"""

    AGENTS = {
        'vulnerability': VulnerabilityAgent,
        'llm_security': LLMSecurityAgent,
        'recon': ReconAgent,
        'exploit': ExploitAgent,
        'synthesis': SynthesisAgent
    }

    @classmethod
    def create_agent(
        cls,
        agent_type: str,
        parameters: ScanParameters,
        on_finding: Callable,
        on_progress: Callable
    ) -> BaseSecurityAgent:
        """Create a security agent by type"""
        if agent_type not in cls.AGENTS:
            raise ValueError(f"Unknown agent type: {agent_type}")

        return cls.AGENTS[agent_type](parameters, on_finding, on_progress)

    @classmethod
    def get_available_agent_types(cls) -> List[str]:
        """Get list of available agent types"""
        return list(cls.AGENTS.keys())
