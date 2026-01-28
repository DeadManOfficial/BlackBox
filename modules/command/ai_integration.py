"""
AI Integration Module - Unified AI-Powered Security Analysis
============================================================

Combines:
- json_repair: Handle malformed LLM outputs
- shannon_methodology: 4-phase security assessment
- llm_router: Free-tier-first API routing

Provides seamless AI-powered security analysis for Pentest Mission Control.

SECURITY: Includes prompt injection sanitization to protect against malicious input.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


# =============================================================================
# Prompt Injection Sanitization (Security Critical)
# =============================================================================

def sanitize_for_prompt(data: str, max_length: int = 4000) -> str:
    """
    Sanitize user-controlled data before including in LLM prompts.

    Prevents prompt injection attacks by:
    1. Removing instruction override patterns
    2. Escaping format string characters
    3. Removing system prompt extraction attempts
    4. Truncating to prevent context overflow

    Args:
        data: User-controlled data to sanitize
        max_length: Maximum length after sanitization

    Returns:
        Sanitized string safe for prompt inclusion
    """
    if not data:
        return ""

    sanitized = str(data)

    # Remove common prompt injection patterns (case-insensitive)
    injection_patterns = [
        # Instruction override attempts
        r'(ignore|forget|disregard|override)\s+(all\s+)?(previous|above|prior|earlier|system)\s+(instructions?|prompts?|rules?|guidelines?)',
        r'(new|updated|revised)\s+(instructions?|prompts?|rules?)',
        r'(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)',
        r'(your\s+new\s+(role|persona|identity)\s+is)',

        # System prompt extraction attempts
        r'(what\s+is\s+your|show\s+me\s+your|reveal\s+your|print\s+your)\s+(system\s+)?(prompt|instructions?)',
        r'(repeat|echo|display)\s+(the\s+)?(system\s+)?(prompt|instructions?)',
        r'(beginning|start)\s+of\s+(the\s+)?(system\s+)?(prompt|conversation)',

        # Code/command injection attempts
        r'```\s*(python|bash|shell|cmd|exec)',
        r'<\s*(script|iframe|object|embed)',
        r'\{\{\s*[^}]+\s*\}\}',  # Template injection

        # Role confusion attempts
        r'(assistant|ai|claude|gpt|model)\s*:\s*',
        r'(user|human)\s*:\s*\[',
    ]

    for pattern in injection_patterns:
        sanitized = re.sub(pattern, '[FILTERED]', sanitized, flags=re.IGNORECASE)

    # Escape Python format string characters to prevent f-string injection
    sanitized = sanitized.replace('{', '{{').replace('}', '}}')

    # Remove null bytes and other problematic characters
    sanitized = sanitized.replace('\x00', '').replace('\r', '\n')

    # Truncate to max length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '...[truncated]'

    return sanitized


def sanitize_dict_for_prompt(data: Dict[str, Any], max_length: int = 4000) -> str:
    """Sanitize a dictionary for prompt inclusion."""
    # Convert to string and sanitize
    return sanitize_for_prompt(str(data), max_length)

from .json_repair import validate_ai_json, safe_json_loads, JSONResult
from .shannon_methodology import (
    ShannonPhaseExecutor,
    Phase,
    ConfidenceLevel,
    PhaseFinding,
    PhaseResult,
    AssessmentState,
    create_shannon_executor,
    run_shannon_assessment
)
from .llm_router import (
    LLMRouter,
    Priority,
    Provider,
    RouteResult,
    complete_free,
    complete_cost_optimized,
    analyze_vulnerability
)

logger = logging.getLogger(__name__)


# ========== AI Analysis Templates ==========

VULN_ANALYSIS_PROMPT = """Analyze the following security scan results and provide:
1. Severity assessment (critical/high/medium/low)
2. Exploitation difficulty
3. Business impact
4. Recommended remediation steps
5. Related CVEs if applicable

Scan Results:
{scan_results}

Respond in JSON format:
{{
    "severity": "...",
    "exploitation_difficulty": "...",
    "business_impact": "...",
    "remediation": ["step1", "step2"],
    "cves": ["CVE-..."],
    "confidence": 0.0-1.0
}}"""

ATTACK_CHAIN_PROMPT = """Given these vulnerabilities, identify potential attack chains:

Vulnerabilities:
{vulnerabilities}

For each attack chain, provide:
1. Entry point vulnerability
2. Escalation path
3. Target (what attacker gains)
4. Likelihood (0-1)
5. Overall impact

Respond in JSON format:
{{
    "attack_chains": [
        {{
            "name": "Chain Name",
            "entry_point": "...",
            "steps": ["step1", "step2"],
            "target": "...",
            "likelihood": 0.0-1.0,
            "impact": "critical/high/medium/low"
        }}
    ]
}}"""

REMEDIATION_PROMPT = """Generate a prioritized remediation plan for these findings:

Findings:
{findings}

Consider:
1. Severity of each issue
2. Exploitation likelihood
3. Dependencies between fixes
4. Resource requirements

Respond in JSON format:
{{
    "immediate": [
        {{"finding": "...", "action": "...", "effort": "low/medium/high"}}
    ],
    "short_term": [...],
    "long_term": [...]
}}"""


@dataclass
class AIAnalysisResult:
    """Result of AI-powered analysis"""
    success: bool
    analysis_type: str
    data: Optional[Dict[str, Any]] = None
    raw_response: Optional[str] = None
    provider_used: Optional[str] = None
    tokens_used: int = 0
    cost_usd: float = 0.0
    confidence: float = 0.0
    errors: List[str] = field(default_factory=list)
    was_repaired: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class AISecurityAnalyzer:
    """
    AI-powered security analysis - ALL FREE FOREVER.

    Combines Shannon methodology, FREE LLM routing, and robust JSON parsing
    for reliable AI-assisted security assessments.

    Never pays for LLM APIs - uses Groq, Google AI Studio, Cerebras.
    """

    def __init__(
        self,
        priority: Priority = Priority.FREE,
        safe_mode: bool = True
    ):
        self.router = LLMRouter(priority=priority)
        self.safe_mode = safe_mode
        self.analysis_history: List[AIAnalysisResult] = []

    async def analyze_vulnerability(
        self,
        scan_results: Dict[str, Any],
        expected_keys: Optional[List[str]] = None
    ) -> AIAnalysisResult:
        """
        Analyze vulnerability scan results with AI.

        Uses free providers first, falls back to premium if needed.
        Handles malformed JSON responses automatically.
        """
        # SECURITY: Sanitize input to prevent prompt injection attacks
        sanitized_results = sanitize_dict_for_prompt(scan_results, max_length=4000)
        prompt = VULN_ANALYSIS_PROMPT.format(
            scan_results=sanitized_results
        )

        expected = expected_keys or ['severity', 'remediation']

        try:
            # Route to best available provider
            route_result = await self.router.complete(
                prompt,
                system_prompt="You are a cybersecurity expert. Respond only with valid JSON."
            )

            if not route_result.success:
                return AIAnalysisResult(
                    success=False,
                    analysis_type="vulnerability",
                    errors=[route_result.error or "LLM call failed"]
                )

            # Parse and repair JSON if needed
            json_result = validate_ai_json(
                route_result.response,
                expected_keys=expected
            )

            result = AIAnalysisResult(
                success=json_result.json_valid,
                analysis_type="vulnerability",
                data=json_result.data,
                raw_response=route_result.response,
                provider_used=route_result.provider.value,
                tokens_used=route_result.tokens_used,
                cost_usd=route_result.cost_usd,
                confidence=json_result.data.get('confidence', 0.7) if json_result.data else 0.0,
                errors=json_result.errors,
                was_repaired=json_result.was_repaired
            )

        except Exception as e:
            logger.error(f"Vulnerability analysis error: {e}")
            result = AIAnalysisResult(
                success=False,
                analysis_type="vulnerability",
                errors=[str(e)]
            )

        self.analysis_history.append(result)
        return result

    async def identify_attack_chains(
        self,
        vulnerabilities: List[Dict[str, Any]]
    ) -> AIAnalysisResult:
        """
        Use AI to identify potential attack chains from vulnerabilities.
        """
        # SECURITY: Sanitize input to prevent prompt injection attacks
        sanitized_vulns = sanitize_for_prompt(str(vulnerabilities), max_length=4000)
        prompt = ATTACK_CHAIN_PROMPT.format(
            vulnerabilities=sanitized_vulns
        )

        try:
            route_result = await self.router.complete(
                prompt,
                system_prompt="You are an offensive security expert. Respond only with valid JSON."
            )

            if not route_result.success:
                return AIAnalysisResult(
                    success=False,
                    analysis_type="attack_chains",
                    errors=[route_result.error or "LLM call failed"]
                )

            json_result = validate_ai_json(
                route_result.response,
                expected_keys=['attack_chains']
            )

            result = AIAnalysisResult(
                success=json_result.json_valid,
                analysis_type="attack_chains",
                data=json_result.data,
                raw_response=route_result.response,
                provider_used=route_result.provider.value,
                tokens_used=route_result.tokens_used,
                cost_usd=route_result.cost_usd,
                confidence=0.8 if json_result.json_valid else 0.0,
                errors=json_result.errors,
                was_repaired=json_result.was_repaired
            )

        except Exception as e:
            logger.error(f"Attack chain analysis error: {e}")
            result = AIAnalysisResult(
                success=False,
                analysis_type="attack_chains",
                errors=[str(e)]
            )

        self.analysis_history.append(result)
        return result

    async def generate_remediation_plan(
        self,
        findings: List[Dict[str, Any]]
    ) -> AIAnalysisResult:
        """
        Generate AI-powered remediation plan.
        """
        # SECURITY: Sanitize input to prevent prompt injection attacks
        sanitized_findings = sanitize_for_prompt(str(findings), max_length=4000)
        prompt = REMEDIATION_PROMPT.format(
            findings=sanitized_findings
        )

        try:
            route_result = await self.router.complete(
                prompt,
                system_prompt="You are a security remediation specialist. Respond only with valid JSON."
            )

            if not route_result.success:
                return AIAnalysisResult(
                    success=False,
                    analysis_type="remediation",
                    errors=[route_result.error or "LLM call failed"]
                )

            json_result = validate_ai_json(
                route_result.response,
                expected_keys=['immediate', 'short_term', 'long_term']
            )

            result = AIAnalysisResult(
                success=json_result.json_valid,
                analysis_type="remediation",
                data=json_result.data,
                raw_response=route_result.response,
                provider_used=route_result.provider.value,
                tokens_used=route_result.tokens_used,
                cost_usd=route_result.cost_usd,
                confidence=0.85 if json_result.json_valid else 0.0,
                errors=json_result.errors,
                was_repaired=json_result.was_repaired
            )

        except Exception as e:
            logger.error(f"Remediation planning error: {e}")
            result = AIAnalysisResult(
                success=False,
                analysis_type="remediation",
                errors=[str(e)]
            )

        self.analysis_history.append(result)
        return result

    async def run_shannon_assessment(
        self,
        target: str,
        recon_data: Optional[Dict] = None,
        vuln_data: Optional[List[Dict]] = None,
        on_finding: Optional[Callable] = None
    ) -> AssessmentState:
        """
        Run full Shannon 4-phase assessment with AI enhancement.

        Integrates LLM analysis at each phase for enriched findings.
        """
        executor = create_shannon_executor(
            target=target,
            safe_mode=self.safe_mode,
            on_finding=on_finding
        )

        # Phase 1: Reconnaissance
        await executor.execute_reconnaissance(recon_data)

        # Phase 2: Vulnerability Analysis
        # Enhance with AI analysis
        if vuln_data:
            ai_analysis = await self.analyze_vulnerability({'findings': vuln_data})
            if ai_analysis.success and ai_analysis.data:
                # Enrich vulnerability data with AI insights
                for vuln in vuln_data:
                    vuln['ai_analysis'] = ai_analysis.data

        await executor.execute_vulnerability_analysis(vuln_data)

        # Phase 3: Attack Chain Identification (AI-powered)
        if executor.state.all_findings:
            chains_result = await self.identify_attack_chains(
                [f.to_dict() for f in executor.state.all_findings]
            )
            if chains_result.success and chains_result.data:
                executor.state.attack_surface['ai_attack_chains'] = chains_result.data.get('attack_chains', [])

        # Phase 4: Reporting
        await executor.execute_reporting()

        return executor.state

    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        total_cost = sum(r.cost_usd for r in self.analysis_history)
        total_tokens = sum(r.tokens_used for r in self.analysis_history)

        return {
            'total_analyses': len(self.analysis_history),
            'successful_analyses': sum(1 for r in self.analysis_history if r.success),
            'total_cost_usd': total_cost,
            'total_tokens': total_tokens,
            'repairs_needed': sum(1 for r in self.analysis_history if r.was_repaired),
            'router_stats': self.router.get_stats()
        }


# ========== Convenience Functions ==========

_default_analyzer: Optional[AISecurityAnalyzer] = None


def get_analyzer(priority: Priority = Priority.FREE) -> AISecurityAnalyzer:
    """Get or create default analyzer - ALL FREE FOREVER"""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = AISecurityAnalyzer(priority=priority)
    return _default_analyzer


async def quick_analyze(
    scan_results: Dict[str, Any],
    priority: Priority = Priority.FREE
) -> AIAnalysisResult:
    """Quick vulnerability analysis with FREE providers - ALL FREE FOREVER"""
    analyzer = AISecurityAnalyzer(priority=priority)
    return await analyzer.analyze_vulnerability(scan_results)


async def full_assessment(
    target: str,
    recon_data: Optional[Dict] = None,
    vuln_data: Optional[List[Dict]] = None,
    priority: Priority = Priority.FREE
) -> AssessmentState:
    """Run full AI-enhanced security assessment - ALL FREE FOREVER"""
    analyzer = AISecurityAnalyzer(priority=priority)
    return await analyzer.run_shannon_assessment(target, recon_data, vuln_data)


# ========== Integration with Pentest Commander ==========

class AIEnhancedPentestMixin:
    """
    Mixin to add AI capabilities to PentestCommander - ALL FREE FOREVER.

    Usage:
        class EnhancedCommander(PentestCommander, AIEnhancedPentestMixin):
            pass
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ai_analyzer = AISecurityAnalyzer(priority=Priority.FREE)  # ALL FREE FOREVER

    async def ai_analyze_findings(self, findings: List[Dict]) -> AIAnalysisResult:
        """Analyze all findings with AI"""
        return await self.ai_analyzer.analyze_vulnerability({'findings': findings})

    async def ai_generate_report(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate AI-enhanced report"""
        # Get vulnerability analysis
        vuln_analysis = await self.ai_analyzer.analyze_vulnerability({'findings': findings})

        # Get attack chains
        chains = await self.ai_analyzer.identify_attack_chains(findings)

        # Get remediation plan
        remediation = await self.ai_analyzer.generate_remediation_plan(findings)

        return {
            'vulnerability_analysis': vuln_analysis.data if vuln_analysis.success else None,
            'attack_chains': chains.data.get('attack_chains', []) if chains.success else [],
            'remediation_plan': remediation.data if remediation.success else None,
            'ai_stats': self.ai_analyzer.get_stats()
        }
