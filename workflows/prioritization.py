"""
Tiered Bounty Prioritization System
====================================

Prioritizes findings based on bounty potential.

Learned from: TikTok engagement bounty analysis

Author: DeadMan Toolkit v5.3
"""

import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class BountyTier(Enum):
    """Bounty tier classification"""
    TIER5 = "tier5"  # $75k-$500k+ - Critical: AI/Auth/RCE
    TIER4 = "tier4"  # $25k-$500k - High: SSRF/Upload/Media
    TIER3 = "tier3"  # $5k-$150k - Medium: IDOR/XSS/OAuth
    TIER2 = "tier2"  # $500-$50k - Low: Info Disclosure
    TIER1 = "tier1"  # $0-$500 - Minimal impact


@dataclass
class BountyTierConfig:
    """Configuration for a bounty tier"""
    tier: BountyTier
    min_bounty: int
    max_bounty: int
    categories: List[str]
    priority: int
    description: str


@dataclass
class PrioritizedFinding:
    """A prioritized vulnerability finding"""
    title: str
    category: str
    tier: BountyTier
    estimated_bounty: Tuple[int, int]  # (min, max)
    confidence: float
    evidence: str
    priority_score: float


# Tier configurations
BOUNTY_TIERS = {
    BountyTier.TIER5: BountyTierConfig(
        tier=BountyTier.TIER5,
        min_bounty=75000,
        max_bounty=500000,
        categories=[
            'rce', 'remote_code_execution',
            'ai_ml_bypass', 'model_theft', 'prompt_injection',
            'auth_bypass', 'account_takeover', 'session_hijack',
            'mass_data_breach', 'payment_bypass',
            'supply_chain_attack'
        ],
        priority=1,
        description="Critical impact vulnerabilities - RCE, AI/ML, Auth"
    ),
    BountyTier.TIER4: BountyTierConfig(
        tier=BountyTier.TIER4,
        min_bounty=25000,
        max_bounty=500000,
        categories=[
            'ssrf', 'server_side_request_forgery',
            'file_upload_rce', 'unrestricted_upload',
            'media_processing', 'ffmpeg_exploit',
            'sqli', 'sql_injection',
            'xxe', 'xml_external_entity',
            'deserialization'
        ],
        priority=2,
        description="High impact - SSRF, Upload, SQLi"
    ),
    BountyTier.TIER3: BountyTierConfig(
        tier=BountyTier.TIER3,
        min_bounty=5000,
        max_bounty=150000,
        categories=[
            'idor', 'insecure_direct_object_reference',
            'xss', 'cross_site_scripting', 'stored_xss',
            'oauth_bypass', 'redirect_uri_manipulation',
            'csrf', 'cross_site_request_forgery',
            'broken_access_control',
            'privilege_escalation'
        ],
        priority=3,
        description="Medium impact - IDOR, XSS, OAuth"
    ),
    BountyTier.TIER2: BountyTierConfig(
        tier=BountyTier.TIER2,
        min_bounty=500,
        max_bounty=50000,
        categories=[
            'information_disclosure', 'sensitive_data_exposure',
            'rate_limiting_bypass',
            'reflected_xss', 'self_xss',
            'open_redirect',
            'clickjacking',
            'subdomain_takeover'
        ],
        priority=4,
        description="Lower impact - Info disclosure, Rate limiting"
    ),
    BountyTier.TIER1: BountyTierConfig(
        tier=BountyTier.TIER1,
        min_bounty=0,
        max_bounty=500,
        categories=[
            'best_practice', 'security_header_missing',
            'verbose_error', 'version_disclosure',
            'email_enumeration',
            'low_impact_csrf'
        ],
        priority=5,
        description="Minimal impact - Best practices, headers"
    )
}

# Category aliases for normalization
CATEGORY_ALIASES = {
    'remote code execution': 'rce',
    'command injection': 'rce',
    'server-side request forgery': 'ssrf',
    'sql injection': 'sqli',
    'cross-site scripting': 'xss',
    'insecure direct object reference': 'idor',
    'broken access control': 'idor',
    'cross-site request forgery': 'csrf',
    'xml external entity': 'xxe',
    'authentication bypass': 'auth_bypass',
    'authorization bypass': 'auth_bypass',
    'account takeover': 'account_takeover',
    'prompt injection': 'prompt_injection',
    'llm injection': 'prompt_injection',
    'ai bypass': 'ai_ml_bypass',
    'model extraction': 'model_theft',
    'information disclosure': 'information_disclosure',
    'sensitive data exposure': 'information_disclosure',
    'open redirect': 'open_redirect',
    'url redirect': 'open_redirect'
}


class VulnerabilityPrioritizer:
    """
    Prioritizes vulnerabilities by bounty potential.

    Usage:
        prioritizer = VulnerabilityPrioritizer()

        # Classify a finding
        tier = prioritizer.classify("ssrf", evidence="AWS metadata access")

        # Prioritize multiple findings
        findings = [
            {"title": "SSRF in upload", "category": "ssrf"},
            {"title": "XSS in comments", "category": "xss"},
            {"title": "IDOR on user data", "category": "idor"}
        ]
        prioritized = prioritizer.prioritize_findings(findings)
    """

    def __init__(self, custom_tiers: Optional[Dict] = None):
        self.tiers = custom_tiers or BOUNTY_TIERS
        self.findings: List[PrioritizedFinding] = []

    def normalize_category(self, category: str) -> str:
        """Normalize category name"""
        normalized = category.lower().strip().replace('-', '_').replace(' ', '_')
        return CATEGORY_ALIASES.get(normalized, normalized)

    def classify(self, category: str, evidence: str = "") -> BountyTier:
        """Classify a vulnerability by category"""
        normalized = self.normalize_category(category)

        for tier_config in sorted(self.tiers.values(), key=lambda x: x.priority):
            if normalized in tier_config.categories:
                return tier_config.tier

        # Check for partial matches
        for tier_config in sorted(self.tiers.values(), key=lambda x: x.priority):
            for cat in tier_config.categories:
                if cat in normalized or normalized in cat:
                    return tier_config.tier

        return BountyTier.TIER2  # Default to medium-low

    def estimate_bounty(
        self,
        tier: BountyTier,
        confidence: float = 0.5
    ) -> Tuple[int, int]:
        """Estimate bounty range"""
        config = self.tiers[tier]
        # Adjust range based on confidence
        min_adj = int(config.min_bounty * (0.5 + confidence * 0.5))
        max_adj = int(config.max_bounty * confidence)
        return (min_adj, max_adj)

    def calculate_priority_score(
        self,
        tier: BountyTier,
        confidence: float,
        has_evidence: bool
    ) -> float:
        """Calculate priority score (0-100)"""
        config = self.tiers[tier]
        tier_weight = (6 - config.priority) * 20  # 20-100 based on tier
        confidence_weight = confidence * 30  # 0-30 based on confidence
        evidence_weight = 20 if has_evidence else 0  # 20 for evidence

        return min(100, tier_weight + confidence_weight + evidence_weight)

    def prioritize_finding(
        self,
        title: str,
        category: str,
        evidence: str = "",
        confidence: float = 0.5
    ) -> PrioritizedFinding:
        """Prioritize a single finding"""
        tier = self.classify(category, evidence)
        bounty_range = self.estimate_bounty(tier, confidence)
        priority_score = self.calculate_priority_score(tier, confidence, bool(evidence))

        finding = PrioritizedFinding(
            title=title,
            category=self.normalize_category(category),
            tier=tier,
            estimated_bounty=bounty_range,
            confidence=confidence,
            evidence=evidence,
            priority_score=priority_score
        )

        self.findings.append(finding)
        return finding

    def prioritize_findings(
        self,
        findings: List[Dict]
    ) -> List[PrioritizedFinding]:
        """Prioritize multiple findings"""
        results = []
        for f in findings:
            result = self.prioritize_finding(
                title=f.get('title', 'Unknown'),
                category=f.get('category', 'unknown'),
                evidence=f.get('evidence', ''),
                confidence=f.get('confidence', 0.5)
            )
            results.append(result)

        # Sort by priority score
        return sorted(results, key=lambda x: x.priority_score, reverse=True)

    def get_summary(self) -> Dict:
        """Get prioritization summary"""
        by_tier = {}
        for tier in BountyTier:
            tier_findings = [f for f in self.findings if f.tier == tier]
            if tier_findings:
                by_tier[tier.value] = {
                    'count': len(tier_findings),
                    'total_min_bounty': sum(f.estimated_bounty[0] for f in tier_findings),
                    'total_max_bounty': sum(f.estimated_bounty[1] for f in tier_findings)
                }

        total_min = sum(f.estimated_bounty[0] for f in self.findings)
        total_max = sum(f.estimated_bounty[1] for f in self.findings)

        return {
            'total_findings': len(self.findings),
            'total_estimated_bounty': f"${total_min:,} - ${total_max:,}",
            'by_tier': by_tier,
            'top_5': [
                {'title': f.title, 'tier': f.tier.value, 'score': f.priority_score}
                for f in sorted(self.findings, key=lambda x: x.priority_score, reverse=True)[:5]
            ]
        }

    def export(self, filepath: str):
        """Export prioritized findings"""
        data = {
            'summary': self.get_summary(),
            'findings': [
                {
                    'title': f.title,
                    'category': f.category,
                    'tier': f.tier.value,
                    'estimated_bounty_min': f.estimated_bounty[0],
                    'estimated_bounty_max': f.estimated_bounty[1],
                    'confidence': f.confidence,
                    'priority_score': f.priority_score,
                    'has_evidence': bool(f.evidence)
                }
                for f in sorted(self.findings, key=lambda x: x.priority_score, reverse=True)
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


def quick_prioritize(findings: List[Dict]) -> List[Dict]:
    """Quick prioritization function"""
    prioritizer = VulnerabilityPrioritizer()
    results = prioritizer.prioritize_findings(findings)

    return [
        {
            'title': f.title,
            'tier': f.tier.value,
            'bounty': f"${f.estimated_bounty[0]:,} - ${f.estimated_bounty[1]:,}",
            'score': f.priority_score
        }
        for f in results
    ]
