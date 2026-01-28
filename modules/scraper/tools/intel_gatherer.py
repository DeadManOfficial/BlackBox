"""
Security Intelligence Gatherer - Threat Research Aggregation
=============================================================

Aggregates publicly available security intelligence from:
- CVE databases (NVD, MITRE)
- Security advisories (GitHub, vendor)
- Exploit databases (Exploit-DB, PacketStorm)
- Bug bounty writeups (HackerOne, Bugcrowd)
- Security research papers
- Vulnerability disclosure feeds

For authorized security research and defensive purposes only.

Author: DeadManOfficial
Version: 1.0.0
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import aiohttp
from urllib.parse import urljoin, quote


class IntelSource(Enum):
    """Intelligence source types"""
    CVE_NVD = "nvd"
    CVE_MITRE = "mitre"
    EXPLOIT_DB = "exploitdb"
    GITHUB_ADVISORY = "github_advisory"
    HACKERONE = "hackerone_hacktivity"
    SECURITY_PAPERS = "papers"
    NUCLEI_TEMPLATES = "nuclei"
    OSINT = "osint"


@dataclass
class VulnerabilityIntel:
    """Vulnerability intelligence record"""
    id: str
    source: IntelSource
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    cwe_ids: List[str] = field(default_factory=list)
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploit_available: bool = False
    exploit_url: Optional[str] = None
    published_date: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'source': self.source.value if isinstance(self.source, IntelSource) else str(self.source),
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cvss_score': self.cvss_score,
            'cwe_ids': self.cwe_ids,
            'affected_products': self.affected_products,
            'references': self.references,
            'exploit_available': self.exploit_available,
            'exploit_url': self.exploit_url,
            'published_date': self.published_date,
            'tags': self.tags
        }


@dataclass
class TechniqueIntel:
    """Attack technique intelligence"""
    id: str
    name: str
    category: str
    description: str
    detection_methods: List[str] = field(default_factory=list)
    mitigation: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'detection_methods': self.detection_methods,
            'mitigation': self.mitigation,
            'examples': self.examples,
            'references': self.references
        }


class CVEIntelligence:
    """
    Gather CVE intelligence from NVD and MITRE.
    """

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MITRE_CVE_API = "https://cveawg.mitre.org/api/cve"

    def __init__(self, nvd_api_key: str = None):
        self.nvd_api_key = nvd_api_key

    async def search_cves(
        self,
        keyword: str = None,
        cpe: str = None,
        severity: str = None,
        days_back: int = 30
    ) -> List[VulnerabilityIntel]:
        """
        Search NVD for CVEs matching criteria.
        """
        params = {}

        if keyword:
            params['keywordSearch'] = keyword

        if cpe:
            params['cpeName'] = cpe

        if severity:
            params['cvssV3Severity'] = severity.upper()

        # Date range
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
        params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')

        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.NVD_API,
                    params=params,
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return self._parse_nvd_response(data)
        except Exception as e:
            print(f"CVE search error: {e}")

        return []

    def _parse_nvd_response(self, data: Dict) -> List[VulnerabilityIntel]:
        """Parse NVD API response into VulnerabilityIntel objects"""
        results = []

        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})

            # Extract CVSS score
            cvss_score = None
            severity = 'UNKNOWN'
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')

            # Extract CWE IDs
            cwe_ids = []
            for weakness in cve.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('value', '').startswith('CWE-'):
                        cwe_ids.append(desc['value'])

            # Extract references
            references = [
                ref.get('url') for ref in cve.get('references', [])
                if ref.get('url')
            ]

            # Check for exploit availability
            exploit_available = any(
                'exploit' in ref.get('url', '').lower() or
                'poc' in ref.get('url', '').lower()
                for ref in cve.get('references', [])
            )

            results.append(VulnerabilityIntel(
                id=cve.get('id', ''),
                source=IntelSource.CVE_NVD,
                title=cve.get('id', ''),
                description=cve.get('descriptions', [{}])[0].get('value', ''),
                severity=severity,
                cvss_score=cvss_score,
                cwe_ids=cwe_ids,
                references=references[:10],  # Limit references
                exploit_available=exploit_available,
                published_date=cve.get('published')
            ))

        return results

    async def get_cve_details(self, cve_id: str) -> Optional[VulnerabilityIntel]:
        """Get detailed information about a specific CVE"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.NVD_API}?cveId={cve_id}"
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = self._parse_nvd_response(data)
                        return results[0] if results else None
        except Exception:
            pass
        return None

    async def search(
        self,
        query: str = None,
        keyword: str = None,
        cpe: str = None,
        cvss_min: float = None,
        published_after: str = None,
        limit: int = 20
    ) -> List[VulnerabilityIntel]:
        """
        Unified search method (alias for search_cves with additional params).
        Bridge-compatible interface.
        """
        # Use query or keyword for keyword search
        search_keyword = keyword or query

        # Map cvss_min to severity if provided
        severity = None
        if cvss_min:
            if cvss_min >= 9.0:
                severity = 'CRITICAL'
            elif cvss_min >= 7.0:
                severity = 'HIGH'
            elif cvss_min >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'

        results = await self.search_cves(
            keyword=search_keyword,
            cpe=cpe,
            severity=severity,
            days_back=365  # Default to 1 year
        )
        return results[:limit]


class ExploitDBIntelligence:
    """
    Search Exploit-DB for public exploits.
    """

    EXPLOITDB_SEARCH = "https://www.exploit-db.com/search"

    async def search_exploits(
        self,
        query: str,
        exploit_type: str = None,
        platform: str = None
    ) -> List[VulnerabilityIntel]:
        """
        Search Exploit-DB for exploits.

        Note: Exploit-DB doesn't have a public API, so this uses
        web scraping with proper rate limiting.
        """
        # For ethical reasons, we'll use their Google dorking approach
        # or rely on the downloaded CSV database
        results = []

        # Using GitHub mirror of exploit-db which is publicly accessible
        github_api = "https://api.github.com/search/code"
        params = {
            'q': f'{query} repo:offensive-security/exploitdb',
            'per_page': 10
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    github_api,
                    params=params,
                    headers={'Accept': 'application/vnd.github.v3+json'}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('items', []):
                            results.append(VulnerabilityIntel(
                                id=item.get('sha', '')[:8],
                                source=IntelSource.EXPLOIT_DB,
                                title=item.get('name', ''),
                                description=f"Exploit file: {item.get('path', '')}",
                                severity='UNKNOWN',
                                exploit_available=True,
                                exploit_url=item.get('html_url'),
                                references=[item.get('html_url')]
                            ))
        except Exception as e:
            print(f"Exploit search error: {e}")

        return results

    async def search(
        self,
        query: str,
        platform: str = None,
        exploit_type: str = None,
        limit: int = 20
    ) -> List[VulnerabilityIntel]:
        """Unified search method (alias for search_exploits). Bridge-compatible."""
        results = await self.search_exploits(query, exploit_type=exploit_type, platform=platform)
        return results[:limit]


class GitHubAdvisoryIntelligence:
    """
    Search GitHub Security Advisories.
    """

    GITHUB_ADVISORY_API = "https://api.github.com/advisories"

    def __init__(self, github_token: str = None):
        self.github_token = github_token

    async def search_advisories(
        self,
        ecosystem: str = None,
        severity: str = None,
        keyword: str = None
    ) -> List[VulnerabilityIntel]:
        """Search GitHub Security Advisory Database"""
        headers = {'Accept': 'application/vnd.github+json'}
        if self.github_token:
            headers['Authorization'] = f'Bearer {self.github_token}'

        params = {'per_page': 50}
        if ecosystem:
            params['ecosystem'] = ecosystem
        if severity:
            params['severity'] = severity

        results = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.GITHUB_ADVISORY_API,
                    params=params,
                    headers=headers
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for adv in data:
                            # Filter by keyword if provided
                            if keyword:
                                text = f"{adv.get('summary', '')} {adv.get('description', '')}"
                                if keyword.lower() not in text.lower():
                                    continue

                            results.append(VulnerabilityIntel(
                                id=adv.get('ghsa_id', ''),
                                source=IntelSource.GITHUB_ADVISORY,
                                title=adv.get('summary', ''),
                                description=adv.get('description', ''),
                                severity=adv.get('severity', 'UNKNOWN').upper(),
                                cvss_score=adv.get('cvss', {}).get('score'),
                                cwe_ids=adv.get('cwe_ids', []),
                                references=[adv.get('html_url')],
                                published_date=adv.get('published_at')
                            ))
        except Exception as e:
            print(f"GitHub advisory search error: {e}")

        return results

    async def search(
        self,
        ecosystem: str = None,
        severity: str = None,
        package: str = None,
        limit: int = 20
    ) -> List[VulnerabilityIntel]:
        """Unified search method (alias for search_advisories). Bridge-compatible."""
        results = await self.search_advisories(ecosystem=ecosystem, severity=severity, keyword=package)
        return results[:limit]


class NucleiTemplateIntelligence:
    """
    Search and analyze Nuclei templates for vulnerability patterns.
    """

    NUCLEI_TEMPLATES_REPO = "https://api.github.com/repos/projectdiscovery/nuclei-templates"

    async def search_templates(
        self,
        query: str,
        severity: str = None,
        tags: List[str] = None
    ) -> List[Dict[str, Any]]:
        """Search Nuclei templates repository"""
        results = []

        # Search via GitHub code search
        search_query = f'{query} repo:projectdiscovery/nuclei-templates'
        if severity:
            search_query += f' severity: {severity}'
        if tags:
            search_query += ' ' + ' '.join(tags)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.github.com/search/code',
                    params={'q': search_query, 'per_page': 20}
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('items', []):
                            results.append({
                                'name': item.get('name'),
                                'path': item.get('path'),
                                'url': item.get('html_url'),
                                'repository': 'nuclei-templates'
                            })
        except Exception as e:
            print(f"Nuclei template search error: {e}")

        return results

    async def get_template_content(self, template_path: str) -> Optional[str]:
        """Get raw content of a Nuclei template"""
        raw_url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{template_path}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(raw_url) as resp:
                    if resp.status == 200:
                        return await resp.text()
        except Exception:
            pass
        return None

    async def search(
        self,
        query: str = None,
        severity: str = None,
        tags: List[str] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Unified search method (alias for search_templates). Bridge-compatible."""
        results = await self.search_templates(query or '', severity=severity, tags=tags)
        return results[:limit]


class BugBountyIntelligence:
    """
    Gather intelligence from public bug bounty disclosures.
    """

    HACKERONE_HACKTIVITY = "https://hackerone.com/hacktivity"

    async def get_recent_disclosures(
        self,
        program: str = None,
        severity: str = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get recent public bug bounty disclosures.

        Note: This uses publicly available data only.
        """
        # HackerOne's public hacktivity doesn't have a direct API
        # We'll aggregate from publicly shared reports

        results = []

        # Search for writeups on GitHub
        search_query = 'bug bounty writeup'
        if program:
            search_query += f' {program}'

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://api.github.com/search/repositories',
                    params={
                        'q': search_query,
                        'sort': 'updated',
                        'per_page': limit
                    }
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for repo in data.get('items', []):
                            results.append({
                                'title': repo.get('name'),
                                'description': repo.get('description'),
                                'url': repo.get('html_url'),
                                'updated': repo.get('updated_at'),
                                'stars': repo.get('stargazers_count')
                            })
        except Exception as e:
            print(f"Bug bounty intel error: {e}")

        return results

    async def search(
        self,
        query: str = None,
        platform: str = None,
        vulnerability_type: str = None,
        min_bounty: int = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Unified search method (alias for get_recent_disclosures). Bridge-compatible."""
        results = await self.get_recent_disclosures(program=query, limit=limit)
        return results


class AttackTechniqueDatabase:
    """
    Database of attack techniques mapped to MITRE ATT&CK.
    """

    MITRE_ATTACK_API = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    def __init__(self):
        self.techniques = {}
        self.loaded = False

    async def load_techniques(self):
        """Load MITRE ATT&CK techniques"""
        if self.loaded:
            return

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.MITRE_ATTACK_API) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for obj in data.get('objects', []):
                            if obj.get('type') == 'attack-pattern':
                                tech_id = None
                                for ref in obj.get('external_references', []):
                                    if ref.get('source_name') == 'mitre-attack':
                                        tech_id = ref.get('external_id')
                                        break

                                if tech_id:
                                    self.techniques[tech_id] = TechniqueIntel(
                                        id=tech_id,
                                        name=obj.get('name', ''),
                                        category=obj.get('x_mitre_tactics', ['Unknown'])[0] if obj.get('x_mitre_tactics') else 'Unknown',
                                        description=obj.get('description', ''),
                                        detection_methods=[d.get('description', '') for d in obj.get('x_mitre_detection', [])],
                                        mitigation=[],
                                        references=[ref.get('url') for ref in obj.get('external_references', []) if ref.get('url')]
                                    )
                        self.loaded = True
        except Exception as e:
            print(f"ATT&CK load error: {e}")

    async def search_techniques(self, query: str) -> List[TechniqueIntel]:
        """Search for attack techniques"""
        await self.load_techniques()

        results = []
        query_lower = query.lower()

        for tech_id, technique in self.techniques.items():
            if (query_lower in technique.name.lower() or
                query_lower in technique.description.lower() or
                query_lower in tech_id.lower()):
                results.append(technique)

        return results[:20]

    async def get_technique(self, technique_id: str) -> Optional[TechniqueIntel]:
        """Get a specific technique by ID"""
        await self.load_techniques()
        return self.techniques.get(technique_id)

    async def search(
        self,
        query: str = None,
        tactic: str = None,
        platform: str = None,
        limit: int = 20
    ) -> List[TechniqueIntel]:
        """Unified search method. Bridge-compatible."""
        await self.load_techniques()

        results = []
        query_lower = (query or '').lower()
        tactic_lower = (tactic or '').lower()

        for tech_id, technique in self.techniques.items():
            # Check query match
            query_match = not query or (
                query_lower in technique.name.lower() or
                query_lower in technique.description.lower() or
                query_lower in tech_id.lower()
            )

            # Check tactic match
            tactic_match = not tactic or tactic_lower in technique.category.lower()

            if query_match and tactic_match:
                results.append(technique)

        return results[:limit]


class SecurityIntelAggregator:
    """
    Aggregate security intelligence from multiple sources.
    """

    def __init__(
        self,
        nvd_api_key: str = None,
        github_token: str = None
    ):
        self.cve_intel = CVEIntelligence(nvd_api_key)
        self.exploit_intel = ExploitDBIntelligence()
        self.github_intel = GitHubAdvisoryIntelligence(github_token)
        self.nuclei_intel = NucleiTemplateIntelligence()
        self.bounty_intel = BugBountyIntelligence()
        self.attack_db = AttackTechniqueDatabase()

    async def comprehensive_search(
        self,
        query: str,
        sources: List[IntelSource] = None
    ) -> Dict[str, List]:
        """
        Search across all intelligence sources.
        """
        if sources is None:
            sources = list(IntelSource)

        results = {
            'query': query,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }

        tasks = []

        if IntelSource.CVE_NVD in sources:
            tasks.append(('cve', self.cve_intel.search_cves(keyword=query)))

        if IntelSource.GITHUB_ADVISORY in sources:
            tasks.append(('github', self.github_intel.search_advisories(keyword=query)))

        if IntelSource.EXPLOIT_DB in sources:
            tasks.append(('exploits', self.exploit_intel.search_exploits(query)))

        if IntelSource.NUCLEI_TEMPLATES in sources:
            tasks.append(('nuclei', self.nuclei_intel.search_templates(query)))

        if IntelSource.HACKERONE in sources:
            tasks.append(('bounty', self.bounty_intel.get_recent_disclosures(program=query)))

        # Execute all searches concurrently
        for name, coro in tasks:
            try:
                results['sources'][name] = await coro
            except Exception as e:
                results['sources'][name] = {'error': str(e)}

        return results

    async def get_vulnerability_context(
        self,
        technology: str,
        version: str = None
    ) -> Dict[str, Any]:
        """
        Get comprehensive vulnerability context for a technology.
        """
        search_term = technology
        if version:
            search_term = f"{technology} {version}"

        # Search CVEs
        cves = await self.cve_intel.search_cves(keyword=search_term, days_back=365)

        # Search for related attack techniques
        techniques = await self.attack_db.search_techniques(technology)

        # Get Nuclei templates
        templates = await self.nuclei_intel.search_templates(technology)

        # Analyze severity distribution
        severity_dist = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for cve in cves:
            if cve.severity in severity_dist:
                severity_dist[cve.severity] += 1

        return {
            'technology': technology,
            'version': version,
            'total_cves': len(cves),
            'severity_distribution': severity_dist,
            'recent_cves': [
                {
                    'id': c.id,
                    'severity': c.severity,
                    'cvss': c.cvss_score,
                    'exploit_available': c.exploit_available
                }
                for c in cves[:10]
            ],
            'related_techniques': [
                {'id': t.id, 'name': t.name}
                for t in techniques[:5]
            ],
            'nuclei_templates': templates[:10],
            'risk_assessment': self._assess_risk(cves, techniques)
        }

    def _assess_risk(
        self,
        cves: List[VulnerabilityIntel],
        techniques: List[TechniqueIntel]
    ) -> Dict[str, Any]:
        """Assess overall risk based on intelligence"""
        critical_count = len([c for c in cves if c.severity == 'CRITICAL'])
        high_count = len([c for c in cves if c.severity == 'HIGH'])
        exploit_count = len([c for c in cves if c.exploit_available])

        risk_score = (
            critical_count * 10 +
            high_count * 5 +
            exploit_count * 3 +
            len(techniques) * 2
        )

        if risk_score > 50:
            risk_level = 'CRITICAL'
        elif risk_score > 30:
            risk_level = 'HIGH'
        elif risk_score > 15:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'

        return {
            'risk_level': risk_level,
            'risk_score': min(risk_score, 100),
            'factors': {
                'critical_vulns': critical_count,
                'high_vulns': high_count,
                'exploits_available': exploit_count,
                'attack_techniques': len(techniques)
            }
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def quick_intel_search(query: str) -> Dict[str, Any]:
    """Quick intelligence search across all sources"""
    aggregator = SecurityIntelAggregator()
    return await aggregator.comprehensive_search(query)


async def tech_vulnerability_report(technology: str, version: str = None) -> Dict[str, Any]:
    """Generate vulnerability report for a technology"""
    aggregator = SecurityIntelAggregator()
    return await aggregator.get_vulnerability_context(technology, version)


# Example usage
if __name__ == "__main__":
    async def main():
        # Search for Next.js vulnerabilities
        results = await tech_vulnerability_report("Next.js", "14")
        print(json.dumps(results, indent=2, default=str))

    asyncio.run(main())
