"""
BlackBox Intel - Security Intelligence Tools
=============================================

9 intelligence gathering tools:
- intel_cve_search: Search NVD for CVEs
- intel_exploit_search: Search Exploit-DB
- intel_github_advisory: GitHub Security Advisories
- intel_nuclei_templates: Find relevant Nuclei templates
- intel_bugbounty: Bug bounty program intelligence
- intel_mitre_attack: MITRE ATT&CK mapping
- intel_comprehensive: Search all sources
- intel_tech_vulns: Technology-specific vulnerabilities
- intel_sources: List available sources
"""

import json
import urllib.request
import urllib.parse
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta


def intel_cve_search(
    keyword: Optional[str] = None,
    cpe: Optional[str] = None,
    cvss_min: Optional[float] = None,
    published_after: Optional[str] = None,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Search NVD for CVEs.

    Args:
        keyword: Search keyword
        cpe: CPE string (e.g., cpe:2.3:a:apache:*)
        cvss_min: Minimum CVSS v3 score
        published_after: ISO date (e.g., 2024-01-01)
        limit: Max results

    Returns:
        CVE search results
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"resultsPerPage": min(limit, 100)}

    if keyword:
        params["keywordSearch"] = keyword
    if cpe:
        params["cpeName"] = cpe
    if cvss_min:
        params["cvssV3Severity"] = "HIGH" if cvss_min >= 7.0 else "MEDIUM" if cvss_min >= 4.0 else "LOW"
    if published_after:
        params["pubStartDate"] = f"{published_after}T00:00:00.000"

    url = f"{base_url}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "BlackBox-Intel/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())

        cves = []
        for vuln in data.get("vulnerabilities", [])[:limit]:
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            cvss_data = {}

            # Extract CVSS v3 if available
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})

            cves.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", "")[:300],
                "cvss_score": cvss_data.get("baseScore"),
                "cvss_severity": cvss_data.get("baseSeverity"),
                "published": cve.get("published"),
                "references": [ref.get("url") for ref in cve.get("references", [])[:3]]
            })

        return {
            "query": params,
            "total_results": data.get("totalResults", 0),
            "cves": cves
        }

    except Exception as e:
        return {"error": str(e)}


def intel_exploit_search(
    query: str,
    exploit_type: Optional[str] = None,
    platform: Optional[str] = None,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Search Exploit-DB for exploits.

    Args:
        query: Search query
        exploit_type: Type filter (remote, local, webapps, dos)
        platform: Platform filter (windows, linux, multiple)
        limit: Max results

    Note: Uses exploit-db.com search (no API key required)
    """
    # Exploit-DB doesn't have a public API, so we return structured search guidance
    search_url = f"https://www.exploit-db.com/search?q={urllib.parse.quote(query)}"

    if exploit_type:
        search_url += f"&type={exploit_type}"
    if platform:
        search_url += f"&platform={platform}"

    return {
        "query": query,
        "search_url": search_url,
        "manual_search_required": True,
        "alternative_sources": [
            f"https://github.com/search?q={urllib.parse.quote(query)}+exploit&type=repositories",
            f"https://packetstormsecurity.com/search/?q={urllib.parse.quote(query)}",
        ],
        "note": "Exploit-DB requires manual search or use nuclei_scan for automated testing"
    }


def intel_github_advisory(
    package: Optional[str] = None,
    ecosystem: str = "npm",
    severity: Optional[str] = None,
    limit: int = 20
) -> Dict[str, Any]:
    """
    Search GitHub Security Advisories.

    Args:
        package: Package name
        ecosystem: Package ecosystem (npm, pip, maven, etc.)
        severity: Severity filter
        limit: Max results
    """
    # GitHub Advisory Database API
    base_url = "https://api.github.com/advisories"
    params = {"per_page": min(limit, 100)}

    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity

    url = f"{base_url}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "BlackBox-Intel/1.0"
        })
        with urllib.request.urlopen(req, timeout=30) as response:
            advisories = json.loads(response.read().decode())

        results = []
        for adv in advisories[:limit]:
            # Filter by package if specified
            if package:
                affected = adv.get("vulnerabilities", [])
                if not any(package.lower() in str(v.get("package", {}).get("name", "")).lower() for v in affected):
                    continue

            results.append({
                "ghsa_id": adv.get("ghsa_id"),
                "cve_id": adv.get("cve_id"),
                "summary": adv.get("summary"),
                "severity": adv.get("severity"),
                "published": adv.get("published_at"),
                "url": adv.get("html_url"),
                "packages": [v.get("package", {}).get("name") for v in adv.get("vulnerabilities", [])]
            })

        return {
            "ecosystem": ecosystem,
            "package": package,
            "advisories": results,
            "total": len(results)
        }

    except Exception as e:
        return {"error": str(e)}


def intel_mitre_attack(
    technique_id: Optional[str] = None,
    tactic: Optional[str] = None,
    search: Optional[str] = None
) -> Dict[str, Any]:
    """
    Query MITRE ATT&CK framework.

    Args:
        technique_id: Specific technique (e.g., T1190)
        tactic: Tactic filter (initial-access, execution, etc.)
        search: Keyword search
    """
    # MITRE ATT&CK tactics mapping
    tactics = {
        "reconnaissance": "TA0043",
        "resource-development": "TA0042",
        "initial-access": "TA0001",
        "execution": "TA0002",
        "persistence": "TA0003",
        "privilege-escalation": "TA0004",
        "defense-evasion": "TA0005",
        "credential-access": "TA0006",
        "discovery": "TA0007",
        "lateral-movement": "TA0008",
        "collection": "TA0009",
        "command-and-control": "TA0011",
        "exfiltration": "TA0010",
        "impact": "TA0040"
    }

    # Common technique mappings
    technique_db = {
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        "T1078": {"name": "Valid Accounts", "tactic": "initial-access"},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
        "T1552": {"name": "Unsecured Credentials", "tactic": "credential-access"},
        "T1046": {"name": "Network Service Discovery", "tactic": "discovery"},
        "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
        "T1005": {"name": "Data from Local System", "tactic": "collection"},
    }

    if technique_id:
        tech = technique_db.get(technique_id, {})
        return {
            "technique_id": technique_id,
            "name": tech.get("name", "Unknown"),
            "tactic": tech.get("tactic", "Unknown"),
            "url": f"https://attack.mitre.org/techniques/{technique_id}/",
            "mitigations_url": f"https://attack.mitre.org/techniques/{technique_id}/#mitigations"
        }

    if tactic:
        tactic_id = tactics.get(tactic, "")
        techniques = [
            {"id": tid, **info}
            for tid, info in technique_db.items()
            if info.get("tactic") == tactic
        ]
        return {
            "tactic": tactic,
            "tactic_id": tactic_id,
            "techniques": techniques,
            "url": f"https://attack.mitre.org/tactics/{tactic_id}/"
        }

    return {
        "tactics": tactics,
        "techniques_sample": list(technique_db.items())[:5],
        "reference": "https://attack.mitre.org/"
    }


def intel_comprehensive(
    query: str,
    sources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Search across all intelligence sources.

    Args:
        query: Search query
        sources: Sources to search (NVD, GITHUB_ADVISORY, MITRE_ATTACK)
    """
    if sources is None:
        sources = ["NVD", "GITHUB_ADVISORY", "MITRE_ATTACK"]

    results = {"query": query, "sources": {}}

    if "NVD" in sources:
        results["sources"]["NVD"] = intel_cve_search(keyword=query, limit=5)

    if "GITHUB_ADVISORY" in sources:
        results["sources"]["GITHUB_ADVISORY"] = intel_github_advisory(package=query, limit=5)

    if "MITRE_ATTACK" in sources:
        results["sources"]["MITRE_ATTACK"] = intel_mitre_attack(search=query)

    return results


def intel_tech_vulns(
    technology: str,
    version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Get vulnerabilities for a specific technology.

    Args:
        technology: Technology name (e.g., apache, nginx, nodejs)
        version: Specific version
    """
    # Map common tech names to CPE prefixes
    cpe_mappings = {
        "apache": "cpe:2.3:a:apache:http_server",
        "nginx": "cpe:2.3:a:nginx:nginx",
        "nodejs": "cpe:2.3:a:nodejs:node.js",
        "wordpress": "cpe:2.3:a:wordpress:wordpress",
        "drupal": "cpe:2.3:a:drupal:drupal",
        "joomla": "cpe:2.3:a:joomla:joomla",
        "tomcat": "cpe:2.3:a:apache:tomcat",
        "mysql": "cpe:2.3:a:mysql:mysql",
        "postgresql": "cpe:2.3:a:postgresql:postgresql",
        "redis": "cpe:2.3:a:redis:redis",
        "mongodb": "cpe:2.3:a:mongodb:mongodb",
        "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    }

    cpe = cpe_mappings.get(technology.lower(), f"cpe:2.3:a:*:{technology.lower()}")
    if version:
        cpe += f":{version}"

    return intel_cve_search(cpe=cpe, limit=20)


def intel_sources() -> Dict[str, Any]:
    """List all available intelligence sources."""
    return {
        "sources": [
            {
                "name": "NVD",
                "description": "NIST National Vulnerability Database",
                "url": "https://nvd.nist.gov/",
                "tool": "intel_cve_search"
            },
            {
                "name": "GitHub Advisory",
                "description": "GitHub Security Advisories",
                "url": "https://github.com/advisories",
                "tool": "intel_github_advisory"
            },
            {
                "name": "MITRE ATT&CK",
                "description": "Adversary Tactics & Techniques",
                "url": "https://attack.mitre.org/",
                "tool": "intel_mitre_attack"
            },
            {
                "name": "Exploit-DB",
                "description": "Exploit Database",
                "url": "https://www.exploit-db.com/",
                "tool": "intel_exploit_search"
            }
        ]
    }


__all__ = [
    "intel_cve_search",
    "intel_exploit_search",
    "intel_github_advisory",
    "intel_mitre_attack",
    "intel_comprehensive",
    "intel_tech_vulns",
    "intel_sources"
]
