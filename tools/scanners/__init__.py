"""
BlackBox Scanners - Vulnerability Detection Tools
=================================================

Tools:
- nuclei_scan: Run Nuclei vulnerability scanner
- js_analyze: Analyze JavaScript for secrets/endpoints
- secret_scan_*: Detect exposed secrets (git, files, URLs)
"""

import subprocess
import json
import re
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
import hashlib
import math

# ============================================
# SECRET PATTERNS (50+ detection patterns)
# ============================================
SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
    "github_token": r"ghp_[A-Za-z0-9]{36}",
    "github_oauth": r"gho_[A-Za-z0-9]{36}",
    "gitlab_token": r"glpat-[A-Za-z0-9\-]{20}",
    "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
    "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
    "stripe_live": r"sk_live_[A-Za-z0-9]{24,}",
    "stripe_test": r"sk_test_[A-Za-z0-9]{24,}",
    "google_api": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "twilio_sid": r"AC[a-z0-9]{32}",
    "twilio_token": r"SK[a-z0-9]{32}",
    "sendgrid": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "mailchimp": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "private_key": r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "ssh_key": r"ssh-(rsa|ed25519|dss) AAAA[0-9A-Za-z+/]+",
    "heroku_api": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "postgres_uri": r"postgres(ql)?://[^:]+:[^@]+@[^/]+/\w+",
    "mongodb_uri": r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+",
    "redis_uri": r"redis://[^:]+:[^@]+@[^:]+:\d+",
    "basic_auth": r"[Aa]uthorization:\s*[Bb]asic\s+[A-Za-z0-9+/=]+",
    "bearer_token": r"[Bb]earer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "api_key_generic": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{20,}['\"]",
    "password_field": r"['\"]?password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
    "secret_field": r"['\"]?secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]{16,}['\"]",
    "anthropic_key": r"sk-ant-[A-Za-z0-9_-]{40,}",
    "openai_key": r"sk-[A-Za-z0-9]{48}",
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "pypi_token": r"pypi-[A-Za-z0-9_-]{50,}",
    "discord_token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
    "discord_webhook": r"https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "telegram_token": r"[0-9]+:AA[A-Za-z0-9_-]{33}",
    "dropbox_token": r"sl\.[A-Za-z0-9_-]{130,}",
    "digitalocean": r"dop_v1_[a-f0-9]{64}",
    "vercel_token": r"[A-Za-z0-9]{24}",
    "netlify_token": r"[A-Za-z0-9_-]{40,}",
    "supabase_key": r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "cloudflare_key": r"[A-Za-z0-9]{37}",
    "azure_key": r"[A-Za-z0-9+/]{86}==",
    "gcp_service_account": r'"type":\s*"service_account"',
}


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def secret_scan_files(
    path: str,
    recursive: bool = True,
    entropy_threshold: float = 4.5,
    include_patterns: Optional[List[str]] = None,
    exclude_patterns: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Scan directory for secrets.

    Args:
        path: Directory to scan
        recursive: Scan subdirectories
        entropy_threshold: Min entropy for high-entropy detection
        include_patterns: Glob patterns to include
        exclude_patterns: Patterns to exclude

    Returns:
        Dict with findings, stats, and recommendations
    """
    if exclude_patterns is None:
        exclude_patterns = ["node_modules", ".git", "__pycache__", "*.min.js", "*.map"]

    findings = []
    files_scanned = 0

    scan_path = Path(path).expanduser()
    if not scan_path.exists():
        return {"error": f"Path not found: {path}"}

    pattern = "**/*" if recursive else "*"

    for file_path in scan_path.glob(pattern):
        if not file_path.is_file():
            continue

        # Skip excluded patterns
        skip = False
        for excl in exclude_patterns:
            if excl in str(file_path):
                skip = True
                break
        if skip:
            continue

        try:
            content = file_path.read_text(errors='ignore')
            files_scanned += 1

            # Check each pattern
            for pattern_name, pattern_regex in SECRET_PATTERNS.items():
                matches = re.findall(pattern_regex, content)
                for match in matches:
                    # Get line number
                    for i, line in enumerate(content.split('\n'), 1):
                        if match in line:
                            findings.append({
                                "type": pattern_name,
                                "file": str(file_path),
                                "line": i,
                                "match": match[:50] + "..." if len(match) > 50 else match,
                                "entropy": calculate_entropy(match),
                                "severity": "HIGH" if "key" in pattern_name.lower() or "token" in pattern_name.lower() else "MEDIUM"
                            })
                            break

            # High entropy detection
            for i, line in enumerate(content.split('\n'), 1):
                # Look for assignment patterns with high entropy values
                assign_match = re.search(r'[=:]\s*["\']([A-Za-z0-9+/=_-]{20,})["\']', line)
                if assign_match:
                    value = assign_match.group(1)
                    entropy = calculate_entropy(value)
                    if entropy >= entropy_threshold:
                        findings.append({
                            "type": "high_entropy",
                            "file": str(file_path),
                            "line": i,
                            "match": value[:50] + "..." if len(value) > 50 else value,
                            "entropy": entropy,
                            "severity": "MEDIUM"
                        })
        except Exception as e:
            continue

    return {
        "findings": findings,
        "stats": {
            "files_scanned": files_scanned,
            "secrets_found": len(findings),
            "high_severity": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium_severity": len([f for f in findings if f["severity"] == "MEDIUM"])
        },
        "recommendations": [
            "Rotate any exposed credentials immediately",
            "Add secrets to .gitignore",
            "Use environment variables or secret managers",
            "Enable secret scanning in CI/CD pipeline"
        ]
    }


def secret_scan_url(url: str, entropy_threshold: float = 4.5) -> Dict[str, Any]:
    """Scan URL content for secrets (useful for JS bundles)."""
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        return {"error": str(e)}

    findings = []

    for pattern_name, pattern_regex in SECRET_PATTERNS.items():
        matches = re.findall(pattern_regex, content)
        for match in matches:
            findings.append({
                "type": pattern_name,
                "url": url,
                "match": match[:50] + "..." if len(match) > 50 else match,
                "entropy": calculate_entropy(match),
                "severity": "HIGH" if "key" in pattern_name.lower() else "MEDIUM"
            })

    return {
        "findings": findings,
        "url": url,
        "content_length": len(content),
        "secrets_found": len(findings)
    }


def js_analyze(url: str = None, content: str = None, source: str = None) -> Dict[str, Any]:
    """
    Analyze JavaScript for security issues.

    Detects:
    - Hardcoded secrets/API keys
    - API endpoints
    - Debug/development code
    - Source map references
    - Sensitive function calls
    """
    if url:
        import urllib.request
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
                source = url
        except Exception as e:
            return {"error": str(e)}

    if not content:
        return {"error": "No content provided"}

    findings = {
        "secrets": [],
        "endpoints": [],
        "debug_code": [],
        "source_maps": [],
        "sensitive_functions": []
    }

    # Find secrets
    for pattern_name, pattern_regex in SECRET_PATTERNS.items():
        matches = re.findall(pattern_regex, content)
        for match in matches:
            findings["secrets"].append({
                "type": pattern_name,
                "value": match[:50] + "..." if len(match) > 50 else match
            })

    # Find API endpoints
    endpoint_patterns = [
        r'["\']/(api|v[0-9]+|graphql)/[^"\']+["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\(["\']([^"\']+)["\']',
        r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
    ]
    for pattern in endpoint_patterns:
        matches = re.findall(pattern, content)
        for match in matches:
            if isinstance(match, tuple):
                match = match[-1]
            if match and not match.startswith('data:'):
                findings["endpoints"].append(match)

    # Remove duplicates
    findings["endpoints"] = list(set(findings["endpoints"]))

    # Find debug code
    debug_patterns = [
        r'console\.(log|debug|warn|error)\([^)]+\)',
        r'debugger;',
        r'//\s*TODO',
        r'//\s*FIXME',
        r'//\s*HACK',
    ]
    for pattern in debug_patterns:
        matches = re.findall(pattern, content)
        findings["debug_code"].extend(matches[:5])  # Limit to 5

    # Find source maps
    sourcemap_pattern = r'//[#@]\s*sourceMappingURL=([^\s]+)'
    matches = re.findall(sourcemap_pattern, content)
    findings["source_maps"].extend(matches)

    # Find sensitive function calls
    sensitive_patterns = [
        r'eval\([^)]+\)',
        r'document\.write\([^)]+\)',
        r'innerHTML\s*=',
        r'\.html\([^)]+\)',
        r'dangerouslySetInnerHTML',
    ]
    for pattern in sensitive_patterns:
        matches = re.findall(pattern, content)
        findings["sensitive_functions"].extend(matches[:3])

    return {
        "source": source,
        "size": len(content),
        "findings": findings,
        "risk_score": _calculate_js_risk(findings),
        "recommendations": _generate_js_recommendations(findings)
    }


def _calculate_js_risk(findings: Dict) -> str:
    """Calculate risk score based on findings."""
    score = 0
    score += len(findings["secrets"]) * 30
    score += len(findings["endpoints"]) * 2
    score += len(findings["debug_code"]) * 5
    score += len(findings["source_maps"]) * 10
    score += len(findings["sensitive_functions"]) * 15

    if score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_js_recommendations(findings: Dict) -> List[str]:
    """Generate recommendations based on findings."""
    recs = []
    if findings["secrets"]:
        recs.append("CRITICAL: Remove hardcoded secrets and use environment variables")
    if findings["source_maps"]:
        recs.append("Remove source map references in production builds")
    if findings["debug_code"]:
        recs.append("Remove debug/console statements before deployment")
    if findings["sensitive_functions"]:
        recs.append("Review use of eval/innerHTML for XSS vulnerabilities")
    return recs


def nuclei_scan(
    target: str,
    templates: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    rate_limit: int = 100,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner.

    Args:
        target: URL or hostname to scan
        templates: Template categories (cves, exposures, misconfiguration, etc.)
        severity: Severity filter (info, low, medium, high, critical)
        rate_limit: Requests per second
        timeout: Request timeout in seconds

    Returns:
        Scan results with findings
    """
    if templates is None:
        templates = ["cves", "exposures", "misconfiguration"]
    if severity is None:
        severity = ["medium", "high", "critical"]

    # Check if nuclei is installed
    nuclei_check = subprocess.run(["which", "nuclei"], capture_output=True)
    if nuclei_check.returncode != 0:
        return {
            "error": "Nuclei not installed",
            "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        }

    cmd = [
        "nuclei",
        "-u", target,
        "-severity", ",".join(severity),
        "-rate-limit", str(rate_limit),
        "-timeout", str(timeout),
        "-json",
        "-silent"
    ]

    for template in templates:
        cmd.extend(["-t", template])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = []

        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template": finding.get("template-id", ""),
                        "name": finding.get("info", {}).get("name", ""),
                        "severity": finding.get("info", {}).get("severity", ""),
                        "matched_at": finding.get("matched-at", ""),
                        "description": finding.get("info", {}).get("description", "")[:200]
                    })
                except json.JSONDecodeError:
                    continue

        return {
            "target": target,
            "findings": findings,
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "critical"]),
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"])
        }

    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out", "target": target}
    except Exception as e:
        return {"error": str(e), "target": target}


def secret_patterns() -> Dict[str, Any]:
    """Return all secret detection patterns."""
    return {
        "patterns": SECRET_PATTERNS,
        "count": len(SECRET_PATTERNS),
        "categories": {
            "cloud": ["aws_access_key", "aws_secret_key", "azure_key", "gcp_service_account", "digitalocean"],
            "api_keys": ["google_api", "stripe_live", "stripe_test", "sendgrid", "mailchimp", "anthropic_key", "openai_key"],
            "tokens": ["github_token", "gitlab_token", "slack_token", "npm_token", "pypi_token", "discord_token"],
            "databases": ["postgres_uri", "mongodb_uri", "redis_uri"],
            "auth": ["jwt_token", "basic_auth", "bearer_token", "private_key", "ssh_key"]
        }
    }


def secret_entropy_check(value: str) -> Dict[str, Any]:
    """Check entropy of a potential secret value."""
    entropy = calculate_entropy(value)
    return {
        "value": value[:20] + "..." if len(value) > 20 else value,
        "length": len(value),
        "entropy": entropy,
        "is_high_entropy": entropy >= 4.5,
        "recommendation": "Likely a secret - investigate" if entropy >= 4.5 else "Normal entropy"
    }


def secret_scan_git(repo_path: str, branch: str = "HEAD", max_commits: int = 100) -> Dict[str, Any]:
    """Scan git history for secrets."""
    import subprocess

    findings = []

    try:
        # Get git log
        result = subprocess.run(
            ["git", "-C", repo_path, "log", f"-{max_commits}", "--oneline"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            return {"error": "Not a git repository or git not available"}

        commits = result.stdout.strip().split('\n')

        for commit_line in commits[:max_commits]:
            if not commit_line:
                continue
            commit_hash = commit_line.split()[0]

            # Get diff for commit
            diff_result = subprocess.run(
                ["git", "-C", repo_path, "show", commit_hash, "--format="],
                capture_output=True, text=True
            )

            diff_content = diff_result.stdout

            # Check for secrets in diff
            for pattern_name, pattern_regex in SECRET_PATTERNS.items():
                matches = re.findall(pattern_regex, diff_content)
                for match in matches:
                    findings.append({
                        "type": pattern_name,
                        "commit": commit_hash,
                        "match": match[:50] + "..." if len(match) > 50 else match,
                        "severity": "HIGH"
                    })

        return {
            "repo": repo_path,
            "commits_scanned": len(commits),
            "findings": findings,
            "secrets_found": len(findings)
        }

    except Exception as e:
        return {"error": str(e)}


def js_analyze_batch(urls: List[str]) -> Dict[str, Any]:
    """Analyze multiple JavaScript files."""
    results = []
    for url in urls[:10]:  # Limit to 10
        result = js_analyze(url=url)
        results.append({"url": url, "result": result})

    return {
        "total_analyzed": len(results),
        "results": results,
        "summary": {
            "total_secrets": sum(len(r["result"].get("findings", {}).get("secrets", [])) for r in results if "error" not in r["result"]),
            "total_endpoints": sum(len(r["result"].get("findings", {}).get("endpoints", [])) for r in results if "error" not in r["result"])
        }
    }


def js_patterns() -> Dict[str, Any]:
    """Return JavaScript analysis patterns."""
    return {
        "secret_patterns": len(SECRET_PATTERNS),
        "endpoint_patterns": [
            "API path detection",
            "fetch() calls",
            "axios requests",
            "jQuery AJAX"
        ],
        "debug_patterns": [
            "console.log/debug/warn/error",
            "debugger statements",
            "TODO/FIXME/HACK comments"
        ],
        "security_patterns": [
            "eval() usage",
            "innerHTML assignment",
            "dangerouslySetInnerHTML"
        ]
    }


def nuclei_templates() -> Dict[str, Any]:
    """List available Nuclei template categories."""
    return {
        "categories": [
            {"name": "cves", "description": "Known CVE vulnerabilities"},
            {"name": "exposures", "description": "Sensitive file/data exposures"},
            {"name": "misconfiguration", "description": "Server misconfigurations"},
            {"name": "takeovers", "description": "Subdomain takeover checks"},
            {"name": "technologies", "description": "Technology detection"},
            {"name": "default-logins", "description": "Default credentials"},
            {"name": "file", "description": "Interesting files"},
            {"name": "fuzzing", "description": "Fuzzing templates"},
            {"name": "headless", "description": "Headless browser templates"},
            {"name": "workflows", "description": "Multi-step workflows"}
        ],
        "severity_levels": ["info", "low", "medium", "high", "critical"]
    }


__all__ = [
    "SECRET_PATTERNS",
    "calculate_entropy",
    "secret_scan_files",
    "secret_scan_url",
    "secret_scan_git",
    "secret_patterns",
    "secret_entropy_check",
    "js_analyze",
    "js_analyze_batch",
    "js_patterns",
    "nuclei_scan",
    "nuclei_templates"
]
