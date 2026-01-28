"""
BlackBox Audit - Code & Compliance Auditing
============================================

Code analysis and security auditing tools.
Wrapper for MCP Auditor functionality.
"""

from typing import Optional, List, Dict, Any
import re
import json


# OWASP patterns
OWASP_PATTERNS = {
    "A01_broken_access": [
        r"isAdmin\s*=\s*req\.",
        r"role\s*=\s*req\.(body|query|params)",
        r"if\s*\(\s*user\s*\)",
    ],
    "A02_crypto_failures": [
        r"md5\s*\(",
        r"sha1\s*\(",
        r"password\s*=\s*['\"]",
        r"DES|3DES|RC4",
    ],
    "A03_injection": [
        r"exec\s*\(",
        r"eval\s*\(",
        r"\$\{.*\}",  # template injection
        r"\.query\s*\(\s*['\"].*\+",  # SQL concat
        r"innerHTML\s*=",
    ],
    "A04_insecure_design": [
        r"TODO.*security",
        r"FIXME.*auth",
        r"//.*hack",
    ],
    "A05_security_misconfig": [
        r"debug\s*[:=]\s*true",
        r"cors.*\*",
        r"allow.*origin.*\*",
    ],
    "A06_vulnerable_components": [
        r"require\s*\(\s*['\"]lodash['\"]",  # Check version separately
    ],
    "A07_auth_failures": [
        r"jwt\.sign\s*\(\s*\{",
        r"bcrypt\.compare",
        r"password.*length\s*[<>]\s*[0-8]",
    ],
    "A08_integrity_failures": [
        r"npm\s+install\s+--save-dev",
        r"pip\s+install\s+--trusted-host",
    ],
    "A09_logging_failures": [
        r"console\.log\s*\(.*password",
        r"console\.log\s*\(.*token",
        r"console\.log\s*\(.*secret",
    ],
    "A10_ssrf": [
        r"fetch\s*\(\s*req\.",
        r"axios\s*\(\s*\{.*url:\s*req\.",
        r"request\s*\(\s*req\.",
    ]
}


def audit_code(code: str, language: str = "auto") -> Dict[str, Any]:
    """
    Audit code for OWASP Top 10 vulnerabilities.

    Args:
        code: Source code to audit
        language: Programming language (auto-detect if not specified)

    Returns:
        Audit findings with OWASP mappings
    """
    findings = []

    # Detect language if auto
    if language == "auto":
        if "import React" in code or "const " in code:
            language = "javascript"
        elif "def " in code or "import " in code:
            language = "python"
        elif "<?php" in code:
            language = "php"
        else:
            language = "unknown"

    # Check each OWASP category
    for owasp_id, patterns in OWASP_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # Get line number
                line_num = code[:match.start()].count('\n') + 1
                line_content = code.split('\n')[line_num - 1].strip()

                findings.append({
                    "owasp": owasp_id,
                    "pattern": pattern,
                    "line": line_num,
                    "code": line_content[:100],
                    "severity": _get_severity(owasp_id)
                })

    return {
        "language": language,
        "lines_analyzed": code.count('\n') + 1,
        "findings": findings,
        "findings_count": len(findings),
        "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
        "high": len([f for f in findings if f["severity"] == "HIGH"]),
        "medium": len([f for f in findings if f["severity"] == "MEDIUM"])
    }


def _get_severity(owasp_id: str) -> str:
    """Map OWASP category to severity."""
    critical = ["A03_injection", "A01_broken_access", "A07_auth_failures"]
    high = ["A02_crypto_failures", "A10_ssrf", "A05_security_misconfig"]
    if owasp_id in critical:
        return "CRITICAL"
    elif owasp_id in high:
        return "HIGH"
    return "MEDIUM"


def scan_red_flags(code: str) -> Dict[str, Any]:
    """
    Quick scan for obvious security red flags.

    Args:
        code: Source code to scan
    """
    red_flags = []

    patterns = {
        "hardcoded_secret": r"(password|secret|key|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "eval_usage": r"eval\s*\(",
        "exec_usage": r"exec\s*\(",
        "dangerous_html": r"\.innerHTML\s*=|dangerouslySetInnerHTML",
        "sql_concat": r"(SELECT|INSERT|UPDATE|DELETE).*\+\s*(req\.|user|input)",
        "shell_injection": r"(child_process|subprocess|os\.system)\s*\(",
        "debug_enabled": r"debug\s*[:=]\s*true",
        "cors_wildcard": r"Access-Control-Allow-Origin.*\*",
    }

    for flag_type, pattern in patterns.items():
        matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            red_flags.append({
                "type": flag_type,
                "line": line_num,
                "match": match.group()[:80]
            })

    return {
        "red_flags": red_flags,
        "count": len(red_flags),
        "severity": "CRITICAL" if len(red_flags) > 0 else "OK"
    }


def analyze_dependencies(package_json: str) -> Dict[str, Any]:
    """
    Analyze package.json for known vulnerable dependencies.

    Args:
        package_json: Contents of package.json
    """
    try:
        pkg = json.loads(package_json)
    except json.JSONDecodeError:
        return {"error": "Invalid JSON"}

    deps = {}
    deps.update(pkg.get("dependencies", {}))
    deps.update(pkg.get("devDependencies", {}))

    # Known vulnerable packages (simplified check)
    known_vulnerable = {
        "lodash": "< 4.17.21",
        "axios": "< 0.21.1",
        "node-fetch": "< 2.6.1",
        "minimist": "< 1.2.6",
        "json-schema": "< 0.4.0",
    }

    findings = []
    for pkg_name, version in deps.items():
        if pkg_name in known_vulnerable:
            findings.append({
                "package": pkg_name,
                "installed": version,
                "vulnerable_below": known_vulnerable[pkg_name],
                "recommendation": f"Update {pkg_name} to latest version"
            })

    return {
        "total_dependencies": len(deps),
        "potentially_vulnerable": len(findings),
        "findings": findings,
        "recommendation": "Run 'npm audit' for complete vulnerability check"
    }


def assess_owasp(context: str) -> Dict[str, Any]:
    """
    Assess application against OWASP Top 10.

    Args:
        context: Application context/description
    """
    owasp_top_10 = [
        {"id": "A01:2021", "name": "Broken Access Control", "questions": ["Does the app enforce authorization checks?"]},
        {"id": "A02:2021", "name": "Cryptographic Failures", "questions": ["Is sensitive data encrypted?"]},
        {"id": "A03:2021", "name": "Injection", "questions": ["Are all inputs validated and sanitized?"]},
        {"id": "A04:2021", "name": "Insecure Design", "questions": ["Was threat modeling performed?"]},
        {"id": "A05:2021", "name": "Security Misconfiguration", "questions": ["Are security headers configured?"]},
        {"id": "A06:2021", "name": "Vulnerable Components", "questions": ["Are dependencies up to date?"]},
        {"id": "A07:2021", "name": "Auth Failures", "questions": ["Is MFA implemented?"]},
        {"id": "A08:2021", "name": "Integrity Failures", "questions": ["Is software signed and verified?"]},
        {"id": "A09:2021", "name": "Logging Failures", "questions": ["Are security events logged?"]},
        {"id": "A10:2021", "name": "SSRF", "questions": ["Are external requests validated?"]},
    ]

    return {
        "framework": "OWASP Top 10 2021",
        "categories": owasp_top_10,
        "assessment_required": True,
        "note": "Complete manual assessment for each category"
    }


__all__ = [
    "audit_code",
    "scan_red_flags",
    "analyze_dependencies",
    "assess_owasp"
]
