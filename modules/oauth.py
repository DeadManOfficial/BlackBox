"""
OAuth Security Testing Framework
================================

Comprehensive OAuth 2.0 security testing - redirect_uri, PKCE, state, scope, token.

Author: DeadMan Toolkit v5.3
"""

import hashlib
import base64
import secrets
import json
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlencode, quote
from dataclasses import dataclass

# Common OAuth endpoints
OAUTH_ENDPOINTS = {
    'authorize': '/oauth/authorize', 'token': '/oauth/token', 'revoke': '/oauth/revoke',
    'introspect': '/oauth/introspect', 'userinfo': '/oauth/userinfo',
    'jwks': '/.well-known/jwks.json', 'openid_config': '/.well-known/openid-configuration'
}
COMMON_SCOPES = ['openid', 'profile', 'email', 'address', 'phone', 'offline_access', 'read', 'write', 'admin']

# =============================================================================
# REDIRECT URI TESTING
# =============================================================================

@dataclass
class RedirectURITest:
    name: str; payload: str; technique: str; description: str; severity: str

class RedirectURITester:
    BYPASS_TECHNIQUES = {
        'path_traversal': [("Path traversal basic", "/../../../attacker.com"), ("Path traversal encoded", "/%2e%2e/%2e%2e/attacker.com"), ("Path traversal double encoded", "/%252e%252e/attacker.com")],
        'fragment_injection': [("Fragment injection", "#@attacker.com"), ("Fragment with path", "#/../attacker.com")],
        'subdomain_confusion': [("Subdomain prepend", "attacker."), ("Subdomain append", ".attacker.com")],
        'url_encoding': [("URL encode @", "%40attacker.com"), ("URL encode slash", "%2fattacker.com"), ("Double encode", "%252fattacker.com")],
        'unicode': [("Unicode dot", "/\uff0e\uff0e/attacker.com"), ("Unicode slash", "/\u2215attacker.com")],
        'parser_confusion': [("Auth in URL", "@attacker.com"), ("Question mark", "?@attacker.com"), ("Backslash", "\\attacker.com"), ("Newline injection", "\nattacker.com")],
        'port_manipulation': [("Port override", ":443@attacker.com"), ("High port", ":8443")],
        'scheme_manipulation': [("HTTP downgrade", "http://"), ("JavaScript scheme", "javascript:")],
        'parameter_pollution': [("Duplicate param", "&redirect_uri=https://attacker.com")],
        'open_redirect_chain': [("Open redirect", "/redirect?url=https://attacker.com")]
    }

    def __init__(self, base_uri: str = "https://example.com/callback"):
        self.base_uri, self.parsed, self.tests = base_uri, urlparse(base_uri), []

    def generate_all_tests(self) -> List[RedirectURITest]:
        self.tests = []
        severity_map = {'subdomain_confusion': 'critical', 'parser_confusion': 'critical', 'open_redirect_chain': 'critical', 'path_traversal': 'high', 'url_encoding': 'high', 'unicode': 'high'}
        for technique, payloads in self.BYPASS_TECHNIQUES.items():
            for name, payload in payloads:
                test_uri = self._apply_payload(technique, payload)
                self.tests.append(RedirectURITest(name=name, payload=test_uri, technique=technique, description=f"Test {technique} using {name}", severity=severity_map.get(technique, 'medium')))
        return self.tests

    def _apply_payload(self, technique: str, payload: str) -> str:
        p = self.parsed
        if technique == 'subdomain_confusion': return f"{p.scheme}://{payload}{p.netloc}{p.path}" if payload.startswith('attacker.') else f"{p.scheme}://{p.netloc}{payload}{p.path}"
        if technique == 'scheme_manipulation': return self.base_uri.replace("https://", "http://") if payload == "http://" else f"{payload}{p.netloc}{p.path}"
        if technique in ['path_traversal', 'fragment_injection', 'unicode', 'parser_confusion']: return f"{p.scheme}://{p.netloc}{p.path}{payload}"
        if technique == 'url_encoding': return f"{p.scheme}://{p.netloc}{p.path}/{payload}"
        if technique == 'port_manipulation': return f"{p.scheme}://{p.hostname}{payload}{p.path}"
        return f"{self.base_uri}{payload}"

# =============================================================================
# PKCE TESTING
# =============================================================================

@dataclass
class PKCETestCase:
    name: str; code_challenge: Optional[str]; code_challenge_method: Optional[str]; code_verifier: Optional[str]; expected_result: str; description: str; severity: str

class PKCETester:
    def __init__(self): self.test_cases = []

    @staticmethod
    def generate_code_verifier(length: int = 64) -> str:
        return ''.join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") for _ in range(length))

    @staticmethod
    def generate_code_challenge(verifier: str, method: str = "S256") -> str:
        if method == "plain": return verifier
        return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')

    def generate_pkce_pair(self, method: str = "S256") -> Tuple[str, str]:
        verifier = self.generate_code_verifier()
        return verifier, self.generate_code_challenge(verifier, method)

    def generate_test_cases(self) -> List[PKCETestCase]:
        v, c = self.generate_pkce_pair()
        self.test_cases = [
            PKCETestCase("No PKCE parameters", None, None, None, "Should reject if PKCE required", "Test if PKCE is enforced", "high"),
            PKCETestCase("Plain method downgrade", v, "plain", v, "Should reject plain method", "Test plain method acceptance", "high"),
            PKCETestCase("Missing code_verifier", c, "S256", None, "Should reject token request", "Challenge but no verifier", "critical"),
            PKCETestCase("Wrong code_verifier", c, "S256", self.generate_code_verifier(), "Should reject - mismatch", "Verifier doesn't match", "critical"),
            PKCETestCase("Empty code_challenge", "", "S256", v, "Should reject empty", "Empty challenge", "medium"),
            PKCETestCase("Invalid challenge method", c, "invalid", v, "Should reject invalid method", "Unsupported method", "medium"),
            PKCETestCase("Short verifier (42 chars)", None, "S256", self.generate_code_verifier(42), "Should reject - too short", "Below RFC minimum", "low"),
        ]
        for t in self.test_cases:
            if t.code_challenge is None and t.code_verifier:
                try: t.code_challenge = self.generate_code_challenge(t.code_verifier, "S256")
                except: t.code_challenge = "invalid"
        return self.test_cases

# =============================================================================
# STATE PARAMETER TESTING
# =============================================================================

@dataclass
class StateTestCase:
    name: str; state_value: Optional[str]; description: str; expected_result: str; severity: str

class StateTester:
    def __init__(self): self.test_cases = []

    @staticmethod
    def generate_state(length: int = 32) -> str: return secrets.token_urlsafe(length)

    def generate_test_cases(self) -> List[StateTestCase]:
        vs = self.generate_state()
        self.test_cases = [
            StateTestCase("No state parameter", None, "Request without state", "Should reject/warn", "high"),
            StateTestCase("Empty state", "", "Empty string state", "Should reject", "medium"),
            StateTestCase("Modified state", vs + "_modified", "State changed", "Should reject mismatch", "critical"),
            StateTestCase("Different user's state", self.generate_state(), "Another user's state", "Should reject - CSRF", "critical"),
            StateTestCase("XSS in state", vs + "<script>alert(1)</script>", "XSS payload", "Should sanitize", "medium"),
            StateTestCase("Header injection", vs + "\r\nX-Injected: header", "CRLF injection", "Should sanitize newlines", "medium"),
            StateTestCase("Very long state", "A" * 10000, "Extremely long state", "Should have length limit", "low"),
        ]
        return self.test_cases

# =============================================================================
# SCOPE TESTING
# =============================================================================

@dataclass
class ScopeTestCase:
    name: str; requested_scopes: List[str]; technique: str; description: str; expected_result: str; severity: str

class ScopeTester:
    COMMON_SCOPES = {'read_only': ['read', 'user.read', 'profile'], 'write': ['write', 'user.write'], 'admin': ['admin', 'manage', 'full_access'], 'sensitive': ['email', 'phone', 'address']}

    def __init__(self, approved_scopes: Optional[List[str]] = None):
        self.approved_scopes, self.test_cases = approved_scopes or ['read', 'profile'], []

    def generate_test_cases(self) -> List[ScopeTestCase]:
        self.test_cases = [
            ScopeTestCase("Add admin scope", self.approved_scopes + ['admin'], "scope_addition", "Request admin beyond approved", "Should reject/re-approve", "critical"),
            ScopeTestCase("Add write scope", self.approved_scopes + ['write'], "scope_addition", "Escalate read to write", "Should require approval", "high"),
            ScopeTestCase("Wildcard scope", ['*'], "wildcard", "Request all with wildcard", "Should reject wildcard", "critical"),
            ScopeTestCase("Regex scope", ['.*', 'read.*'], "wildcard", "Regex pattern", "Should reject patterns", "high"),
            ScopeTestCase("Offline access", self.approved_scopes + ['offline_access'], "token_escalation", "Request refresh token", "Should require approval", "high"),
            ScopeTestCase("URL-encoded scope", ['%61%64%6d%69%6e'], "injection", "URL-encoded 'admin'", "Should decode and validate", "medium"),
            ScopeTestCase("Scope addition on refresh", self.approved_scopes + ['admin'], "token_escalation", "More scopes on refresh", "Should reject escalation", "critical"),
        ]
        return self.test_cases

# =============================================================================
# TOKEN TESTING
# =============================================================================

@dataclass
class TokenTestCase:
    name: str; test_type: str; description: str; procedure: str; expected_result: str; severity: str

class TokenTester:
    def __init__(self): self.test_cases = []

    def generate_test_cases(self) -> List[TokenTestCase]:
        self.test_cases = [
            TokenTestCase("Token in URL", "leakage", "Token in URLs", "Check browser history for token", "Never in URL", "high"),
            TokenTestCase("Token in referrer", "leakage", "Token via Referrer", "Click external link, check Referrer", "Not in Referrer", "high"),
            TokenTestCase("Expired token", "validation", "Expired tokens accepted", "Wait for expiry, use token", "Expired rejected", "critical"),
            TokenTestCase("Revoked token", "validation", "Revoked tokens accepted", "Revoke then use token", "Revoked rejected", "critical"),
            TokenTestCase("Token after password change", "validation", "Invalidated on password change", "Change password, use token", "Should invalidate", "high"),
            TokenTestCase("Refresh token rotation", "refresh", "Tokens rotate", "Refresh, check new token issued", "Should rotate", "medium"),
            TokenTestCase("Refresh token reuse", "refresh", "Old refresh rejected", "Refresh, try old token", "Old rejected", "high"),
            TokenTestCase("JWT algorithm none", "tampering", "Alg=none attack", "Change alg to none, remove sig", "None rejected", "critical"),
            TokenTestCase("JWT claim modification", "tampering", "Modify claims", "Change user_id/scope, re-sign", "Invalid sig rejected", "critical"),
            TokenTestCase("Token binding", "binding", "Bound to client", "Use token from different client", "Reject different client", "high"),
        ]
        return self.test_cases

    def get_tests_by_type(self, test_type: str) -> List[TokenTestCase]:
        if not self.test_cases: self.generate_test_cases()
        return [t for t in self.test_cases if t.test_type == test_type]

__all__ = ['RedirectURITester', 'RedirectURITest', 'PKCETester', 'PKCETestCase', 'StateTester', 'StateTestCase', 'ScopeTester', 'ScopeTestCase', 'TokenTester', 'TokenTestCase', 'OAUTH_ENDPOINTS', 'COMMON_SCOPES']
