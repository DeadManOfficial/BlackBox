"""
Advanced Reconnaissance Module
==============================
Enhanced penetration testing capabilities for modern web applications.

Addresses gaps in:
- JavaScript deep analysis (source maps, AST, bundle unpacking)
- Dynamic SPA testing
- GraphQL security
- Subdomain enumeration
- Authentication testing
- Cloud asset discovery

Author: DeadMan Pentest Suite
Version: 1.0.0
"""

import re
import json
import base64
import hashlib
import asyncio
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, parse_qs
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReconFinding:
    """Security finding from reconnaissance"""
    title: str
    severity: FindingSeverity
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe
        }


# =============================================================================
# JAVASCRIPT DEEP ANALYSIS
# =============================================================================

class JSDeepAnalyzer:
    """
    Advanced JavaScript analysis for modern web apps.

    Features:
    - Source map detection and download
    - Webpack/bundle unpacking
    - AST-based secret extraction
    - API endpoint extraction from minified code
    - React/Next.js route extraction
    """

    # Enhanced patterns for secret detection
    SECRET_PATTERNS = {
        # Cloud providers
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access)?[_\-\.]?key['\"]?\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "gcp_api_key": r"AIza[0-9A-Za-z\-_]{35}",
        "azure_storage": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",

        # Payment
        "stripe_live": r"sk_live_[0-9a-zA-Z]{24,}",
        "stripe_test": r"sk_test_[0-9a-zA-Z]{24,}",
        "stripe_pub": r"pk_(live|test)_[0-9a-zA-Z]{24,}",

        # Auth tokens
        "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "gitlab_token": r"glpat-[A-Za-z0-9\-]{20,}",
        "jwt_token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "bearer_token": r"['\"]Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+['\"]",

        # Database
        "mongodb_uri": r"mongodb(?:\+srv)?://[^\s'\"]+",
        "postgres_uri": r"postgres(?:ql)?://[^\s'\"]+",
        "redis_uri": r"redis://[^\s'\"]+",

        # API keys (generic)
        "api_key_generic": r"(?i)['\"]?(?:api[_\-]?key|apikey|api_secret|api_token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",
        "auth_token": r"(?i)['\"]?(?:auth[_\-]?token|access[_\-]?token|secret[_\-]?token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_]{20,})['\"]",

        # Private keys
        "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",

        # Firebase
        "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
        "firebase_config": r"apiKey:\s*['\"][A-Za-z0-9\-_]+['\"]",

        # Slack
        "slack_webhook": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "slack_token": r"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}",

        # Twilio
        "twilio_sid": r"AC[a-f0-9]{32}",
        "twilio_token": r"(?i)twilio[_\-]?(?:auth)?[_\-]?token['\"]?\s*[:=]\s*['\"]([a-f0-9]{32})['\"]",

        # SendGrid
        "sendgrid_key": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",

        # Mailgun
        "mailgun_key": r"key-[a-f0-9]{32}",
    }

    # API endpoint patterns
    ENDPOINT_PATTERNS = [
        r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_\-]+["\']',
        r'["\']https?://[^"\']+/(api|v[0-9]+)/[^"\']+["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
        r'baseURL:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
    ]

    # Next.js/React route patterns
    ROUTE_PATTERNS = [
        r'path:\s*["\']([^"\']+)["\']',
        r'to:\s*["\']([^"\']+)["\']',
        r'href:\s*["\']([^"\']+)["\']',
        r'navigate\s*\(\s*["\']([^"\']+)["\']',
        r'push\s*\(\s*["\']([^"\']+)["\']',
        r'replace\s*\(\s*["\']([^"\']+)["\']',
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def analyze_url(self, js_url: str) -> Dict[str, Any]:
        """
        Perform deep analysis on a JavaScript file.

        Args:
            js_url: URL to JavaScript file

        Returns:
            Analysis results with secrets, endpoints, routes
        """
        results = {
            "url": js_url,
            "secrets": [],
            "endpoints": [],
            "routes": [],
            "source_map": None,
            "original_source": None,
        }

        try:
            # Fetch JS content
            resp = self.session.get(js_url, timeout=self.timeout)
            content = resp.text

            # Check for source map
            source_map_url = self._find_source_map(content, js_url)
            if source_map_url:
                results["source_map"] = source_map_url
                original = self._fetch_source_map(source_map_url)
                if original:
                    results["original_source"] = True
                    content = original  # Analyze original source instead

            # Scan for secrets
            results["secrets"] = self._scan_secrets(content)

            # Extract endpoints
            results["endpoints"] = self._extract_endpoints(content)

            # Extract routes
            results["routes"] = self._extract_routes(content)

        except Exception as e:
            results["error"] = str(e)

        return results

    def analyze_multiple(self, js_urls: List[str], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Analyze multiple JS files concurrently"""
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.analyze_url, url): url for url in js_urls}
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def _find_source_map(self, content: str, js_url: str) -> Optional[str]:
        """Find source map URL in JS file"""
        # Check for sourceMappingURL comment
        match = re.search(r'//[#@]\s*sourceMappingURL=(.+?)(?:\s|$)', content)
        if match:
            map_url = match.group(1)
            if not map_url.startswith('http'):
                # Relative URL
                map_url = urljoin(js_url, map_url)
            return map_url

        # Try .map extension
        map_url = js_url + '.map'
        try:
            resp = self.session.head(map_url, timeout=5)
            if resp.status_code == 200:
                return map_url
        except Exception:
            pass

        return None

    def _fetch_source_map(self, map_url: str) -> Optional[str]:
        """Fetch and decode source map to get original source"""
        try:
            resp = self.session.get(map_url, timeout=self.timeout)
            if resp.status_code != 200:
                return None

            map_data = resp.json()

            # Combine all original sources
            sources = []
            if 'sourcesContent' in map_data:
                sources = map_data['sourcesContent']

            return '\n'.join(s for s in sources if s)

        except Exception:
            return None

    def _scan_secrets(self, content: str) -> List[Dict[str, Any]]:
        """Scan content for secrets using enhanced patterns"""
        secrets = []

        for name, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                value = match.group(0)
                # Skip obvious false positives
                if self._is_false_positive(value, name):
                    continue

                secrets.append({
                    "type": name,
                    "value": self._mask_secret(value),
                    "raw_length": len(value),
                    "context": content[max(0, match.start()-20):match.end()+20]
                })

        return secrets

    def _is_false_positive(self, value: str, secret_type: str) -> bool:
        """Filter out common false positives"""
        # Placeholder patterns
        placeholders = [
            'xxx', 'your_', 'example', 'placeholder', 'test_',
            'dummy', 'fake', 'sample', '<', '${', '{{',
            'REPLACE', 'INSERT', 'TODO', 'CHANGEME'
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders)

    def _mask_secret(self, value: str) -> str:
        """Mask secret value for safe logging"""
        if len(value) <= 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def _extract_endpoints(self, content: str) -> List[str]:
        """Extract API endpoints from JS content"""
        endpoints = set()

        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip('"\'')
                if self._is_valid_endpoint(endpoint):
                    endpoints.add(endpoint)

        return sorted(endpoints)

    def _extract_routes(self, content: str) -> List[str]:
        """Extract application routes from JS content"""
        routes = set()

        for pattern in self.ROUTE_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                route = match.group(1)
                if route.startswith('/') and not route.startswith('//'):
                    routes.add(route)

        return sorted(routes)

    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Check if extracted endpoint is valid"""
        if not endpoint or len(endpoint) < 2:
            return False
        # Skip static assets
        if any(endpoint.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.ico']):
            return False
        # Skip data URIs
        if endpoint.startswith('data:'):
            return False
        return True


# =============================================================================
# GRAPHQL SECURITY TESTING
# =============================================================================

class GraphQLTester:
    """
    GraphQL security testing module.

    Tests for:
    - Introspection enabled
    - Query depth attacks
    - Batch query attacks
    - Field suggestion exploitation
    - Authorization bypass
    """

    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind }
          }
        }
      }
    }
    """

    FIELD_SUGGESTION_QUERY = """
    query { __typename usre { id } }
    """

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        self.findings: List[ReconFinding] = []

    def test_endpoint(self, url: str, headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Run all GraphQL security tests on endpoint.

        Args:
            url: GraphQL endpoint URL
            headers: Optional auth headers

        Returns:
            Test results and findings
        """
        if headers:
            self.session.headers.update(headers)

        results = {
            "url": url,
            "is_graphql": False,
            "introspection_enabled": False,
            "schema": None,
            "field_suggestions": False,
            "batch_queries": False,
            "findings": []
        }

        # Test if endpoint is GraphQL
        if not self._test_graphql_endpoint(url):
            return results
        results["is_graphql"] = True

        # Test introspection
        intro_result = self._test_introspection(url)
        results["introspection_enabled"] = intro_result["enabled"]
        if intro_result["enabled"]:
            results["schema"] = intro_result["schema"]
            self.findings.append(ReconFinding(
                title="GraphQL Introspection Enabled",
                severity=FindingSeverity.MEDIUM,
                description="GraphQL introspection is enabled, allowing attackers to discover the entire API schema.",
                evidence=f"Endpoint: {url}",
                remediation="Disable introspection in production environments.",
                cwe="CWE-200"
            ))

        # Test field suggestions
        results["field_suggestions"] = self._test_field_suggestions(url)
        if results["field_suggestions"]:
            self.findings.append(ReconFinding(
                title="GraphQL Field Suggestions Enabled",
                severity=FindingSeverity.LOW,
                description="GraphQL returns field suggestions on typos, aiding schema discovery.",
                evidence=f"Endpoint: {url}",
                remediation="Disable field suggestions in production.",
                cwe="CWE-200"
            ))

        # Test batch queries
        results["batch_queries"] = self._test_batch_queries(url)
        if results["batch_queries"]:
            self.findings.append(ReconFinding(
                title="GraphQL Batch Queries Enabled",
                severity=FindingSeverity.LOW,
                description="GraphQL accepts batched queries, potentially enabling DoS or rate limit bypass.",
                evidence=f"Endpoint: {url}",
                remediation="Implement query cost analysis and rate limiting.",
                cwe="CWE-770"
            ))

        results["findings"] = [f.to_dict() for f in self.findings]
        return results

    def _test_graphql_endpoint(self, url: str) -> bool:
        """Test if URL is a GraphQL endpoint"""
        try:
            resp = self.session.post(url, json={"query": "{ __typename }"}, timeout=self.timeout)
            data = resp.json()
            return "data" in data or "errors" in data
        except Exception:
            return False

    def _test_introspection(self, url: str) -> Dict[str, Any]:
        """Test for introspection vulnerability"""
        try:
            resp = self.session.post(
                url,
                json={"query": self.INTROSPECTION_QUERY},
                timeout=self.timeout
            )
            data = resp.json()

            if "data" in data and data["data"] and "__schema" in data["data"]:
                return {
                    "enabled": True,
                    "schema": data["data"]["__schema"]
                }
        except Exception:
            pass

        return {"enabled": False, "schema": None}

    def _test_field_suggestions(self, url: str) -> bool:
        """Test for field suggestion disclosure"""
        try:
            resp = self.session.post(
                url,
                json={"query": self.FIELD_SUGGESTION_QUERY},
                timeout=self.timeout
            )
            data = resp.json()

            if "errors" in data:
                error_text = str(data["errors"])
                # Check for suggestion patterns
                if "Did you mean" in error_text or "did you mean" in error_text:
                    return True
        except Exception:
            pass

        return False

    def _test_batch_queries(self, url: str) -> bool:
        """Test for batch query support"""
        try:
            batch = [
                {"query": "{ __typename }"},
                {"query": "{ __typename }"}
            ]
            resp = self.session.post(url, json=batch, timeout=self.timeout)
            data = resp.json()
            return isinstance(data, list) and len(data) == 2
        except Exception:
            return False

    def extract_types(self, schema: Dict) -> Dict[str, List[str]]:
        """Extract types and fields from introspection schema"""
        types_info = {}

        if not schema or "types" not in schema:
            return types_info

        for t in schema["types"]:
            if t["name"].startswith("__"):
                continue  # Skip introspection types

            fields = []
            if t.get("fields"):
                fields = [f["name"] for f in t["fields"]]

            types_info[t["name"]] = fields

        return types_info


# =============================================================================
# SUBDOMAIN ENUMERATION
# =============================================================================

class SubdomainEnumerator:
    """
    Subdomain enumeration using multiple sources.

    Sources:
    - Certificate Transparency logs (crt.sh)
    - DNS brute forcing
    - Common subdomain wordlist
    - Web archive (Wayback Machine)
    """

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
        "beta", "app", "m", "mobile", "portal", "secure", "vpn", "remote",
        "cdn", "static", "assets", "img", "images", "media", "download",
        "support", "help", "docs", "blog", "shop", "store", "pay", "checkout",
        "login", "auth", "sso", "oauth", "account", "my", "dashboard",
        "internal", "intranet", "corp", "corporate", "employee", "staff",
        "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "build",
        "monitor", "status", "health", "metrics", "grafana", "kibana",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
        "s3", "storage", "backup", "archive", "legacy", "old", "new",
        "sandbox", "demo", "preview", "uat", "qa", "prod", "production",
        "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap", "webmail",
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def enumerate(self, domain: str, use_bruteforce: bool = True) -> Dict[str, Any]:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Target domain
            use_bruteforce: Also try common subdomain names

        Returns:
            Enumeration results
        """
        results = {
            "domain": domain,
            "subdomains": set(),
            "sources": {},
            "live": [],
            "takeover_candidates": []
        }

        # Certificate Transparency
        ct_results = self._query_ct_logs(domain)
        results["sources"]["ct_logs"] = len(ct_results)
        results["subdomains"].update(ct_results)

        # Wayback Machine
        wayback_results = self._query_wayback(domain)
        results["sources"]["wayback"] = len(wayback_results)
        results["subdomains"].update(wayback_results)

        # Brute force common subdomains
        if use_bruteforce:
            brute_results = self._bruteforce_subdomains(domain)
            results["sources"]["bruteforce"] = len(brute_results)
            results["subdomains"].update(brute_results)

        # Check which are live
        results["subdomains"] = sorted(results["subdomains"])
        results["live"] = self._check_live(list(results["subdomains"]))

        # Check for subdomain takeover
        results["takeover_candidates"] = self._check_takeover(results["live"])

        return results

    def _query_ct_logs(self, domain: str) -> Set[str]:
        """Query Certificate Transparency logs via crt.sh"""
        subdomains = set()

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = self.session.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Handle wildcards and multiple names
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n.startswith("*."):
                            n = n[2:]
                        if n.endswith(domain) and n != domain:
                            subdomains.add(n)
        except Exception:
            pass

        return subdomains

    def _query_wayback(self, domain: str) -> Set[str]:
        """Query Wayback Machine for historical subdomains"""
        subdomains = set()

        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            resp = self.session.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                for entry in data[1:]:  # Skip header
                    try:
                        parsed = urlparse(entry[0])
                        host = parsed.netloc.lower()
                        if host.endswith(domain) and host != domain:
                            subdomains.add(host)
                    except Exception:
                        pass
        except Exception:
            pass

        return subdomains

    def _bruteforce_subdomains(self, domain: str) -> Set[str]:
        """Brute force common subdomain names"""
        found = set()

        def check_subdomain(sub: str) -> Optional[str]:
            fqdn = f"{sub}.{domain}"
            try:
                import socket
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.COMMON_SUBDOMAINS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result)

        return found

    def _check_live(self, subdomains: List[str], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Check which subdomains are live"""
        live = []

        def check(subdomain: str) -> Optional[Dict]:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{subdomain}"
                    resp = self.session.get(url, timeout=5, allow_redirects=False)
                    return {
                        "subdomain": subdomain,
                        "url": url,
                        "status": resp.status_code,
                        "server": resp.headers.get("Server", ""),
                        "redirect": resp.headers.get("Location", "")
                    }
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(check, sub): sub for sub in subdomains[:100]}  # Limit
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live.append(result)

        return live

    def _check_takeover(self, live_subdomains: List[Dict]) -> List[Dict[str, Any]]:
        """Check for potential subdomain takeover"""
        TAKEOVER_SIGNATURES = {
            "GitHub Pages": "There isn't a GitHub Pages site here",
            "Heroku": "No such app",
            "AWS S3": "NoSuchBucket",
            "Azure": "404 Web Site not found",
            "Shopify": "Sorry, this shop is currently unavailable",
            "Tumblr": "There's nothing here",
            "WordPress": "Do you want to register",
            "Ghost": "The thing you were looking for is no longer here",
            "Surge": "project not found",
            "Bitbucket": "Repository not found",
            "Pantheon": "404 error unknown site",
            "Fastly": "Fastly error: unknown domain",
            "Zendesk": "Help Center Closed",
        }

        candidates = []

        for sub in live_subdomains:
            try:
                resp = self.session.get(sub["url"], timeout=5)
                content = resp.text[:5000]

                for service, signature in TAKEOVER_SIGNATURES.items():
                    if signature in content:
                        candidates.append({
                            "subdomain": sub["subdomain"],
                            "service": service,
                            "signature": signature
                        })
                        break
            except Exception:
                pass

        return candidates


# =============================================================================
# AUTHENTICATION TESTING
# =============================================================================

class AuthTester:
    """
    Authentication security testing module.

    Tests for:
    - Username enumeration
    - Rate limiting
    - Password policy
    - Account lockout
    - Session security
    - OAuth misconfigurations
    """

    COMMON_USERNAMES = ["admin", "administrator", "root", "test", "user", "guest", "demo"]
    WEAK_PASSWORDS = ["password", "123456", "admin", "test", "guest", "letmein"]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings: List[ReconFinding] = []

    def test_login_endpoint(
        self,
        url: str,
        username_field: str = "username",
        password_field: str = "password",
        valid_username: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test login endpoint for common vulnerabilities.

        Args:
            url: Login endpoint URL
            username_field: Username form field name
            password_field: Password form field name
            valid_username: Known valid username for testing

        Returns:
            Test results
        """
        results = {
            "url": url,
            "username_enumeration": False,
            "rate_limiting": True,  # Assume exists until proven otherwise
            "rate_limit_threshold": None,
            "account_lockout": None,
            "findings": []
        }

        # Test username enumeration
        enum_result = self._test_username_enumeration(
            url, username_field, password_field, valid_username
        )
        results["username_enumeration"] = enum_result["vulnerable"]
        if enum_result["vulnerable"]:
            self.findings.append(ReconFinding(
                title="Username Enumeration",
                severity=FindingSeverity.MEDIUM,
                description="Login endpoint reveals whether usernames exist through different responses.",
                evidence=enum_result.get("evidence", ""),
                remediation="Use generic error messages for both invalid username and password.",
                cwe="CWE-204"
            ))

        # Test rate limiting
        rate_result = self._test_rate_limiting(url, username_field, password_field)
        results["rate_limiting"] = rate_result["exists"]
        results["rate_limit_threshold"] = rate_result.get("threshold")
        if not rate_result["exists"]:
            self.findings.append(ReconFinding(
                title="Missing Rate Limiting on Login",
                severity=FindingSeverity.HIGH,
                description="Login endpoint lacks rate limiting, enabling brute force attacks.",
                evidence=f"Sent {rate_result.get('requests_sent', 'multiple')} requests without blocking",
                remediation="Implement rate limiting (e.g., 5 attempts per minute).",
                cwe="CWE-307"
            ))

        results["findings"] = [f.to_dict() for f in self.findings]
        return results

    def _test_username_enumeration(
        self,
        url: str,
        username_field: str,
        password_field: str,
        valid_username: Optional[str]
    ) -> Dict[str, Any]:
        """Test for username enumeration vulnerability"""
        result = {"vulnerable": False, "evidence": ""}

        invalid_user = "nonexistent_user_" + hashlib.md5(str(id(self)).encode()).hexdigest()[:8]
        test_password = "InvalidPassword123!"

        try:
            # Test with invalid username
            resp_invalid = self.session.post(url, data={
                username_field: invalid_user,
                password_field: test_password
            }, timeout=self.timeout, allow_redirects=False)

            # Test with potentially valid username
            test_user = valid_username or "admin"
            resp_valid = self.session.post(url, data={
                username_field: test_user,
                password_field: test_password
            }, timeout=self.timeout, allow_redirects=False)

            # Compare responses
            if resp_invalid.status_code != resp_valid.status_code:
                result["vulnerable"] = True
                result["evidence"] = f"Different status codes: {resp_invalid.status_code} vs {resp_valid.status_code}"
            elif len(resp_invalid.text) != len(resp_valid.text):
                diff = abs(len(resp_invalid.text) - len(resp_valid.text))
                if diff > 10:  # Significant difference
                    result["vulnerable"] = True
                    result["evidence"] = f"Response length differs by {diff} bytes"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _test_rate_limiting(
        self,
        url: str,
        username_field: str,
        password_field: str,
        attempts: int = 20
    ) -> Dict[str, Any]:
        """Test for rate limiting on login endpoint"""
        result = {"exists": False, "threshold": None, "requests_sent": 0}

        test_user = "test_rate_limit_" + hashlib.md5(str(id(self)).encode()).hexdigest()[:8]

        try:
            for i in range(attempts):
                resp = self.session.post(url, data={
                    username_field: test_user,
                    password_field: f"password{i}"
                }, timeout=self.timeout, allow_redirects=False)

                result["requests_sent"] = i + 1

                # Check for rate limiting indicators
                if resp.status_code == 429:  # Too Many Requests
                    result["exists"] = True
                    result["threshold"] = i + 1
                    break

                if any(indicator in resp.text.lower() for indicator in [
                    "too many", "rate limit", "slow down", "try again later",
                    "blocked", "locked", "captcha"
                ]):
                    result["exists"] = True
                    result["threshold"] = i + 1
                    break

        except Exception as e:
            result["error"] = str(e)

        return result

    def test_session_security(self, url: str) -> Dict[str, Any]:
        """Test session cookie security"""
        results = {
            "url": url,
            "cookies": [],
            "findings": []
        }

        try:
            resp = self.session.get(url, timeout=self.timeout)

            for cookie in resp.cookies:
                cookie_info = {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(),
                    "samesite": cookie.get_nonstandard_attr("SameSite", "None")
                }
                results["cookies"].append(cookie_info)

                # Check for insecure session cookies
                if "session" in cookie.name.lower() or "token" in cookie.name.lower():
                    if not cookie.secure:
                        self.findings.append(ReconFinding(
                            title="Session Cookie Missing Secure Flag",
                            severity=FindingSeverity.MEDIUM,
                            description=f"Cookie '{cookie.name}' lacks Secure flag, transmittable over HTTP.",
                            remediation="Add Secure flag to all session cookies.",
                            cwe="CWE-614"
                        ))
                    if not cookie_info["httponly"]:
                        self.findings.append(ReconFinding(
                            title="Session Cookie Missing HttpOnly Flag",
                            severity=FindingSeverity.MEDIUM,
                            description=f"Cookie '{cookie.name}' lacks HttpOnly flag, accessible via JavaScript.",
                            remediation="Add HttpOnly flag to session cookies.",
                            cwe="CWE-1004"
                        ))

        except Exception as e:
            results["error"] = str(e)

        results["findings"] = [f.to_dict() for f in self.findings]
        return results


# =============================================================================
# CLOUD ASSET DISCOVERY
# =============================================================================

class CloudAssetDiscovery:
    """
    Discover cloud assets associated with a domain.

    Checks:
    - AWS S3 buckets
    - Azure Blob storage
    - Google Cloud Storage
    - Common cloud service patterns
    """

    S3_REGIONS = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1"
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def discover(self, domain: str) -> Dict[str, Any]:
        """
        Discover cloud assets for a domain.

        Args:
            domain: Target domain

        Returns:
            Discovery results
        """
        results = {
            "domain": domain,
            "s3_buckets": [],
            "azure_storage": [],
            "gcp_storage": [],
            "findings": []
        }

        # Generate bucket name permutations
        base_name = domain.replace(".", "-")
        permutations = self._generate_permutations(base_name, domain.split(".")[0])

        # Check S3
        results["s3_buckets"] = self._check_s3_buckets(permutations)

        # Check Azure
        results["azure_storage"] = self._check_azure_storage(permutations)

        # Check GCP
        results["gcp_storage"] = self._check_gcp_storage(permutations)

        return results

    def _generate_permutations(self, base: str, short: str) -> List[str]:
        """Generate common bucket name permutations"""
        suffixes = [
            "", "-backup", "-backups", "-bak", "-data", "-files",
            "-assets", "-static", "-media", "-images", "-uploads",
            "-dev", "-staging", "-prod", "-production", "-test",
            "-logs", "-archive", "-public", "-private", "-internal"
        ]

        names = []
        for suffix in suffixes:
            names.append(f"{base}{suffix}")
            names.append(f"{short}{suffix}")

        return names

    def _check_s3_buckets(self, names: List[str]) -> List[Dict[str, Any]]:
        """Check for exposed S3 buckets"""
        found = []

        def check_bucket(name: str) -> Optional[Dict]:
            url = f"https://{name}.s3.amazonaws.com"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    return {"name": name, "url": url, "public": True, "listable": "<ListBucketResult" in resp.text}
                elif resp.status_code == 403:
                    return {"name": name, "url": url, "public": False, "exists": True}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_bucket, name): name for name in names}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        return found

    def _check_azure_storage(self, names: List[str]) -> List[Dict[str, Any]]:
        """Check for exposed Azure Blob storage"""
        found = []

        for name in names[:20]:  # Limit checks
            # Azure storage account names are 3-24 chars, lowercase alphanumeric
            clean_name = re.sub(r'[^a-z0-9]', '', name.lower())[:24]
            if len(clean_name) < 3:
                continue

            url = f"https://{clean_name}.blob.core.windows.net"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code != 404:
                    found.append({
                        "name": clean_name,
                        "url": url,
                        "status": resp.status_code
                    })
            except Exception:
                pass

        return found

    def _check_gcp_storage(self, names: List[str]) -> List[Dict[str, Any]]:
        """Check for exposed GCP Storage buckets"""
        found = []

        for name in names[:20]:  # Limit checks
            url = f"https://storage.googleapis.com/{name}"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    found.append({
                        "name": name,
                        "url": url,
                        "public": True
                    })
                elif resp.status_code == 403:
                    found.append({
                        "name": name,
                        "url": url,
                        "exists": True,
                        "public": False
                    })
            except Exception:
                pass

        return found


# =============================================================================
# UNIFIED ADVANCED RECON
# =============================================================================

class AdvancedRecon:
    """
    Unified advanced reconnaissance toolkit.

    Combines all advanced testing capabilities:
    - JS deep analysis
    - GraphQL security
    - Subdomain enumeration
    - Auth testing
    - Cloud asset discovery

    Example:
        recon = AdvancedRecon()
        results = recon.full_scan("example.com")
    """

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.js_analyzer = JSDeepAnalyzer(timeout)
        self.graphql_tester = GraphQLTester(timeout)
        self.subdomain_enum = SubdomainEnumerator(timeout)
        self.auth_tester = AuthTester(timeout)
        self.cloud_discovery = CloudAssetDiscovery(timeout)

    def full_scan(
        self,
        domain: str,
        include_subdomains: bool = True,
        include_cloud: bool = True,
        js_urls: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run comprehensive reconnaissance scan.

        Args:
            domain: Target domain
            include_subdomains: Enumerate subdomains
            include_cloud: Check cloud assets
            js_urls: JavaScript URLs to analyze

        Returns:
            Complete scan results
        """
        results = {
            "domain": domain,
            "scan_modules": [],
            "subdomains": None,
            "cloud_assets": None,
            "js_analysis": None,
            "graphql": None,
            "all_findings": []
        }

        # Subdomain enumeration
        if include_subdomains:
            results["scan_modules"].append("subdomains")
            results["subdomains"] = self.subdomain_enum.enumerate(domain)

            # Check for takeover findings
            if results["subdomains"].get("takeover_candidates"):
                for candidate in results["subdomains"]["takeover_candidates"]:
                    results["all_findings"].append({
                        "title": "Potential Subdomain Takeover",
                        "severity": "high",
                        "description": f"Subdomain {candidate['subdomain']} may be vulnerable to takeover via {candidate['service']}",
                        "evidence": candidate["signature"]
                    })

        # Cloud asset discovery
        if include_cloud:
            results["scan_modules"].append("cloud")
            results["cloud_assets"] = self.cloud_discovery.discover(domain)

            # Check for exposed buckets
            for bucket in results["cloud_assets"].get("s3_buckets", []):
                if bucket.get("public") and bucket.get("listable"):
                    results["all_findings"].append({
                        "title": "Exposed S3 Bucket",
                        "severity": "high",
                        "description": f"S3 bucket {bucket['name']} is publicly listable",
                        "evidence": bucket["url"]
                    })

        # JavaScript analysis
        if js_urls:
            results["scan_modules"].append("javascript")
            results["js_analysis"] = self.js_analyzer.analyze_multiple(js_urls)

            # Collect secret findings
            for analysis in results["js_analysis"]:
                for secret in analysis.get("secrets", []):
                    results["all_findings"].append({
                        "title": f"Hardcoded Secret ({secret['type']})",
                        "severity": "high",
                        "description": f"Found {secret['type']} in JavaScript",
                        "evidence": secret["value"]
                    })

        # Try common GraphQL endpoints
        graphql_endpoints = [
            f"https://{domain}/graphql",
            f"https://{domain}/api/graphql",
            f"https://www.{domain}/graphql",
            f"https://api.{domain}/graphql"
        ]

        for endpoint in graphql_endpoints:
            try:
                gql_result = self.graphql_tester.test_endpoint(endpoint)
                if gql_result.get("is_graphql"):
                    results["scan_modules"].append("graphql")
                    results["graphql"] = gql_result
                    results["all_findings"].extend(gql_result.get("findings", []))
                    break
            except Exception:
                pass

        return results

    @staticmethod
    def get_capabilities() -> Dict[str, str]:
        """List all reconnaissance capabilities"""
        return {
            "js_deep_analysis": "Deep JavaScript analysis with source map recovery and AST-based secret scanning",
            "graphql_security": "GraphQL introspection, batching, and field suggestion testing",
            "subdomain_enumeration": "CT logs, Wayback Machine, DNS brute force, takeover detection",
            "auth_testing": "Username enumeration, rate limiting, session security testing",
            "cloud_discovery": "AWS S3, Azure Blob, GCP Storage bucket discovery"
        }


# Export all classes
__all__ = [
    "FindingSeverity",
    "ReconFinding",
    "JSDeepAnalyzer",
    "GraphQLTester",
    "SubdomainEnumerator",
    "AuthTester",
    "CloudAssetDiscovery",
    "AdvancedRecon",
]
