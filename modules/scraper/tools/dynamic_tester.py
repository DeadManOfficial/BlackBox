"""
Dynamic Application Security Testing Module
============================================
Browser-based testing for modern SPAs and JavaScript-heavy applications.

Features:
- Playwright-based browser automation
- Form detection and auto-filling
- XSS payload injection testing
- DOM-based vulnerability detection
- Network request interception
- Cookie and storage analysis

Author: DeadMan Pentest Suite
Version: 1.0.0
"""

import asyncio
import json
import re
import hashlib
from typing import Optional, List, Dict, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, urljoin, parse_qs


@dataclass
class DynamicFinding:
    """Security finding from dynamic testing"""
    title: str
    severity: str
    finding_type: str
    url: str
    description: str
    evidence: str = ""
    request: Optional[Dict] = None
    response: Optional[Dict] = None
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "type": self.finding_type,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "remediation": self.remediation
        }


@dataclass
class FormField:
    """Detected form field"""
    name: str
    field_type: str
    required: bool = False
    value: str = ""
    placeholder: str = ""
    autocomplete: str = ""


@dataclass
class DetectedForm:
    """Detected form on page"""
    action: str
    method: str
    fields: List[FormField]
    submit_selector: str = ""


class XSSPayloads:
    """XSS test payloads organized by context"""

    # Basic payloads
    BASIC = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
    ]

    # Event handler payloads
    EVENT_HANDLERS = [
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<video><source onerror=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ]

    # Filter bypass payloads
    BYPASSES = [
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>alert`1`</script>',
        '<img src=x onerror="alert(1)">',
        '<svg/onload=alert(1)>',
        '<<script>script>alert(1)//<</script>/script>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
    ]

    # DOM-based payloads
    DOM_BASED = [
        'javascript:alert(1)',
        '#<script>alert(1)</script>',
        'data:text/html,<script>alert(1)</script>',
    ]

    # Polyglot payloads
    POLYGLOTS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    ]

    @classmethod
    def get_all(cls) -> List[str]:
        """Get all XSS payloads"""
        return cls.BASIC + cls.EVENT_HANDLERS + cls.BYPASSES + cls.DOM_BASED

    @classmethod
    def get_safe_canary(cls) -> str:
        """Get a safe canary string for reflection testing"""
        return "DMPCANARY" + hashlib.md5(str(id(cls)).encode()).hexdigest()[:8]


class SQLiPayloads:
    """SQL injection test payloads"""

    ERROR_BASED = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' ORDER BY 1--",
    ]

    TIME_BASED = [
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1' AND SLEEP(5)--",
        "'; SELECT SLEEP(5);--",
    ]

    BOOLEAN_BASED = [
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR 1=1--",
        "' OR 1=2--",
    ]

    @classmethod
    def get_safe_canary(cls) -> str:
        """Get a canary that triggers SQL errors"""
        return "'"


class DynamicTester:
    """
    Dynamic security testing using browser automation.

    Requires: playwright (pip install playwright && playwright install)

    Example:
        tester = DynamicTester()
        await tester.init_browser()
        results = await tester.test_url("https://example.com")
        await tester.close()
    """

    def __init__(self, headless: bool = True, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout
        self.browser = None
        self.context = None
        self.page = None
        self.findings: List[DynamicFinding] = []
        self.intercepted_requests: List[Dict] = []
        self.intercepted_responses: List[Dict] = []

    async def init_browser(self, browser_type: str = "chromium"):
        """Initialize browser for testing"""
        try:
            from playwright.async_api import async_playwright

            self.playwright = await async_playwright().start()

            if browser_type == "chromium":
                self.browser = await self.playwright.chromium.launch(headless=self.headless)
            elif browser_type == "firefox":
                self.browser = await self.playwright.firefox.launch(headless=self.headless)
            elif browser_type == "webkit":
                self.browser = await self.playwright.webkit.launch(headless=self.headless)

            self.context = await self.browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )

            self.page = await self.context.new_page()

            # Set up request interception
            await self._setup_interception()

        except ImportError:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install")

    async def _setup_interception(self):
        """Set up network request interception"""
        async def handle_request(request):
            self.intercepted_requests.append({
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data
            })

        async def handle_response(response):
            self.intercepted_responses.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers)
            })

        self.page.on("request", handle_request)
        self.page.on("response", handle_response)

    async def close(self):
        """Close browser and cleanup"""
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()

    async def test_url(self, url: str) -> Dict[str, Any]:
        """
        Run comprehensive dynamic testing on a URL.

        Args:
            url: Target URL

        Returns:
            Test results
        """
        results = {
            "url": url,
            "forms_detected": [],
            "xss_tests": [],
            "reflection_points": [],
            "cookies": [],
            "local_storage": {},
            "session_storage": {},
            "console_errors": [],
            "findings": []
        }

        try:
            # Navigate to page
            await self.page.goto(url, timeout=self.timeout)
            await self.page.wait_for_load_state("networkidle")

            # Detect forms
            results["forms_detected"] = await self._detect_forms()

            # Test for XSS reflection
            results["reflection_points"] = await self._test_reflection(url)

            # Analyze cookies
            results["cookies"] = await self._analyze_cookies()

            # Check storage
            results["local_storage"] = await self._get_local_storage()
            results["session_storage"] = await self._get_session_storage()

            # Get console errors (may reveal issues)
            results["console_errors"] = await self._get_console_errors()

            # DOM-based vulnerability checks
            dom_findings = await self._check_dom_vulnerabilities()
            self.findings.extend(dom_findings)

        except Exception as e:
            results["error"] = str(e)

        results["findings"] = [f.to_dict() for f in self.findings]
        return results

    async def _detect_forms(self) -> List[Dict]:
        """Detect all forms on the page"""
        forms = []

        form_elements = await self.page.query_selector_all("form")

        for form in form_elements:
            form_data = {
                "action": await form.get_attribute("action") or "",
                "method": (await form.get_attribute("method") or "GET").upper(),
                "fields": []
            }

            # Get input fields
            inputs = await form.query_selector_all("input, textarea, select")
            for inp in inputs:
                field_info = {
                    "name": await inp.get_attribute("name") or "",
                    "type": await inp.get_attribute("type") or "text",
                    "id": await inp.get_attribute("id") or "",
                    "required": await inp.get_attribute("required") is not None,
                    "autocomplete": await inp.get_attribute("autocomplete") or ""
                }
                form_data["fields"].append(field_info)

            forms.append(form_data)

        return forms

    async def _test_reflection(self, base_url: str) -> List[Dict]:
        """Test for input reflection (potential XSS)"""
        reflection_points = []
        canary = XSSPayloads.get_safe_canary()

        # Get all input fields
        inputs = await self.page.query_selector_all("input[type='text'], input[type='search'], textarea")

        for inp in inputs:
            try:
                name = await inp.get_attribute("name") or await inp.get_attribute("id") or "unknown"

                # Type canary into field
                await inp.fill(canary)

                # Try to submit (look for nearby button)
                form = await inp.evaluate("el => el.form")
                if form:
                    await self.page.keyboard.press("Enter")
                    await self.page.wait_for_load_state("networkidle", timeout=5000)

                    # Check if canary is reflected
                    content = await self.page.content()
                    if canary in content:
                        reflection_points.append({
                            "field": name,
                            "reflected": True,
                            "context": self._detect_reflection_context(content, canary)
                        })

                        self.findings.append(DynamicFinding(
                            title="Input Reflection Detected",
                            severity="medium",
                            finding_type="reflection",
                            url=self.page.url,
                            description=f"User input from field '{name}' is reflected in the response",
                            evidence=f"Canary '{canary}' found in page content",
                            remediation="Ensure proper output encoding based on context"
                        ))

                    # Navigate back
                    await self.page.goto(base_url, timeout=self.timeout)
                    await self.page.wait_for_load_state("networkidle")

            except Exception:
                pass

        return reflection_points

    def _detect_reflection_context(self, content: str, canary: str) -> str:
        """Detect the context where input is reflected"""
        idx = content.find(canary)
        if idx == -1:
            return "unknown"

        # Get surrounding context
        start = max(0, idx - 50)
        end = min(len(content), idx + len(canary) + 50)
        context = content[start:end]

        # Determine context type
        if f'"{canary}"' in context or f"'{canary}'" in context:
            if 'href=' in context or 'src=' in context:
                return "attribute_value"
            return "javascript_string"
        elif f'>{canary}<' in context:
            return "html_content"
        elif f'<{canary}' in context or f'{canary}>' in context:
            return "html_tag"
        elif 'script' in context.lower():
            return "javascript"
        else:
            return "other"

    async def _analyze_cookies(self) -> List[Dict]:
        """Analyze cookie security"""
        cookies = await self.context.cookies()
        analyzed = []

        for cookie in cookies:
            cookie_info = {
                "name": cookie["name"],
                "domain": cookie.get("domain", ""),
                "path": cookie.get("path", "/"),
                "secure": cookie.get("secure", False),
                "httpOnly": cookie.get("httpOnly", False),
                "sameSite": cookie.get("sameSite", "None"),
                "expires": cookie.get("expires", -1)
            }
            analyzed.append(cookie_info)

            # Check for security issues
            if "session" in cookie["name"].lower() or "token" in cookie["name"].lower():
                if not cookie.get("secure"):
                    self.findings.append(DynamicFinding(
                        title="Session Cookie Missing Secure Flag",
                        severity="medium",
                        finding_type="cookie_security",
                        url=self.page.url,
                        description=f"Cookie '{cookie['name']}' lacks Secure flag",
                        remediation="Add Secure flag to prevent transmission over HTTP"
                    ))

                if not cookie.get("httpOnly"):
                    self.findings.append(DynamicFinding(
                        title="Session Cookie Missing HttpOnly Flag",
                        severity="medium",
                        finding_type="cookie_security",
                        url=self.page.url,
                        description=f"Cookie '{cookie['name']}' lacks HttpOnly flag",
                        remediation="Add HttpOnly flag to prevent JavaScript access"
                    ))

        return analyzed

    async def _get_local_storage(self) -> Dict:
        """Get localStorage contents"""
        try:
            storage = await self.page.evaluate("() => Object.fromEntries(Object.entries(localStorage))")
            return storage or {}
        except Exception:
            return {}

    async def _get_session_storage(self) -> Dict:
        """Get sessionStorage contents"""
        try:
            storage = await self.page.evaluate("() => Object.fromEntries(Object.entries(sessionStorage))")
            return storage or {}
        except Exception:
            return {}

    async def _get_console_errors(self) -> List[str]:
        """Collect console errors (may reveal debug info)"""
        errors = []

        def handle_console(msg):
            if msg.type == "error":
                errors.append(msg.text)

        self.page.on("console", handle_console)

        # Wait a moment to collect errors
        await asyncio.sleep(1)

        return errors

    async def _check_dom_vulnerabilities(self) -> List[DynamicFinding]:
        """Check for DOM-based vulnerabilities"""
        findings = []

        # Check for dangerous sinks
        dangerous_patterns = await self.page.evaluate("""() => {
            const findings = [];

            // Check for innerHTML usage
            const scripts = document.querySelectorAll('script');
            scripts.forEach(s => {
                if (s.textContent.includes('innerHTML') ||
                    s.textContent.includes('outerHTML') ||
                    s.textContent.includes('document.write')) {
                    findings.push({
                        type: 'dangerous_sink',
                        pattern: 'innerHTML/document.write detected'
                    });
                }
            });

            // Check for eval usage
            scripts.forEach(s => {
                if (s.textContent.includes('eval(') ||
                    s.textContent.includes('Function(') ||
                    s.textContent.includes('setTimeout(') && s.textContent.includes('string')) {
                    findings.push({
                        type: 'eval_usage',
                        pattern: 'eval/Function constructor detected'
                    });
                }
            });

            // Check for postMessage handlers without origin check
            if (document.documentElement.outerHTML.includes('addEventListener') &&
                document.documentElement.outerHTML.includes('message')) {
                findings.push({
                    type: 'postmessage',
                    pattern: 'postMessage handler detected - check for origin validation'
                });
            }

            return findings;
        }""")

        for pattern in dangerous_patterns:
            findings.append(DynamicFinding(
                title=f"Potential DOM Vulnerability: {pattern['type']}",
                severity="low",
                finding_type="dom_vulnerability",
                url=self.page.url,
                description=pattern['pattern'],
                remediation="Review code for proper input validation and output encoding"
            ))

        return findings

    async def test_form_xss(self, form_selector: str, field_name: str) -> List[DynamicFinding]:
        """
        Test a specific form field for XSS.

        Args:
            form_selector: CSS selector for form
            field_name: Name of field to test

        Returns:
            XSS findings
        """
        findings = []
        payloads = XSSPayloads.BASIC[:5]  # Use subset for speed

        for payload in payloads:
            try:
                # Find and fill field
                field = await self.page.query_selector(f"{form_selector} [name='{field_name}']")
                if not field:
                    continue

                await field.fill(payload)

                # Submit form
                await self.page.keyboard.press("Enter")
                await self.page.wait_for_load_state("networkidle", timeout=5000)

                # Check for XSS indicators
                content = await self.page.content()

                # Check if payload executed (alert would be caught by dialog handler)
                if payload in content:
                    # Check if it's in a dangerous context
                    if self._detect_reflection_context(content, payload) in ["javascript", "html_content"]:
                        findings.append(DynamicFinding(
                            title="Potential XSS Vulnerability",
                            severity="high",
                            finding_type="xss",
                            url=self.page.url,
                            description=f"XSS payload reflected in dangerous context",
                            evidence=f"Payload: {payload}",
                            remediation="Implement proper output encoding and CSP"
                        ))

                # Go back for next test
                await self.page.go_back()
                await self.page.wait_for_load_state("networkidle")

            except Exception:
                pass

        return findings


class APITester:
    """
    API security testing module.

    Tests REST and GraphQL APIs for:
    - Authentication bypass
    - IDOR/BOLA
    - Rate limiting
    - Mass assignment
    - Improper error handling
    """

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = None
        self.findings: List[DynamicFinding] = []

    def _get_session(self):
        """Lazy load requests session"""
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
        return self.session

    def test_idor(
        self,
        url_template: str,
        id_param: str,
        valid_id: str,
        test_ids: List[str],
        auth_header: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Test for Insecure Direct Object Reference (IDOR).

        Args:
            url_template: URL with {id} placeholder
            id_param: Parameter name for ID
            valid_id: A known valid ID for the authenticated user
            test_ids: IDs to test access to
            auth_header: Authentication header

        Returns:
            IDOR test results
        """
        session = self._get_session()
        results = {
            "tested_ids": [],
            "accessible": [],
            "findings": []
        }

        if auth_header:
            session.headers.update(auth_header)

        # First, establish baseline with valid ID
        valid_url = url_template.replace("{id}", valid_id)
        try:
            baseline = session.get(valid_url, timeout=self.timeout)
            baseline_status = baseline.status_code
            baseline_keys = set(baseline.json().keys()) if baseline.status_code == 200 else set()
        except Exception:
            return {"error": "Could not establish baseline"}

        # Test other IDs
        for test_id in test_ids:
            if test_id == valid_id:
                continue

            test_url = url_template.replace("{id}", test_id)
            results["tested_ids"].append(test_id)

            try:
                resp = session.get(test_url, timeout=self.timeout)

                if resp.status_code == 200:
                    # Check if we got actual data
                    try:
                        data = resp.json()
                        if data and (isinstance(data, dict) and data.keys() or isinstance(data, list) and data):
                            results["accessible"].append({
                                "id": test_id,
                                "url": test_url,
                                "status": resp.status_code,
                                "data_keys": list(data.keys()) if isinstance(data, dict) else "array"
                            })
                    except Exception:
                        pass

            except Exception:
                pass

        # Generate findings
        if results["accessible"]:
            self.findings.append(DynamicFinding(
                title="Insecure Direct Object Reference (IDOR)",
                severity="high",
                finding_type="idor",
                url=url_template,
                description=f"Able to access {len(results['accessible'])} unauthorized resources",
                evidence=json.dumps(results["accessible"][:3]),
                remediation="Implement proper authorization checks for all object access"
            ))

        results["findings"] = [f.to_dict() for f in self.findings]
        return results

    def test_mass_assignment(
        self,
        url: str,
        method: str,
        base_data: Dict,
        extra_fields: List[str],
        auth_header: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Test for mass assignment vulnerability.

        Args:
            url: API endpoint
            method: HTTP method (POST, PUT, PATCH)
            base_data: Normal request data
            extra_fields: Fields to try injecting (e.g., ['role', 'is_admin', 'credits'])
            auth_header: Authentication header

        Returns:
            Mass assignment test results
        """
        session = self._get_session()
        results = {
            "url": url,
            "method": method,
            "tested_fields": [],
            "accepted_fields": [],
            "findings": []
        }

        if auth_header:
            session.headers.update(auth_header)

        # Dangerous values to try injecting
        injection_values = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "isAdmin": True,
            "is_staff": True,
            "is_superuser": True,
            "permissions": ["admin", "write", "delete"],
            "credits": 999999,
            "balance": 999999,
            "verified": True,
            "email_verified": True,
            "status": "admin",
            "type": "admin",
            "level": 99,
        }

        for field in extra_fields:
            results["tested_fields"].append(field)

            # Create payload with extra field
            test_data = base_data.copy()
            test_data[field] = injection_values.get(field, "injected_value")

            try:
                if method.upper() == "POST":
                    resp = session.post(url, json=test_data, timeout=self.timeout)
                elif method.upper() == "PUT":
                    resp = session.put(url, json=test_data, timeout=self.timeout)
                elif method.upper() == "PATCH":
                    resp = session.patch(url, json=test_data, timeout=self.timeout)
                else:
                    continue

                # Check if field was accepted
                if resp.status_code in [200, 201]:
                    try:
                        response_data = resp.json()
                        if field in str(response_data):
                            results["accepted_fields"].append({
                                "field": field,
                                "value": test_data[field],
                                "response_status": resp.status_code
                            })
                    except Exception:
                        pass

            except Exception:
                pass

        # Generate findings
        if results["accepted_fields"]:
            self.findings.append(DynamicFinding(
                title="Mass Assignment Vulnerability",
                severity="high",
                finding_type="mass_assignment",
                url=url,
                description=f"API accepts unexpected fields: {[f['field'] for f in results['accepted_fields']]}",
                evidence=json.dumps(results["accepted_fields"]),
                remediation="Implement strict input validation and whitelist allowed fields"
            ))

        results["findings"] = [f.to_dict() for f in self.findings]
        return results

    def test_verb_tampering(
        self,
        url: str,
        auth_header: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Test for HTTP verb tampering vulnerabilities.

        Args:
            url: API endpoint
            auth_header: Authentication header

        Returns:
            Verb tampering test results
        """
        session = self._get_session()
        results = {
            "url": url,
            "methods_tested": [],
            "unexpected_responses": [],
            "findings": []
        }

        if auth_header:
            session.headers.update(auth_header)

        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

        for method in methods:
            results["methods_tested"].append(method)

            try:
                resp = session.request(method, url, timeout=self.timeout)

                if resp.status_code not in [404, 405]:
                    results["unexpected_responses"].append({
                        "method": method,
                        "status": resp.status_code,
                        "content_length": len(resp.text)
                    })

                    # TRACE is especially dangerous
                    if method == "TRACE" and resp.status_code == 200:
                        self.findings.append(DynamicFinding(
                            title="HTTP TRACE Method Enabled",
                            severity="medium",
                            finding_type="verb_tampering",
                            url=url,
                            description="TRACE method is enabled, potential for XST attacks",
                            remediation="Disable TRACE method on the server"
                        ))

            except Exception:
                pass

        results["findings"] = [f.to_dict() for f in self.findings]
        return results


# Export all classes
__all__ = [
    "DynamicFinding",
    "FormField",
    "DetectedForm",
    "XSSPayloads",
    "SQLiPayloads",
    "DynamicTester",
    "APITester",
]
