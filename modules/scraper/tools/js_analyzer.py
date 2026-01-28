"""
JavaScript Security Analyzer
============================

Deep analysis of JavaScript files for security-relevant information.
Extracts endpoints, secrets, API keys, and other sensitive data.

Author: DeadMan Security Research
License: MIT
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

# Try to import jsbeautifier, provide fallback
try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False
    logging.warning("jsbeautifier not installed. Install with: pip install jsbeautifier")

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(Enum):
    """Types of findings."""
    SECRET = "secret"
    ENDPOINT = "endpoint"
    INTERNAL_URL = "internal_url"
    COMMENT = "comment"
    DEBUG_CODE = "debug_code"
    SENSITIVE_FUNCTION = "sensitive_function"
    HARDCODED_CREDENTIAL = "hardcoded_credential"
    SOURCE_MAP = "source_map"
    WEBPACK_CHUNK = "webpack_chunk"


@dataclass
class JSFinding:
    """Represents a security-relevant finding in JavaScript."""
    type: FindingType
    severity: FindingSeverity
    value: str
    pattern_name: str = ""
    line_number: Optional[int] = None
    column: Optional[int] = None
    context: str = ""
    confidence: float = 0.8
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "value": self.value,
            "pattern_name": self.pattern_name,
            "line_number": self.line_number,
            "context": self.context,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


@dataclass
class JSAnalysisReport:
    """Complete analysis report for a JavaScript file."""
    url: str
    file_hash: str
    size: int
    beautified_size: int = 0
    findings: list[JSFinding] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    webpack_chunks: list[str] = field(default_factory=list)
    framework_detected: str = ""
    analysis_time: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def secret_count(self) -> int:
        return sum(1 for f in self.findings if f.type == FindingType.SECRET)

    @property
    def endpoint_count(self) -> int:
        return sum(1 for f in self.findings if f.type == FindingType.ENDPOINT)

    @property
    def severity_summary(self) -> dict[str, int]:
        summary = {s.value: 0 for s in FindingSeverity}
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "file_hash": self.file_hash,
            "size": self.size,
            "beautified_size": self.beautified_size,
            "finding_count": len(self.findings),
            "secret_count": self.secret_count,
            "endpoint_count": self.endpoint_count,
            "severity_summary": self.severity_summary,
            "findings": [f.to_dict() for f in self.findings],
            "endpoints": self.endpoints,
            "domains": self.domains,
            "source_maps": self.source_maps,
            "webpack_chunks": self.webpack_chunks,
            "framework_detected": self.framework_detected,
            "analysis_time": self.analysis_time,
            "errors": self.errors
        }


class JSSecurityAnalyzer:
    """
    Analyzes JavaScript files for security vulnerabilities and sensitive data.

    Features:
    - Secret detection (API keys, tokens, passwords)
    - Endpoint extraction
    - Source map detection
    - Webpack bundle analysis
    - Framework detection
    - Debug code identification
    """

    # Secret patterns with severity and confidence
    SECRET_PATTERNS: dict[str, tuple[str, FindingSeverity, float]] = {
        # Cloud Providers
        "AWS Access Key ID": (r"AKIA[0-9A-Z]{16}", FindingSeverity.CRITICAL, 0.95),
        "AWS Secret Key": (r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])", FindingSeverity.CRITICAL, 0.6),
        "AWS MWS Key": (r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", FindingSeverity.CRITICAL, 0.95),
        "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", FindingSeverity.MEDIUM, 0.9),
        "Google OAuth ID": (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", FindingSeverity.MEDIUM, 0.95),
        "Azure Storage Key": (r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}", FindingSeverity.CRITICAL, 0.95),

        # Payment Providers
        "Stripe Secret Key": (r"sk_live_[0-9a-zA-Z]{24,}", FindingSeverity.CRITICAL, 0.98),
        "Stripe Publishable Key": (r"pk_live_[0-9a-zA-Z]{24,}", FindingSeverity.LOW, 0.98),
        "Stripe Test Secret": (r"sk_test_[0-9a-zA-Z]{24,}", FindingSeverity.LOW, 0.98),
        "PayPal Access Token": (r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", FindingSeverity.CRITICAL, 0.95),
        "Square Access Token": (r"sq0atp-[0-9A-Za-z\-_]{22}", FindingSeverity.CRITICAL, 0.95),
        "Square OAuth Secret": (r"sq0csp-[0-9A-Za-z\-_]{43}", FindingSeverity.CRITICAL, 0.95),

        # Version Control
        "GitHub Token": (r"ghp_[0-9a-zA-Z]{36}", FindingSeverity.HIGH, 0.98),
        "GitHub OAuth": (r"gho_[0-9a-zA-Z]{36}", FindingSeverity.HIGH, 0.98),
        "GitHub App Token": (r"ghu_[0-9a-zA-Z]{36}", FindingSeverity.HIGH, 0.98),
        "GitHub Refresh Token": (r"ghr_[0-9a-zA-Z]{36}", FindingSeverity.HIGH, 0.98),
        "GitLab Token": (r"glpat-[0-9a-zA-Z\-_]{20}", FindingSeverity.HIGH, 0.95),

        # Communication
        "Slack Token": (r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*", FindingSeverity.HIGH, 0.95),
        "Slack Webhook": (r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}", FindingSeverity.HIGH, 0.98),
        "Discord Webhook": (r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+", FindingSeverity.HIGH, 0.98),
        "Discord Bot Token": (r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}", FindingSeverity.HIGH, 0.85),
        "Twilio API Key": (r"SK[0-9a-fA-F]{32}", FindingSeverity.HIGH, 0.9),
        "Twilio Account SID": (r"AC[a-zA-Z0-9_\-]{32}", FindingSeverity.MEDIUM, 0.9),
        "SendGrid API Key": (r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", FindingSeverity.HIGH, 0.98),

        # Authentication
        "JWT Token": (r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*", FindingSeverity.MEDIUM, 0.95),
        "Basic Auth Header": (r"Basic [A-Za-z0-9+/=]{10,}", FindingSeverity.MEDIUM, 0.8),
        "Bearer Token": (r"Bearer [A-Za-z0-9\-_\.~\+\/]+=*", FindingSeverity.MEDIUM, 0.7),

        # Database
        "MongoDB URI": (r"mongodb(\+srv)?://[^\s\"']+", FindingSeverity.CRITICAL, 0.9),
        "PostgreSQL URI": (r"postgres(ql)?://[^\s\"']+", FindingSeverity.CRITICAL, 0.9),
        "MySQL URI": (r"mysql://[^\s\"']+", FindingSeverity.CRITICAL, 0.9),
        "Redis URI": (r"redis://[^\s\"']+", FindingSeverity.HIGH, 0.9),

        # Private Keys
        "RSA Private Key": (r"-----BEGIN RSA PRIVATE KEY-----", FindingSeverity.CRITICAL, 0.99),
        "EC Private Key": (r"-----BEGIN EC PRIVATE KEY-----", FindingSeverity.CRITICAL, 0.99),
        "OpenSSH Private Key": (r"-----BEGIN OPENSSH PRIVATE KEY-----", FindingSeverity.CRITICAL, 0.99),
        "PGP Private Key": (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", FindingSeverity.CRITICAL, 0.99),

        # Other Services
        "Mailgun API Key": (r"key-[0-9a-zA-Z]{32}", FindingSeverity.HIGH, 0.85),
        "Mailchimp API Key": (r"[0-9a-f]{32}-us[0-9]{1,2}", FindingSeverity.MEDIUM, 0.9),
        "Heroku API Key": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", FindingSeverity.MEDIUM, 0.5),
        "Firebase URL": (r"https://[a-z0-9-]+\.firebaseio\.com", FindingSeverity.LOW, 0.9),
        "Algolia API Key": (r"[a-z0-9]{32}", FindingSeverity.LOW, 0.3),

        # Generic Patterns
        "Password in URL": (r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}", FindingSeverity.HIGH, 0.85),
        "Generic API Key": (r"api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", FindingSeverity.MEDIUM, 0.7),
        "Generic Secret": (r"secret['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", FindingSeverity.MEDIUM, 0.7),
        "Generic Token": (r"token['\"]?\s*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]", FindingSeverity.MEDIUM, 0.6),
    }

    # Endpoint extraction patterns
    ENDPOINT_PATTERNS: list[tuple[str, str]] = [
        (r'["\']/(api|v[0-9]+)/[^"\']*["\']', "API Path"),
        (r'fetch\s*\(\s*["\']([^"\']+)["\']', "Fetch Call"),
        (r'axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']', "Axios Call"),
        (r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', "jQuery Ajax"),
        (r'XMLHttpRequest[^;]*open\s*\(\s*["\'][^"\']+["\'],\s*["\']([^"\']+)["\']', "XHR Open"),
        (r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']', "WebSocket"),
        (r'\.send\s*\(\s*["\']([^"\']+)["\']', "Send Call"),
        (r'href\s*=\s*["\']/(api|internal|admin)[^"\']*["\']', "Href API"),
        (r'action\s*=\s*["\']([^"\']+)["\']', "Form Action"),
        (r'@(Get|Post|Put|Delete|Patch)Mapping\s*\(\s*["\']([^"\']+)["\']', "Spring Mapping"),
        (r'router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "Express Router"),
        (r'app\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', "Express App"),
    ]

    # Interesting comment patterns
    COMMENT_PATTERNS: list[tuple[str, FindingSeverity]] = [
        (r"//\s*TODO:?\s*.*password", FindingSeverity.MEDIUM),
        (r"//\s*FIXME:?\s*.*security", FindingSeverity.MEDIUM),
        (r"//\s*HACK:?\s*", FindingSeverity.LOW),
        (r"//\s*XXX:?\s*", FindingSeverity.LOW),
        (r"//\s*BUG:?\s*", FindingSeverity.LOW),
        (r"/\*[\s\S]*?(password|secret|key|token|credential)[\s\S]*?\*/", FindingSeverity.MEDIUM),
        (r"//.*admin.*bypass", FindingSeverity.HIGH),
        (r"//.*debug.*mode", FindingSeverity.LOW),
        (r"//.*temporary.*fix", FindingSeverity.LOW),
    ]

    # Debug/development code patterns
    DEBUG_PATTERNS: list[tuple[str, str]] = [
        (r"console\.(log|debug|info|warn|error)\s*\(", "Console Output"),
        (r"debugger\s*;", "Debugger Statement"),
        (r"alert\s*\(", "Alert Statement"),
        (r"document\.write\s*\(", "Document Write"),
        (r"eval\s*\(", "Eval Usage"),
        (r"innerHTML\s*=", "InnerHTML Assignment"),
        (r"\.innerText\s*=.*\+", "Dynamic Text Assignment"),
    ]

    # Framework detection patterns
    FRAMEWORK_PATTERNS: dict[str, str] = {
        "React": r"React\.|ReactDOM|createElement|useState|useEffect",
        "Angular": r"@angular|ng-|ngIf|ngFor|\$scope",
        "Vue": r"Vue\.|v-if|v-for|v-model|createApp",
        "Next.js": r"next/|_next/|__NEXT_DATA__|getServerSideProps",
        "Nuxt": r"nuxt|__NUXT__|asyncData",
        "Svelte": r"svelte|$$|on:click",
        "jQuery": r"\$\(|jQuery",
        "Webpack": r"webpackJsonp|__webpack_require__|webpackChunk",
        "Vite": r"/@vite/|import\.meta\.hot",
    }

    def __init__(
        self,
        timeout: int = 30,
        max_size: int = 10 * 1024 * 1024,  # 10MB
        beautify: bool = True
    ):
        """
        Initialize JavaScript analyzer.

        Args:
            timeout: HTTP request timeout
            max_size: Maximum file size to analyze
            beautify: Whether to beautify JS before analysis
        """
        self.timeout = timeout
        self.max_size = max_size
        self.beautify = beautify and HAS_JSBEAUTIFIER

    async def analyze_url(self, url: str) -> JSAnalysisReport:
        """
        Fetch and analyze JavaScript from URL.

        Args:
            url: URL of JavaScript file

        Returns:
            JSAnalysisReport with all findings
        """
        import time
        start_time = time.time()

        report = JSAnalysisReport(
            url=url,
            file_hash="",
            size=0
        )

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout)
                ) as response:
                    if response.status != 200:
                        report.errors.append(f"HTTP {response.status}")
                        return report

                    content = await response.text()

            report = self.analyze_content(content, url)

        except asyncio.TimeoutError:
            report.errors.append("Request timeout")
        except Exception as e:
            report.errors.append(str(e))
            logger.error(f"Error analyzing {url}: {e}")

        report.analysis_time = time.time() - start_time
        return report

    def analyze_content(self, content: str, url: str = "") -> JSAnalysisReport:
        """
        Analyze JavaScript content.

        Args:
            content: JavaScript source code
            url: Optional URL for reference

        Returns:
            JSAnalysisReport with all findings
        """
        import time
        start_time = time.time()

        # Calculate hash
        file_hash = hashlib.sha256(content.encode()).hexdigest()

        report = JSAnalysisReport(
            url=url,
            file_hash=file_hash,
            size=len(content)
        )

        # Check size limit
        if len(content) > self.max_size:
            report.errors.append(f"File too large: {len(content)} bytes")
            return report

        # Beautify if enabled
        if self.beautify:
            try:
                options = jsbeautifier.default_options()
                options.indent_size = 2
                options.preserve_newlines = True
                content = jsbeautifier.beautify(content, options)
                report.beautified_size = len(content)
            except Exception as e:
                report.errors.append(f"Beautification failed: {e}")

        # Run all analyses
        report.findings.extend(self._find_secrets(content))
        report.findings.extend(self._find_endpoints(content))
        report.findings.extend(self._find_comments(content))
        report.findings.extend(self._find_debug_code(content))

        # Extract additional info
        report.endpoints = self._extract_endpoints(content)
        report.domains = self._extract_domains(content)
        report.source_maps = self._find_source_maps(content)
        report.webpack_chunks = self._find_webpack_chunks(content)
        report.framework_detected = self._detect_framework(content)

        report.analysis_time = time.time() - start_time
        return report

    def _find_secrets(self, content: str) -> list[JSFinding]:
        """Find secrets in JavaScript content."""
        findings = []

        for name, (pattern, severity, confidence) in self.SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content, re.IGNORECASE):
                # Skip if in comment
                line_start = content.rfind('\n', 0, match.start()) + 1
                line = content[line_start:match.end()]
                if line.strip().startswith('//'):
                    continue

                # Get line number
                line_number = content[:match.start()].count('\n') + 1

                # Mask the secret value for safety
                value = match.group()
                if len(value) > 10:
                    masked_value = value[:4] + "*" * (len(value) - 8) + value[-4:]
                else:
                    masked_value = value[:2] + "*" * (len(value) - 2)

                findings.append(JSFinding(
                    type=FindingType.SECRET,
                    severity=severity,
                    value=masked_value,
                    pattern_name=name,
                    line_number=line_number,
                    context=self._get_context(content, match.start()),
                    confidence=confidence,
                    metadata={"full_match_length": len(value)}
                ))

        return findings

    def _find_endpoints(self, content: str) -> list[JSFinding]:
        """Find API endpoints in JavaScript content."""
        findings = []
        seen = set()

        for pattern, name in self.ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                # Extract the URL/path
                groups = match.groups()
                endpoint = groups[-1] if groups else match.group()

                # Deduplicate
                if endpoint in seen:
                    continue
                seen.add(endpoint)

                line_number = content[:match.start()].count('\n') + 1

                findings.append(JSFinding(
                    type=FindingType.ENDPOINT,
                    severity=FindingSeverity.INFO,
                    value=endpoint,
                    pattern_name=name,
                    line_number=line_number,
                    context=self._get_context(content, match.start()),
                    confidence=0.9
                ))

        return findings

    def _find_comments(self, content: str) -> list[JSFinding]:
        """Find security-relevant comments."""
        findings = []

        for pattern, severity in self.COMMENT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_number = content[:match.start()].count('\n') + 1

                findings.append(JSFinding(
                    type=FindingType.COMMENT,
                    severity=severity,
                    value=match.group()[:100],  # Truncate long comments
                    pattern_name="Security Comment",
                    line_number=line_number,
                    context=self._get_context(content, match.start()),
                    confidence=0.7
                ))

        return findings

    def _find_debug_code(self, content: str) -> list[JSFinding]:
        """Find debug/development code."""
        findings = []

        for pattern, name in self.DEBUG_PATTERNS:
            for match in re.finditer(pattern, content):
                line_number = content[:match.start()].count('\n') + 1

                findings.append(JSFinding(
                    type=FindingType.DEBUG_CODE,
                    severity=FindingSeverity.LOW,
                    value=match.group(),
                    pattern_name=name,
                    line_number=line_number,
                    context=self._get_context(content, match.start()),
                    confidence=0.8
                ))

        return findings

    def _extract_endpoints(self, content: str) -> list[str]:
        """Extract unique endpoints from content."""
        endpoints = set()

        # API paths
        for match in re.finditer(r'["\']/(api|v[0-9]+|graphql|rest)/[^"\']*["\']', content):
            endpoints.add(match.group().strip("'\""))

        # Fetch/axios calls
        for match in re.finditer(r'(?:fetch|axios[^(]*)\(["\']([^"\']+)["\']', content):
            endpoints.add(match.group(1))

        return sorted(list(endpoints))

    def _extract_domains(self, content: str) -> list[str]:
        """Extract unique domains from content."""
        domains = set()

        for match in re.finditer(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}', content):
            parsed = urlparse(match.group())
            if parsed.netloc:
                domains.add(parsed.netloc)

        return sorted(list(domains))

    def _find_source_maps(self, content: str) -> list[str]:
        """Find source map references."""
        maps = []

        # Inline source map
        for match in re.finditer(r'//# sourceMappingURL=([^\s]+)', content):
            maps.append(match.group(1))

        # Data URL source map
        for match in re.finditer(r'//# sourceMappingURL=data:application/json;base64,([A-Za-z0-9+/=]+)', content):
            maps.append("data:base64 (embedded)")

        return maps

    def _find_webpack_chunks(self, content: str) -> list[str]:
        """Find webpack chunk information."""
        chunks = []

        # webpackChunkName
        for match in re.finditer(r'webpackChunkName:\s*["\']([^"\']+)["\']', content):
            chunks.append(match.group(1))

        # Chunk IDs
        for match in re.finditer(r'webpackJsonp[^(]*\(\s*\[([0-9,\s]+)\]', content):
            chunks.append(f"chunk_ids: {match.group(1)}")

        return chunks

    def _detect_framework(self, content: str) -> str:
        """Detect JavaScript framework/library."""
        for framework, pattern in self.FRAMEWORK_PATTERNS.items():
            if re.search(pattern, content):
                return framework
        return "Unknown"

    def _get_context(self, content: str, position: int, chars: int = 60) -> str:
        """Get surrounding context for a match."""
        start = max(0, position - chars)
        end = min(len(content), position + chars)
        context = content[start:end].replace('\n', ' ').replace('\r', '')
        return context.strip()


async def analyze_multiple_urls(urls: list[str]) -> list[JSAnalysisReport]:
    """Analyze multiple JavaScript URLs concurrently."""
    analyzer = JSSecurityAnalyzer()
    tasks = [analyzer.analyze_url(url) for url in urls]
    return await asyncio.gather(*tasks)


def analyze_directory(directory: Path, pattern: str = "*.js") -> list[JSAnalysisReport]:
    """Analyze all JavaScript files in a directory."""
    analyzer = JSSecurityAnalyzer()
    reports = []

    for js_file in directory.rglob(pattern):
        try:
            content = js_file.read_text(encoding='utf-8', errors='ignore')
            report = analyzer.analyze_content(content, str(js_file))
            reports.append(report)
        except Exception as e:
            logger.error(f"Error analyzing {js_file}: {e}")

    return reports


if __name__ == "__main__":
    # Example usage
    async def main():
        analyzer = JSSecurityAnalyzer()

        # Analyze a sample
        sample_js = """
        const API_KEY = "sk_live_abc123xyz456";
        const endpoint = "/api/v1/users";

        fetch("/api/v2/data")
            .then(r => r.json());

        // TODO: fix security issue with password handling
        console.log("Debug: user logged in");
        """

        report = analyzer.analyze_content(sample_js, "sample.js")

        print(f"Analyzed: {report.url}")
        print(f"Size: {report.size} bytes")
        print(f"Findings: {len(report.findings)}")
        print(f"Secrets: {report.secret_count}")
        print(f"Endpoints: {report.endpoint_count}")
        print(f"Framework: {report.framework_detected}")

        for finding in report.findings:
            print(f"  [{finding.severity.value}] {finding.pattern_name}: {finding.value}")

    asyncio.run(main())
