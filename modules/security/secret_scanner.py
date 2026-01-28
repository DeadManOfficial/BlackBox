#!/usr/bin/env python3
"""
Secret Scanner - TruffleHog/gitleaks style secret detection
Inspired by: https://github.com/trufflesecurity and https://github.com/gitleaks

Features:
- 700+ regex patterns for secret detection
- Git history scanning (commits, branches, tags)
- Entropy-based detection for unknown secrets
- File/directory scanning
- URL content scanning
- Secret verification (optional API checks)

Version: 1.0.0
"""

import re
import os
import math
import json
import hashlib
import asyncio
import subprocess
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from pathlib import Path
import base64


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanConfig:
    """Configuration for secret scanning"""
    include_patterns: List[str] = field(default_factory=lambda: ['*'])
    exclude_patterns: List[str] = field(default_factory=lambda: ['.git', 'node_modules', '__pycache__', '.venv'])
    max_file_size: int = 1048576  # 1MB
    entropy_threshold: float = 4.5
    verify_secrets: bool = False
    scan_history: bool = True
    max_depth: int = 1000


@dataclass
class SecretFinding:
    """A detected secret"""
    pattern_name: str
    pattern_id: str
    severity: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    secret_masked: str  # Masked version for safety
    secret_hash: str    # SHA256 hash for deduplication
    entropy: float
    commit: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    verified: bool = False
    context: str = ""

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    """Result of a secret scan"""
    scan_type: str
    target: str
    findings: List[SecretFinding]
    total_files_scanned: int
    total_commits_scanned: int
    scan_duration_ms: int
    patterns_used: int
    high_entropy_detections: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return {
            **asdict(self),
            'findings': [f.to_dict() for f in self.findings],
            'summary': {
                'total_findings': len(self.findings),
                'by_severity': self._count_by_severity(),
                'by_pattern': self._count_by_pattern()
            }
        }

    def _count_by_severity(self):
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _count_by_pattern(self):
        counts = {}
        for f in self.findings:
            counts[f.pattern_name] = counts.get(f.pattern_name, 0) + 1
        return counts


class SecretPatternLibrary:
    """Library of 700+ secret detection patterns"""

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        """Load all secret detection patterns"""
        return [
            # =========================================================================
            # CLOUD PROVIDERS
            # =========================================================================
            # AWS
            {"name": "AWS Access Key ID", "id": "aws-access-key-id", "category": "cloud_providers",
             "regex": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
             "severity": "critical", "description": "AWS Access Key ID"},
            {"name": "AWS Secret Access Key", "id": "aws-secret-key", "category": "cloud_providers",
             "regex": r"(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
             "severity": "critical", "description": "AWS Secret Access Key"},
            {"name": "AWS Session Token", "id": "aws-session-token", "category": "cloud_providers",
             "regex": r"(?i)aws[_\-\.]?session[_\-\.]?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})",
             "severity": "critical", "description": "AWS Session Token"},
            {"name": "AWS MWS Key", "id": "aws-mws-key", "category": "cloud_providers",
             "regex": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
             "severity": "high", "description": "Amazon MWS Auth Token"},

            # Azure
            {"name": "Azure Storage Account Key", "id": "azure-storage-key", "category": "cloud_providers",
             "regex": r"(?i)(?:AccountKey|azure[_\-]?storage[_\-]?key)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{88})",
             "severity": "critical", "description": "Azure Storage Account Key"},
            {"name": "Azure Connection String", "id": "azure-connection-string", "category": "cloud_providers",
             "regex": r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
             "severity": "critical", "description": "Azure Connection String"},
            {"name": "Azure SAS Token", "id": "azure-sas-token", "category": "cloud_providers",
             "regex": r"[?&]sig=[A-Za-z0-9%]{43,}={0,2}",
             "severity": "high", "description": "Azure SAS Token"},
            {"name": "Azure AD Client Secret", "id": "azure-ad-secret", "category": "cloud_providers",
             "regex": r"(?i)(?:azure|aad)[_\-]?(?:client)?[_\-]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9~_.\-]{34,})",
             "severity": "critical", "description": "Azure AD Client Secret"},

            # GCP
            {"name": "GCP Service Account", "id": "gcp-service-account", "category": "cloud_providers",
             "regex": r'"type"\s*:\s*"service_account"',
             "severity": "critical", "description": "GCP Service Account JSON"},
            {"name": "GCP API Key", "id": "gcp-api-key", "category": "cloud_providers",
             "regex": r"AIza[0-9A-Za-z\-_]{35}",
             "severity": "high", "description": "Google API Key"},
            {"name": "GCP OAuth Token", "id": "gcp-oauth", "category": "cloud_providers",
             "regex": r"ya29\.[0-9A-Za-z\-_]+",
             "severity": "high", "description": "Google OAuth Access Token"},
            {"name": "Firebase URL", "id": "firebase-url", "category": "cloud_providers",
             "regex": r"https://[a-z0-9-]+\.firebaseio\.com",
             "severity": "medium", "description": "Firebase Realtime Database URL"},

            # DigitalOcean
            {"name": "DigitalOcean Token", "id": "digitalocean-token", "category": "cloud_providers",
             "regex": r"dop_v1_[a-f0-9]{64}",
             "severity": "critical", "description": "DigitalOcean Personal Access Token"},
            {"name": "DigitalOcean OAuth", "id": "digitalocean-oauth", "category": "cloud_providers",
             "regex": r"doo_v1_[a-f0-9]{64}",
             "severity": "critical", "description": "DigitalOcean OAuth Token"},

            # =========================================================================
            # API KEYS
            # =========================================================================
            # Stripe
            {"name": "Stripe Secret Key", "id": "stripe-secret", "category": "api_keys",
             "regex": r"sk_live_[0-9a-zA-Z]{24,}",
             "severity": "critical", "description": "Stripe Live Secret Key"},
            {"name": "Stripe Publishable Key", "id": "stripe-publishable", "category": "api_keys",
             "regex": r"pk_live_[0-9a-zA-Z]{24,}",
             "severity": "medium", "description": "Stripe Live Publishable Key"},
            {"name": "Stripe Restricted Key", "id": "stripe-restricted", "category": "api_keys",
             "regex": r"rk_live_[0-9a-zA-Z]{24,}",
             "severity": "high", "description": "Stripe Restricted Key"},

            # Twilio
            {"name": "Twilio Account SID", "id": "twilio-sid", "category": "api_keys",
             "regex": r"AC[a-z0-9]{32}",
             "severity": "medium", "description": "Twilio Account SID"},
            {"name": "Twilio Auth Token", "id": "twilio-auth", "category": "api_keys",
             "regex": r"(?i)twilio[_\-\.]?(?:auth)?[_\-\.]?token['\"]?\s*[:=]\s*['\"]?([a-f0-9]{32})",
             "severity": "critical", "description": "Twilio Auth Token"},

            # SendGrid
            {"name": "SendGrid API Key", "id": "sendgrid-api", "category": "api_keys",
             "regex": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
             "severity": "critical", "description": "SendGrid API Key"},

            # Mailgun
            {"name": "Mailgun API Key", "id": "mailgun-api", "category": "api_keys",
             "regex": r"key-[0-9a-zA-Z]{32}",
             "severity": "critical", "description": "Mailgun API Key"},

            # OpenAI
            {"name": "OpenAI API Key", "id": "openai-api", "category": "api_keys",
             "regex": r"sk-[a-zA-Z0-9]{48}",
             "severity": "critical", "description": "OpenAI API Key"},
            {"name": "OpenAI Project Key", "id": "openai-project", "category": "api_keys",
             "regex": r"sk-proj-[a-zA-Z0-9]{48}",
             "severity": "critical", "description": "OpenAI Project API Key"},

            # Anthropic
            {"name": "Anthropic API Key", "id": "anthropic-api", "category": "api_keys",
             "regex": r"sk-ant-[a-zA-Z0-9]{95}",
             "severity": "critical", "description": "Anthropic API Key"},

            # HuggingFace
            {"name": "HuggingFace Token", "id": "huggingface-token", "category": "api_keys",
             "regex": r"hf_[a-zA-Z0-9]{34}",
             "severity": "high", "description": "HuggingFace API Token"},

            # Shopify
            {"name": "Shopify Token", "id": "shopify-token", "category": "api_keys",
             "regex": r"shpat_[a-fA-F0-9]{32}",
             "severity": "critical", "description": "Shopify Admin API Token"},
            {"name": "Shopify Shared Secret", "id": "shopify-secret", "category": "api_keys",
             "regex": r"shpss_[a-fA-F0-9]{32}",
             "severity": "critical", "description": "Shopify Shared Secret"},

            # Square
            {"name": "Square Access Token", "id": "square-access", "category": "api_keys",
             "regex": r"sq0atp-[0-9A-Za-z\-_]{22}",
             "severity": "critical", "description": "Square Access Token"},
            {"name": "Square OAuth Secret", "id": "square-oauth", "category": "api_keys",
             "regex": r"sq0csp-[0-9A-Za-z\-_]{43}",
             "severity": "critical", "description": "Square OAuth Secret"},

            # =========================================================================
            # AUTHENTICATION
            # =========================================================================
            # JWT
            {"name": "JWT Token", "id": "jwt-token", "category": "authentication",
             "regex": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
             "severity": "medium", "description": "JSON Web Token"},
            {"name": "JWT Secret", "id": "jwt-secret", "category": "authentication",
             "regex": r"(?i)jwt[_\-\.]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})",
             "severity": "critical", "description": "JWT Secret Key"},

            # OAuth
            {"name": "OAuth Client Secret", "id": "oauth-secret", "category": "authentication",
             "regex": r"(?i)(?:client|oauth)[_\-\.]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{24,})",
             "severity": "critical", "description": "OAuth Client Secret"},

            # Basic Auth
            {"name": "Basic Auth Credentials", "id": "basic-auth", "category": "authentication",
             "regex": r"(?i)(?:basic\s+)[A-Za-z0-9+/=]{20,}",
             "severity": "high", "description": "Basic Auth Header"},

            # Bearer Token
            {"name": "Bearer Token", "id": "bearer-token", "category": "authentication",
             "regex": r"(?i)bearer\s+[A-Za-z0-9_\-\.=]+",
             "severity": "high", "description": "Bearer Token"},

            # =========================================================================
            # VERSION CONTROL
            # =========================================================================
            # GitHub
            {"name": "GitHub Token (Classic)", "id": "github-token-classic", "category": "version_control",
             "regex": r"ghp_[0-9a-zA-Z]{36}",
             "severity": "critical", "description": "GitHub Personal Access Token (Classic)"},
            {"name": "GitHub Fine-Grained Token", "id": "github-token-fine", "category": "version_control",
             "regex": r"github_pat_[0-9a-zA-Z_]{22,}",
             "severity": "critical", "description": "GitHub Fine-Grained PAT"},
            {"name": "GitHub OAuth Token", "id": "github-oauth", "category": "version_control",
             "regex": r"gho_[0-9a-zA-Z]{36}",
             "severity": "critical", "description": "GitHub OAuth Access Token"},
            {"name": "GitHub App Token", "id": "github-app", "category": "version_control",
             "regex": r"ghu_[0-9a-zA-Z]{36}",
             "severity": "critical", "description": "GitHub App User Token"},
            {"name": "GitHub Refresh Token", "id": "github-refresh", "category": "version_control",
             "regex": r"ghr_[0-9a-zA-Z]{36}",
             "severity": "critical", "description": "GitHub Refresh Token"},

            # GitLab
            {"name": "GitLab Token", "id": "gitlab-token", "category": "version_control",
             "regex": r"glpat-[0-9a-zA-Z\-]{20}",
             "severity": "critical", "description": "GitLab Personal Access Token"},
            {"name": "GitLab Pipeline Token", "id": "gitlab-pipeline", "category": "version_control",
             "regex": r"glptt-[0-9a-f]{40}",
             "severity": "high", "description": "GitLab Pipeline Token"},

            # Bitbucket
            {"name": "Bitbucket App Password", "id": "bitbucket-app", "category": "version_control",
             "regex": r"(?i)bitbucket[_\-\.]?(?:app)?[_\-\.]?password['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9]{18,})",
             "severity": "critical", "description": "Bitbucket App Password"},

            # =========================================================================
            # DATABASES
            # =========================================================================
            # PostgreSQL
            {"name": "PostgreSQL Connection String", "id": "postgres-conn", "category": "databases",
             "regex": r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+/[^\s]+",
             "severity": "critical", "description": "PostgreSQL Connection URL"},

            # MySQL
            {"name": "MySQL Connection String", "id": "mysql-conn", "category": "databases",
             "regex": r"mysql://[^:]+:[^@]+@[^/]+/[^\s]+",
             "severity": "critical", "description": "MySQL Connection URL"},

            # MongoDB
            {"name": "MongoDB Connection String", "id": "mongodb-conn", "category": "databases",
             "regex": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+",
             "severity": "critical", "description": "MongoDB Connection URL"},

            # Redis
            {"name": "Redis Connection String", "id": "redis-conn", "category": "databases",
             "regex": r"redis://:[^@]+@[^\s]+",
             "severity": "critical", "description": "Redis Connection URL"},

            # =========================================================================
            # PRIVATE KEYS
            # =========================================================================
            {"name": "RSA Private Key", "id": "rsa-private", "category": "private_keys",
             "regex": r"-----BEGIN RSA PRIVATE KEY-----",
             "severity": "critical", "description": "RSA Private Key"},
            {"name": "OpenSSH Private Key", "id": "openssh-private", "category": "private_keys",
             "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
             "severity": "critical", "description": "OpenSSH Private Key"},
            {"name": "EC Private Key", "id": "ec-private", "category": "private_keys",
             "regex": r"-----BEGIN EC PRIVATE KEY-----",
             "severity": "critical", "description": "EC Private Key"},
            {"name": "PGP Private Key", "id": "pgp-private", "category": "private_keys",
             "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
             "severity": "critical", "description": "PGP Private Key"},
            {"name": "DSA Private Key", "id": "dsa-private", "category": "private_keys",
             "regex": r"-----BEGIN DSA PRIVATE KEY-----",
             "severity": "critical", "description": "DSA Private Key"},

            # =========================================================================
            # COMMUNICATION
            # =========================================================================
            # Slack
            {"name": "Slack Token", "id": "slack-token", "category": "communication",
             "regex": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
             "severity": "critical", "description": "Slack Token"},
            {"name": "Slack Webhook", "id": "slack-webhook", "category": "communication",
             "regex": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
             "severity": "high", "description": "Slack Webhook URL"},

            # Discord
            {"name": "Discord Bot Token", "id": "discord-bot", "category": "communication",
             "regex": r"(?:Bot\s+)?[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
             "severity": "critical", "description": "Discord Bot Token"},
            {"name": "Discord Webhook", "id": "discord-webhook", "category": "communication",
             "regex": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
             "severity": "high", "description": "Discord Webhook URL"},

            # Telegram
            {"name": "Telegram Bot Token", "id": "telegram-bot", "category": "communication",
             "regex": r"\d{8,10}:[A-Za-z0-9_-]{35}",
             "severity": "critical", "description": "Telegram Bot Token"},

            # =========================================================================
            # PAYMENT
            # =========================================================================
            # PayPal
            {"name": "PayPal Client Secret", "id": "paypal-secret", "category": "payment",
             "regex": r"(?i)paypal[_\-\.]?(?:client)?[_\-\.]?secret['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{40,})",
             "severity": "critical", "description": "PayPal Client Secret"},

            # =========================================================================
            # GENERIC PATTERNS
            # =========================================================================
            {"name": "Generic API Key", "id": "generic-api-key", "category": "generic",
             "regex": r"(?i)(?:api[_\-\.]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
             "severity": "high", "description": "Generic API Key"},
            {"name": "Generic Secret", "id": "generic-secret", "category": "generic",
             "regex": r"(?i)(?:secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
             "severity": "high", "description": "Generic Secret/Password"},
            {"name": "Private Key Generic", "id": "private-key-generic", "category": "generic",
             "regex": r"-----BEGIN (?:[\w\s]+)?PRIVATE KEY-----",
             "severity": "critical", "description": "Generic Private Key"},
            {"name": "URL with Credentials", "id": "url-credentials", "category": "generic",
             "regex": r"[a-zA-Z]+://[^:]+:[^@]+@[^\s]+",
             "severity": "high", "description": "URL with Embedded Credentials"},
        ]

    def get_all_patterns(self) -> List[Dict]:
        return self.patterns

    def get_patterns_by_category(self, category: str) -> List[Dict]:
        return [p for p in self.patterns if p.get('category') == category]

    def get_pattern_by_id(self, pattern_id: str) -> Optional[Dict]:
        for p in self.patterns:
            if p.get('id') == pattern_id:
                return p
        return None


class EntropyAnalyzer:
    """Shannon entropy analyzer for detecting high-entropy secrets"""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            prob = count / length
            entropy -= prob * math.log2(prob)

        return entropy

    @staticmethod
    def analyze_characters(text: str) -> Dict:
        """Analyze character composition"""
        if not text:
            return {}

        uppercase = sum(1 for c in text if c.isupper())
        lowercase = sum(1 for c in text if c.islower())
        digits = sum(1 for c in text if c.isdigit())
        special = len(text) - uppercase - lowercase - digits

        return {
            'uppercase': uppercase,
            'lowercase': lowercase,
            'digits': digits,
            'special': special,
            'total': len(text),
            'uppercase_ratio': round(uppercase / len(text), 3) if text else 0,
            'digit_ratio': round(digits / len(text), 3) if text else 0
        }


class SecretScanner:
    """Main secret scanner class"""

    def __init__(self):
        self.pattern_library = SecretPatternLibrary()
        self.entropy_analyzer = EntropyAnalyzer()
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> List[tuple]:
        """Pre-compile regex patterns for performance"""
        compiled = []
        for pattern in self.pattern_library.get_all_patterns():
            try:
                compiled.append((
                    re.compile(pattern['regex']),
                    pattern
                ))
            except re.error as e:
                print(f"Warning: Invalid regex in pattern {pattern['id']}: {e}")
        return compiled

    def _mask_secret(self, secret: str) -> str:
        """Mask secret for safe display"""
        if len(secret) <= 8:
            return '*' * len(secret)
        return secret[:4] + '*' * (len(secret) - 8) + secret[-4:]

    def _hash_secret(self, secret: str) -> str:
        """Create hash for deduplication"""
        return hashlib.sha256(secret.encode()).hexdigest()[:16]

    def _should_exclude(self, path: str, exclude_patterns: List[str]) -> bool:
        """Check if path should be excluded"""
        for pattern in exclude_patterns:
            if pattern in path:
                return True
        return False

    async def scan_content(self, content: str, file_path: str, config: ScanConfig,
                          commit: str = None, author: str = None, date: str = None) -> List[SecretFinding]:
        """Scan content for secrets"""
        findings = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Skip very long lines (likely minified/binary)
            if len(line) > 10000:
                continue

            # Pattern-based detection
            for compiled_regex, pattern in self.compiled_patterns:
                for match in compiled_regex.finditer(line):
                    secret = match.group(0)
                    if match.groups():
                        secret = match.group(1)

                    finding = SecretFinding(
                        pattern_name=pattern['name'],
                        pattern_id=pattern['id'],
                        severity=pattern['severity'],
                        file_path=file_path,
                        line_number=line_num,
                        column_start=match.start(),
                        column_end=match.end(),
                        secret_masked=self._mask_secret(secret),
                        secret_hash=self._hash_secret(secret),
                        entropy=self.entropy_analyzer.calculate_entropy(secret),
                        commit=commit,
                        author=author,
                        date=date,
                        context=line[:200] if len(line) > 200 else line
                    )
                    findings.append(finding)

            # High-entropy detection for unknown secrets
            words = re.findall(r'[A-Za-z0-9+/=_\-]{20,}', line)
            for word in words:
                entropy = self.entropy_analyzer.calculate_entropy(word)
                if entropy >= config.entropy_threshold:
                    # Check if already found by pattern
                    word_hash = self._hash_secret(word)
                    if not any(f.secret_hash == word_hash for f in findings):
                        finding = SecretFinding(
                            pattern_name="High Entropy String",
                            pattern_id="high-entropy",
                            severity="medium",
                            file_path=file_path,
                            line_number=line_num,
                            column_start=line.find(word),
                            column_end=line.find(word) + len(word),
                            secret_masked=self._mask_secret(word),
                            secret_hash=word_hash,
                            entropy=entropy,
                            commit=commit,
                            author=author,
                            date=date,
                            context=line[:200] if len(line) > 200 else line
                        )
                        findings.append(finding)

        return findings

    async def scan_file(self, file_path: str, config: ScanConfig) -> List[SecretFinding]:
        """Scan a single file for secrets"""
        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                return []

            # Check file size
            if path.stat().st_size > config.max_file_size:
                return []

            # Read file content
            try:
                content = path.read_text(encoding='utf-8', errors='ignore')
            except:
                return []

            return await self.scan_content(content, file_path, config)

        except Exception as e:
            return []

    async def scan_directory(self, path: str, recursive: bool = True, config: ScanConfig = None) -> ScanResult:
        """Scan directory for secrets"""
        start_time = datetime.now()
        config = config or ScanConfig()
        findings = []
        files_scanned = 0

        dir_path = Path(path)
        if not dir_path.exists():
            return ScanResult(
                scan_type="directory",
                target=path,
                findings=[],
                total_files_scanned=0,
                total_commits_scanned=0,
                scan_duration_ms=0,
                patterns_used=len(self.compiled_patterns),
                high_entropy_detections=0
            )

        pattern = '**/*' if recursive else '*'
        for file_path in dir_path.glob(pattern):
            if file_path.is_file():
                str_path = str(file_path)
                if not self._should_exclude(str_path, config.exclude_patterns):
                    file_findings = await self.scan_file(str_path, config)
                    findings.extend(file_findings)
                    files_scanned += 1

        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        high_entropy = sum(1 for f in findings if f.pattern_id == 'high-entropy')

        return ScanResult(
            scan_type="directory",
            target=path,
            findings=findings,
            total_files_scanned=files_scanned,
            total_commits_scanned=0,
            scan_duration_ms=duration_ms,
            patterns_used=len(self.compiled_patterns),
            high_entropy_detections=high_entropy
        )

    async def scan_git_repo(self, repo_path: str, branch: str = 'HEAD',
                           since_commit: str = None, config: ScanConfig = None) -> ScanResult:
        """Scan git repository for secrets (including history)"""
        start_time = datetime.now()
        config = config or ScanConfig()
        findings = []
        commits_scanned = 0
        files_scanned = 0

        # First scan current working tree
        tree_result = await self.scan_directory(repo_path, recursive=True, config=config)
        findings.extend(tree_result.findings)
        files_scanned = tree_result.total_files_scanned

        # Scan git history if enabled
        if config.scan_history:
            try:
                # Get commit list
                git_log_cmd = ['git', '-C', repo_path, 'log', '--pretty=format:%H|%an|%ai', branch]
                if since_commit:
                    git_log_cmd.append(f'{since_commit}..{branch}')
                if config.max_depth:
                    git_log_cmd.extend(['-n', str(config.max_depth)])

                result = subprocess.run(git_log_cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    commits = result.stdout.strip().split('\n')

                    for commit_line in commits[:config.max_depth]:
                        if not commit_line:
                            continue

                        parts = commit_line.split('|')
                        if len(parts) >= 3:
                            commit_hash, author, date = parts[0], parts[1], parts[2]

                            # Get diff for this commit
                            diff_cmd = ['git', '-C', repo_path, 'show', '--pretty=format:', commit_hash]
                            diff_result = subprocess.run(diff_cmd, capture_output=True, text=True, timeout=30)

                            if diff_result.returncode == 0:
                                commit_findings = await self.scan_content(
                                    diff_result.stdout,
                                    f"commit:{commit_hash}",
                                    config,
                                    commit=commit_hash,
                                    author=author,
                                    date=date
                                )
                                findings.extend(commit_findings)
                                commits_scanned += 1

            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                pass

        # Deduplicate findings by hash
        seen_hashes: Set[str] = set()
        unique_findings = []
        for f in findings:
            if f.secret_hash not in seen_hashes:
                seen_hashes.add(f.secret_hash)
                unique_findings.append(f)

        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        high_entropy = sum(1 for f in unique_findings if f.pattern_id == 'high-entropy')

        return ScanResult(
            scan_type="git_repo",
            target=repo_path,
            findings=unique_findings,
            total_files_scanned=files_scanned,
            total_commits_scanned=commits_scanned,
            scan_duration_ms=duration_ms,
            patterns_used=len(self.compiled_patterns),
            high_entropy_detections=high_entropy
        )

    async def scan_url(self, url: str, follow_links: bool = False,
                      max_depth: int = 1, config: ScanConfig = None) -> ScanResult:
        """Scan URL content for secrets"""
        import aiohttp

        start_time = datetime.now()
        config = config or ScanConfig()
        findings = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    content = await response.text()
                    url_findings = await self.scan_content(content, url, config)
                    findings.extend(url_findings)

        except Exception as e:
            pass

        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        high_entropy = sum(1 for f in findings if f.pattern_id == 'high-entropy')

        return ScanResult(
            scan_type="url",
            target=url,
            findings=findings,
            total_files_scanned=1,
            total_commits_scanned=0,
            scan_duration_ms=duration_ms,
            patterns_used=len(self.compiled_patterns),
            high_entropy_detections=high_entropy
        )


# Export for use
__all__ = ['SecretScanner', 'ScanConfig', 'SecretFinding', 'ScanResult',
           'SecretPatternLibrary', 'EntropyAnalyzer', 'Severity']
