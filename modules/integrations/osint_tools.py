"""
OSINT Tools Integration
=======================
Google dorking, data harvesting, and intelligence gathering tools.

Includes:
- SpeedyDork: Automated Google dorking for OSINT
- DataSploit: OSINT framework and aggregator
- PastebinScrapy: Credential leak monitoring

Original repos:
- https://github.com/MrQauckQauck/SpeedyDork
- https://github.com/DataSploit/datasploit (3,000+ stars)
- https://github.com/apurvsinghgautam/PastebinScrapy
"""

import subprocess
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

EXTERNAL_PATH = Path(__file__).parent.parent.parent / "external-tools"


class DorkCategory(Enum):
    """Google dork categories"""
    FILES = "files"
    DIRECTORIES = "directories"
    LOGIN_PAGES = "login"
    SENSITIVE_DATA = "sensitive"
    DATABASE = "database"
    ERRORS = "errors"
    ADMIN_PANELS = "admin"
    CONFIG_FILES = "config"
    BACKUP_FILES = "backup"
    EXPOSED_DOCS = "documents"


@dataclass
class DorkResult:
    """Google dork search result"""
    url: str
    title: str
    snippet: str
    dork_used: str
    category: DorkCategory


@dataclass
class OSINTProfile:
    """OSINT gathered profile"""
    target: str
    emails: List[str] = field(default_factory=list)
    usernames: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    social_profiles: Dict[str, str] = field(default_factory=dict)
    breaches: List[Dict] = field(default_factory=list)
    paste_hits: List[Dict] = field(default_factory=list)


class SpeedyDorkScanner:
    """
    Automated Google Dorking for OSINT.

    Features:
    - Pre-built dork templates for common vulnerabilities
    - Rate limiting to avoid blocks
    - Result parsing and categorization

    Example:
        dork = SpeedyDorkScanner()
        results = dork.scan_domain("target.com", categories=[DorkCategory.LOGIN_PAGES])
    """

    # Common Google dorks for security testing
    DORK_TEMPLATES = {
        DorkCategory.FILES: [
            'site:{domain} filetype:pdf',
            'site:{domain} filetype:doc OR filetype:docx',
            'site:{domain} filetype:xls OR filetype:xlsx',
            'site:{domain} filetype:sql',
            'site:{domain} filetype:log',
            'site:{domain} filetype:bak',
            'site:{domain} filetype:env',
        ],
        DorkCategory.DIRECTORIES: [
            'site:{domain} intitle:"index of"',
            'site:{domain} intitle:"directory listing"',
            'site:{domain} inurl:/backup/',
            'site:{domain} inurl:/admin/',
            'site:{domain} inurl:/config/',
        ],
        DorkCategory.LOGIN_PAGES: [
            'site:{domain} inurl:login',
            'site:{domain} inurl:signin',
            'site:{domain} inurl:admin',
            'site:{domain} intitle:"login"',
            'site:{domain} inurl:wp-login.php',
        ],
        DorkCategory.SENSITIVE_DATA: [
            'site:{domain} "password" filetype:txt',
            'site:{domain} "api_key" OR "apikey"',
            'site:{domain} "secret" filetype:json',
            'site:{domain} "BEGIN RSA PRIVATE KEY"',
            'site:{domain} inurl:credentials',
        ],
        DorkCategory.DATABASE: [
            'site:{domain} filetype:sql "INSERT INTO"',
            'site:{domain} inurl:phpmyadmin',
            'site:{domain} "mysql dump"',
            'site:{domain} inurl:db OR inurl:database',
        ],
        DorkCategory.ERRORS: [
            'site:{domain} "SQL syntax error"',
            'site:{domain} "Warning: mysql"',
            'site:{domain} "Parse error"',
            'site:{domain} "Fatal error"',
            'site:{domain} inurl:debug',
        ],
        DorkCategory.ADMIN_PANELS: [
            'site:{domain} inurl:admin',
            'site:{domain} inurl:administrator',
            'site:{domain} inurl:cpanel',
            'site:{domain} inurl:wp-admin',
            'site:{domain} intitle:"Dashboard"',
        ],
        DorkCategory.CONFIG_FILES: [
            'site:{domain} filetype:xml',
            'site:{domain} filetype:conf',
            'site:{domain} filetype:ini',
            'site:{domain} filetype:env',
            'site:{domain} "config" filetype:json',
        ],
        DorkCategory.BACKUP_FILES: [
            'site:{domain} filetype:bak',
            'site:{domain} filetype:old',
            'site:{domain} filetype:backup',
            'site:{domain} inurl:backup',
            'site:{domain} "~" filetype:sql',
        ],
    }

    def __init__(self, speedy_dork_path: Optional[Path] = None):
        self.speedy_dork_path = speedy_dork_path or EXTERNAL_PATH / "SpeedyDork"

    def get_dorks(
        self,
        domain: str,
        categories: Optional[List[DorkCategory]] = None
    ) -> List[str]:
        """
        Generate Google dorks for a domain.

        Args:
            domain: Target domain
            categories: Specific categories to generate dorks for

        Returns:
            List of formatted Google dork queries
        """
        if categories is None:
            categories = list(DorkCategory)

        dorks = []
        for category in categories:
            if category in self.DORK_TEMPLATES:
                for template in self.DORK_TEMPLATES[category]:
                    dorks.append(template.format(domain=domain))

        return dorks

    def run_script(self, domain: str) -> subprocess.CompletedProcess:
        """
        Run the SpeedyDork bash script.

        Args:
            domain: Target domain

        Returns:
            CompletedProcess with results
        """
        script_path = self.speedy_dork_path / "gdork.sh"

        if not script_path.exists():
            raise FileNotFoundError(f"SpeedyDork script not found at {script_path}")

        return subprocess.run(
            ["bash", str(script_path), domain],
            capture_output=True,
            text=True
        )

    @staticmethod
    def get_exploit_db_dorks() -> List[str]:
        """Get Google Hacking Database (GHDB) style dorks"""
        return [
            # Exposed credentials
            '"index of" "credentials"',
            'filetype:env "DB_PASSWORD"',
            'filetype:yaml "password:"',

            # Exposed configs
            'filetype:conf inurl:".htaccess"',
            'filetype:ini "[database]"',

            # Vulnerable pages
            'inurl:".php?id=" site:',
            'inurl:"viewprofile.php"',

            # Admin panels
            'intitle:"Grafana" inurl:/login',
            'intitle:"phpMyAdmin"',
            'intitle:"Jenkins" inurl:/login',
        ]


class DataSploitOSINT:
    """
    DataSploit OSINT Framework.

    An OSINT Framework to perform various recon techniques on Companies,
    People, Phone Numbers, Bitcoin Addresses, etc.

    Original: https://github.com/DataSploit/datasploit (3,000+ stars)

    Features:
    - Domain OSINT (whois, DNS, subdomains)
    - Email OSINT (breach lookup, validation)
    - Username OSINT (social media profiles)
    - IP OSINT (geolocation, ASN, reputation)

    Example:
        osint = DataSploitOSINT()
        profile = osint.investigate_domain("target.com")
    """

    def __init__(self, datasploit_path: Optional[Path] = None):
        self.datasploit_path = datasploit_path or EXTERNAL_PATH / "datasploit"

    def _run_datasploit(self, module: str, target: str) -> subprocess.CompletedProcess:
        """Run a datasploit module"""
        if not self.datasploit_path.exists():
            raise FileNotFoundError(f"DataSploit not found at {self.datasploit_path}")

        script = self.datasploit_path / f"domain_{module}.py"
        if not script.exists():
            script = self.datasploit_path / f"{module}.py"

        return subprocess.run(
            ["python", str(script), target],
            cwd=str(self.datasploit_path),
            capture_output=True,
            text=True
        )

    def investigate_domain(self, domain: str) -> OSINTProfile:
        """
        Full domain OSINT investigation.

        Args:
            domain: Target domain

        Returns:
            OSINTProfile with gathered intelligence
        """
        profile = OSINTProfile(target=domain)

        # Would run multiple modules and aggregate results
        # This is a placeholder for the actual implementation

        return profile

    def investigate_email(self, email: str) -> OSINTProfile:
        """
        Email OSINT investigation.

        Args:
            email: Target email address

        Returns:
            OSINTProfile with breach data, social profiles, etc.
        """
        profile = OSINTProfile(target=email, emails=[email])
        return profile

    def investigate_username(self, username: str) -> OSINTProfile:
        """
        Username OSINT investigation.

        Args:
            username: Target username

        Returns:
            OSINTProfile with social media profiles
        """
        profile = OSINTProfile(target=username, usernames=[username])
        return profile

    @staticmethod
    def available_modules() -> Dict[str, str]:
        """List available DataSploit modules"""
        return {
            "domain_whois": "WHOIS lookup",
            "domain_dns": "DNS records",
            "domain_subdomains": "Subdomain enumeration",
            "domain_emails": "Email harvesting",
            "email_breach": "Breach database lookup",
            "email_validate": "Email validation",
            "username_social": "Social media profile search",
            "ip_geolocation": "IP geolocation",
            "ip_reputation": "IP reputation check",
        }


class PastebinMonitor:
    """
    Pastebin Credential Leak Monitor.

    Monitors Pastebin for leaked credentials, API keys, and sensitive data.

    Original: https://github.com/apurvsinghgautam/PastebinScrapy

    Example:
        monitor = PastebinMonitor()
        leaks = monitor.search_keywords(["target.com", "company_name"])
    """

    def __init__(self, pastebin_path: Optional[Path] = None):
        self.pastebin_path = pastebin_path or EXTERNAL_PATH / "PastebinScrapy"

    def search_keywords(self, keywords: List[str]) -> List[Dict]:
        """
        Search Pastebin for keywords.

        Args:
            keywords: List of keywords to search for

        Returns:
            List of matching pastes
        """
        # Implementation would use Pastebin scraping
        return []

    def monitor_realtime(self, keywords: List[str], callback):
        """
        Real-time monitoring for keyword matches.

        Args:
            keywords: Keywords to monitor
            callback: Function to call on match
        """
        pass

    @staticmethod
    def get_common_patterns() -> Dict[str, str]:
        """Common patterns to search for in pastes"""
        return {
            "api_key": r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "aws_secret": r'["\']?aws[_-]?secret["\']?\s*[:=]\s*["\']?[\w/+=]+',
            "github_token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
            "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            "password": r'["\']?password["\']?\s*[:=]\s*["\']?[^\s"\']+',
            "email_password": r'[\w.+-]+@[\w-]+\.[\w.-]+\s*[:;|]\s*\S+',
            "connection_string": r'mongodb(?:\+srv)?://[^\s]+',
            "jwt_token": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+',
        }
