"""
Mobile Security Tools Integration
=================================
Mobile application security testing for Android and iOS.

Includes:
- Objection: Runtime mobile exploration toolkit (Frida-based)
- MobSF: Mobile Security Framework (static + dynamic analysis)

Original repos:
- https://github.com/sensepost/objection (7,000+ stars)
- https://github.com/MobSF/Mobile-Security-Framework-MobSF (17,000+ stars)
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

EXTERNAL_PATH = Path(__file__).parent.parent.parent / "external-tools"


class Platform(Enum):
    """Mobile platforms"""
    ANDROID = "android"
    IOS = "ios"


class HookType(Enum):
    """Frida hook types"""
    METHOD = "method"
    CLASS = "class"
    SEARCH = "search"
    WATCH = "watch"


@dataclass
class MobileApp:
    """Mobile application metadata"""
    package_name: str
    app_name: str
    version: str
    platform: Platform
    permissions: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)


@dataclass
class SecurityFinding:
    """Mobile security finding"""
    severity: str  # critical, high, medium, low, info
    category: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: str = ""


@dataclass
class MobSFReport:
    """MobSF analysis report"""
    app: MobileApp
    security_score: int
    findings: List[SecurityFinding] = field(default_factory=list)
    manifest_analysis: Dict = field(default_factory=dict)
    code_analysis: Dict = field(default_factory=dict)
    binary_analysis: Dict = field(default_factory=dict)
    urls_found: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    secrets_found: List[Dict] = field(default_factory=list)


class ObjectionMobile:
    """
    Objection - Runtime Mobile Exploration Toolkit.

    A runtime mobile exploration toolkit, powered by Frida.
    Allows you to assess mobile applications and their security posture
    without the need for a jailbroken or rooted device.

    Original: https://github.com/sensepost/objection (7,000+ stars)

    Features:
    - SSL pinning bypass
    - Root/jailbreak detection bypass
    - Method hooking and tracing
    - Memory dumping and searching
    - Keychain/SharedPreferences access
    - SQLite database access

    Example:
        objection = ObjectionMobile()
        objection.connect("com.target.app")
        objection.bypass_ssl_pinning()
        objection.dump_keychain()
    """

    def __init__(self, objection_path: Optional[Path] = None):
        self.objection_path = objection_path or EXTERNAL_PATH / "objection"
        self.connected_app: Optional[str] = None

    def _run_objection(self, *args) -> subprocess.CompletedProcess:
        """Run objection command"""
        cmd = ["objection"] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True)

    def _run_command(self, app: str, command: str) -> subprocess.CompletedProcess:
        """Run objection command against connected app"""
        return subprocess.run(
            ["objection", "-g", app, "run", command],
            capture_output=True,
            text=True
        )

    def connect(self, package_name: str) -> bool:
        """
        Connect to a mobile application.

        Args:
            package_name: App package/bundle identifier

        Returns:
            True if connected successfully
        """
        result = self._run_objection("-g", package_name, "explore")
        self.connected_app = package_name
        return result.returncode == 0

    def bypass_ssl_pinning(self, package_name: Optional[str] = None) -> subprocess.CompletedProcess:
        """
        Bypass SSL certificate pinning.

        Args:
            package_name: Target app (uses connected app if not specified)

        Returns:
            Command result
        """
        app = package_name or self.connected_app
        if not app:
            raise ValueError("No app connected. Call connect() first or provide package_name.")

        return self._run_command(app, "android sslpinning disable")

    def bypass_root_detection(self, package_name: Optional[str] = None) -> subprocess.CompletedProcess:
        """
        Bypass root/jailbreak detection.

        Args:
            package_name: Target app

        Returns:
            Command result
        """
        app = package_name or self.connected_app
        if not app:
            raise ValueError("No app connected.")

        return self._run_command(app, "android root disable")

    def dump_keychain(self, package_name: Optional[str] = None) -> str:
        """
        Dump iOS Keychain / Android SharedPreferences.

        Args:
            package_name: Target app

        Returns:
            Keychain/preferences data
        """
        app = package_name or self.connected_app
        if not app:
            raise ValueError("No app connected.")

        result = self._run_command(app, "ios keychain dump")
        if result.returncode != 0:
            result = self._run_command(app, "android keystore list")

        return result.stdout

    def list_activities(self, package_name: Optional[str] = None) -> List[str]:
        """List Android activities"""
        app = package_name or self.connected_app
        result = self._run_command(app, "android hooking list activities")
        return result.stdout.strip().split("\n")

    def list_classes(self, package_name: Optional[str] = None) -> List[str]:
        """List loaded classes"""
        app = package_name or self.connected_app
        result = self._run_command(app, "android hooking list classes")
        return result.stdout.strip().split("\n")

    def search_classes(self, pattern: str, package_name: Optional[str] = None) -> List[str]:
        """
        Search for classes matching pattern.

        Args:
            pattern: Search pattern (e.g., "crypto", "ssl")
            package_name: Target app

        Returns:
            List of matching class names
        """
        app = package_name or self.connected_app
        result = self._run_command(app, f"android hooking search classes {pattern}")
        return result.stdout.strip().split("\n")

    def hook_method(
        self,
        class_name: str,
        method_name: str,
        package_name: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """
        Hook a method to observe calls.

        Args:
            class_name: Full class name
            method_name: Method to hook
            package_name: Target app

        Returns:
            Command result
        """
        app = package_name or self.connected_app
        return self._run_command(
            app,
            f"android hooking watch class_method {class_name}.{method_name}"
        )

    def dump_memory(self, package_name: Optional[str] = None) -> subprocess.CompletedProcess:
        """Dump application memory"""
        app = package_name or self.connected_app
        return self._run_command(app, "memory dump all")

    def search_memory(self, pattern: str, package_name: Optional[str] = None) -> str:
        """
        Search memory for pattern.

        Args:
            pattern: String pattern to search for
            package_name: Target app

        Returns:
            Memory search results
        """
        app = package_name or self.connected_app
        result = self._run_command(app, f'memory search "{pattern}"')
        return result.stdout

    @staticmethod
    def get_common_bypasses() -> Dict[str, str]:
        """Common security bypasses available in Objection"""
        return {
            "ssl_pinning": "android sslpinning disable",
            "root_detection": "android root disable",
            "jailbreak_detection": "ios jailbreak disable",
            "biometric_bypass": "android keystore watch",
            "screenshot_enable": "android ui FLAG_SECURE false",
            "debuggable": "android shell_exec getprop ro.debuggable",
        }


class MobSFScanner:
    """
    MobSF - Mobile Security Framework.

    An automated, all-in-one mobile application security testing framework
    capable of performing static analysis, dynamic analysis, and malware analysis.

    Original: https://github.com/MobSF/Mobile-Security-Framework-MobSF (17,000+ stars)

    Features:
    - Static Analysis (APK, IPA, APPX)
    - Dynamic Analysis (real-time testing)
    - Malware Analysis
    - API Security Testing
    - Web API Fuzzer

    Example:
        mobsf = MobSFScanner(api_key="your_key")
        report = mobsf.scan_apk("/path/to/app.apk")
        print(f"Security Score: {report.security_score}")
    """

    def __init__(
        self,
        mobsf_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        mobsf_path: Optional[Path] = None
    ):
        self.mobsf_url = mobsf_url.rstrip("/")
        self.api_key = api_key or os.environ.get("MOBSF_API_KEY")
        self.mobsf_path = mobsf_path or EXTERNAL_PATH / "mobsf"

    def _api_request(self, endpoint: str, data: Dict = None, files: Dict = None) -> Dict:
        """Make MobSF API request"""
        import requests

        headers = {"Authorization": self.api_key} if self.api_key else {}
        url = f"{self.mobsf_url}/api/v1/{endpoint}"

        if files:
            response = requests.post(url, headers=headers, data=data, files=files)
        else:
            response = requests.post(url, headers=headers, data=data)

        return response.json()

    def upload(self, file_path: str) -> Dict:
        """
        Upload app for analysis.

        Args:
            file_path: Path to APK/IPA file

        Returns:
            Upload response with scan hash
        """
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            return self._api_request("upload", files=files)

    def scan(self, scan_hash: str, scan_type: str = "apk") -> Dict:
        """
        Start static analysis.

        Args:
            scan_hash: Hash from upload response
            scan_type: Type of scan (apk, ipa, appx)

        Returns:
            Scan results
        """
        return self._api_request("scan", data={"hash": scan_hash, "scan_type": scan_type})

    def get_report(self, scan_hash: str) -> MobSFReport:
        """
        Get analysis report.

        Args:
            scan_hash: Hash from upload response

        Returns:
            MobSFReport with findings
        """
        result = self._api_request("report_json", data={"hash": scan_hash})

        app = MobileApp(
            package_name=result.get("package_name", ""),
            app_name=result.get("app_name", ""),
            version=result.get("version_name", ""),
            platform=Platform.ANDROID if "apk" in result.get("file_name", "").lower() else Platform.IOS,
            permissions=result.get("permissions", []),
            activities=result.get("activities", []),
            services=result.get("services", []),
            receivers=result.get("receivers", [])
        )

        findings = []
        for vuln in result.get("code_analysis", {}).values():
            if isinstance(vuln, dict):
                findings.append(SecurityFinding(
                    severity=vuln.get("severity", "info"),
                    category="Code Analysis",
                    title=vuln.get("title", ""),
                    description=vuln.get("description", ""),
                    recommendation=vuln.get("recommendation", "")
                ))

        return MobSFReport(
            app=app,
            security_score=result.get("security_score", 0),
            findings=findings,
            manifest_analysis=result.get("manifest_analysis", {}),
            code_analysis=result.get("code_analysis", {}),
            binary_analysis=result.get("binary_analysis", {}),
            urls_found=result.get("urls", []),
            api_endpoints=result.get("api", {}).get("api_endpoints", []),
            secrets_found=result.get("secrets", [])
        )

    def scan_apk(self, apk_path: str) -> MobSFReport:
        """
        Full APK analysis pipeline.

        Args:
            apk_path: Path to APK file

        Returns:
            MobSFReport with complete analysis
        """
        upload_result = self.upload(apk_path)
        scan_hash = upload_result.get("hash")

        self.scan(scan_hash, "apk")

        return self.get_report(scan_hash)

    def scan_ipa(self, ipa_path: str) -> MobSFReport:
        """
        Full IPA analysis pipeline.

        Args:
            ipa_path: Path to IPA file

        Returns:
            MobSFReport with complete analysis
        """
        upload_result = self.upload(ipa_path)
        scan_hash = upload_result.get("hash")

        self.scan(scan_hash, "ipa")

        return self.get_report(scan_hash)

    def start_server(self) -> subprocess.Popen:
        """Start MobSF Docker container"""
        return subprocess.Popen([
            "docker", "run", "-it", "--rm",
            "-p", "8000:8000",
            "opensecurity/mobile-security-framework-mobsf:latest"
        ])

    @staticmethod
    def get_check_categories() -> Dict[str, List[str]]:
        """Security check categories in MobSF"""
        return {
            "manifest_analysis": [
                "Exported components",
                "Backup allowed",
                "Debuggable",
                "Permissions (dangerous)",
                "Intent filters",
            ],
            "code_analysis": [
                "Hardcoded secrets",
                "Weak cryptography",
                "Insecure random",
                "SQL injection",
                "Path traversal",
                "WebView vulnerabilities",
                "Insecure logging",
            ],
            "binary_analysis": [
                "PIE enabled",
                "Stack canary",
                "RELRO",
                "NX bit",
                "Fortify source",
            ],
            "network_security": [
                "Cleartext traffic",
                "SSL pinning",
                "Certificate validation",
            ],
        }
