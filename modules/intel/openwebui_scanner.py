"""
Open WebUI Scanner Module

Specialized scanner for Open WebUI (AI/LLM Interface) instances.
Identifies exposed deployments and checks for known CVEs.
"""

import json
import asyncio
import aiohttp
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
from packaging import version


@dataclass
class OpenWebUIInstance:
    """A discovered Open WebUI instance"""
    host: str
    port: int = 443
    accessible: bool = False
    version: Optional[str] = None
    features: Dict = field(default_factory=dict)
    endpoints_found: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)
    technologies: Set[str] = field(default_factory=set)
    oauth_providers: List[str] = field(default_factory=list)
    signup_enabled: bool = False
    api_keys_enabled: bool = False
    websocket_enabled: bool = False
    scan_time: str = ""


@dataclass
class CVEInfo:
    """CVE information"""
    cve_id: str
    cvss: float
    description: str
    affected_versions: str
    patched_version: str
    exploit_type: str


# Known CVEs for Open WebUI
KNOWN_CVES = [
    CVEInfo(
        cve_id="CVE-2025-64496",
        cvss=8.0,
        description="SSE Code Injection Remote Code Execution",
        affected_versions="<=0.6.34",
        patched_version="0.6.35",
        exploit_type="RCE"
    ),
    CVEInfo(
        cve_id="CVE-2025-64495",
        cvss=6.1,
        description="DOM XSS via crafted prompts",
        affected_versions="<=0.7.x",
        patched_version="TBD",
        exploit_type="XSS"
    ),
    CVEInfo(
        cve_id="ZDI-26-031",
        cvss=9.8,
        description="PIP command injection (0-day)",
        affected_versions="all",
        patched_version="None",
        exploit_type="RCE"
    ),
]


class OpenWebUIScanner:
    """
    Specialized scanner for Open WebUI instances.

    Features:
    - Detect exposed deployments
    - Extract configuration from /api/config
    - Check for known CVEs
    - Enumerate API endpoints
    - Identify authentication configuration
    """

    SIGNATURES = [
        b'Open WebUI',
        b'open-webui',
        b'ollama',
        b'openai/v1',
    ]

    ENDPOINTS_TO_CHECK = [
        '/api/config',
        '/api/version',
        '/health',
        '/api/v1/models',
        '/api/v1/chats',
        '/api/v1/prompts',
        '/api/v1/users',
        '/api/v1/auths/signin',
        '/api/v1/auths/signup',
        '/openai/v1/models',
        '/ollama/api/tags',
        '/api/v1/tools',
        '/api/v1/functions',
        '/api/v1/files',
        '/api/v1/memories',
        '/api/pipelines',
        '/manifest.json',
    ]

    def __init__(self, concurrency: int = 10, timeout: float = 15.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False)
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            }
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def scan_target(self, host: str, port: int = 443, use_https: bool = True) -> OpenWebUIInstance:
        """
        Scan a single target for Open WebUI.
        """
        instance = OpenWebUIInstance(
            host=host,
            port=port,
            scan_time=datetime.now().isoformat()
        )

        scheme = "https" if use_https else "http"
        base_url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"

        try:
            # Check /api/config first - main identifier
            config_url = f"{base_url}/api/config"
            async with self.session.get(config_url) as resp:
                if resp.status == 200:
                    try:
                        config = await resp.json()
                        if config.get('name') == 'Open WebUI' or 'version' in config:
                            instance.accessible = True
                            instance.version = config.get('version')
                            instance.features = config.get('features', {})
                            instance.signup_enabled = instance.features.get('enable_signup', False)
                            instance.api_keys_enabled = instance.features.get('enable_api_keys', False)
                            instance.websocket_enabled = instance.features.get('enable_websocket', False)

                            # Extract OAuth providers
                            oauth = config.get('oauth', {}).get('providers', {})
                            instance.oauth_providers = list(oauth.keys())

                            instance.endpoints_found.append('/api/config')
                            instance.technologies.add('open-webui')
                            instance.technologies.add('svelte')
                    except:
                        pass

            if not instance.accessible:
                return instance

            # Check additional endpoints
            await self._enumerate_endpoints(instance, base_url)

            # Check for CVEs
            self._check_cves(instance)

        except Exception as e:
            pass

        return instance

    async def _enumerate_endpoints(self, instance: OpenWebUIInstance, base_url: str):
        """Enumerate accessible endpoints"""
        for endpoint in self.ENDPOINTS_TO_CHECK:
            if endpoint == '/api/config':
                continue  # Already checked

            try:
                url = f"{base_url}{endpoint}"
                async with self.session.get(url) as resp:
                    status = resp.status

                    if status == 200:
                        instance.endpoints_found.append(f"{endpoint} (200)")

                        # Try to get additional info
                        try:
                            data = await resp.json()
                            if endpoint == '/api/version':
                                if 'version' in data:
                                    instance.version = data['version']
                            elif endpoint == '/manifest.json':
                                instance.technologies.add('pwa')
                        except:
                            pass

                    elif status == 401:
                        instance.endpoints_found.append(f"{endpoint} (401-auth)")
                    elif status == 403:
                        instance.endpoints_found.append(f"{endpoint} (403-forbidden)")

            except:
                pass

    def _check_cves(self, instance: OpenWebUIInstance):
        """Check for known CVEs based on version"""
        if not instance.version:
            return

        try:
            current_ver = version.parse(instance.version)
        except:
            return

        for cve in KNOWN_CVES:
            vuln_info = {
                'cve_id': cve.cve_id,
                'cvss': cve.cvss,
                'description': cve.description,
                'exploit_type': cve.exploit_type,
                'status': 'unknown'
            }

            # CVE-2025-64496: patched in 0.6.35
            if cve.cve_id == "CVE-2025-64496":
                try:
                    if current_ver < version.parse("0.6.35"):
                        vuln_info['status'] = 'VULNERABLE'
                    else:
                        vuln_info['status'] = 'patched'
                except:
                    vuln_info['status'] = 'check_manually'

            # CVE-2025-64495: DOM XSS - affects most versions
            elif cve.cve_id == "CVE-2025-64495":
                vuln_info['status'] = 'potentially_vulnerable'
                vuln_info['note'] = 'Requires authenticated user interaction'

            # ZDI-26-031: 0-day, no patch
            elif cve.cve_id == "ZDI-26-031":
                vuln_info['status'] = 'potentially_vulnerable'
                vuln_info['note'] = '0-day - no public patch available'

            instance.vulnerabilities.append(vuln_info)

    async def scan_targets(self, targets: List[str], port: int = 443) -> List[OpenWebUIInstance]:
        """Scan multiple targets"""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_with_limit(target):
            async with semaphore:
                return await self.scan_target(target, port)

        async with self:
            results = await asyncio.gather(*[scan_with_limit(t) for t in targets])
            return [r for r in results if r.accessible]

    def generate_report(self, instances: List[OpenWebUIInstance]) -> str:
        """Generate markdown report"""
        report = """# Open WebUI Scan Report

## Summary
"""
        accessible = [i for i in instances if i.accessible]
        vulnerable = [i for i in accessible if any(v['status'] in ['VULNERABLE', 'potentially_vulnerable'] for v in i.vulnerabilities)]

        report += f"- **Targets Scanned:** {len(instances)}\n"
        report += f"- **Accessible:** {len(accessible)}\n"
        report += f"- **Potentially Vulnerable:** {len(vulnerable)}\n\n"

        report += "## Instances\n\n"
        report += "| Host | Version | Signup | API Keys | CVE Status |\n"
        report += "|------|---------|--------|----------|------------|\n"

        for inst in accessible:
            signup = '✅' if inst.signup_enabled else '❌'
            api_keys = '✅' if inst.api_keys_enabled else '❌'

            cve_status = 'OK'
            for v in inst.vulnerabilities:
                if v['status'] == 'VULNERABLE':
                    cve_status = f"⚠️ {v['cve_id']}"
                    break
                elif v['status'] == 'potentially_vulnerable':
                    cve_status = f"⚡ Check {v['cve_id']}"

            report += f"| {inst.host}:{inst.port} | {inst.version} | {signup} | {api_keys} | {cve_status} |\n"

        report += "\n## Vulnerability Details\n\n"
        for inst in vulnerable:
            report += f"### {inst.host}:{inst.port}\n"
            report += f"- **Version:** {inst.version}\n"
            report += f"- **Endpoints Found:** {len(inst.endpoints_found)}\n"

            for v in inst.vulnerabilities:
                if v['status'] in ['VULNERABLE', 'potentially_vulnerable']:
                    report += f"\n#### {v['cve_id']} (CVSS {v['cvss']})\n"
                    report += f"- **Type:** {v['exploit_type']}\n"
                    report += f"- **Description:** {v['description']}\n"
                    report += f"- **Status:** {v['status']}\n"
                    if 'note' in v:
                        report += f"- **Note:** {v['note']}\n"

        return report


# CLI interface
async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python openwebui_scanner.py <target> [port]")
        print("  target: IP address or hostname")
        print("  port: Port to scan (default: 443)")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"[*] Scanning {target}:{port} for Open WebUI...")

    scanner = OpenWebUIScanner()
    async with scanner:
        result = await scanner.scan_target(target, port)

        if result.accessible:
            print(f"\n[+] Open WebUI {result.version} found!")
            print(f"    Signup: {'enabled' if result.signup_enabled else 'disabled'}")
            print(f"    API Keys: {'enabled' if result.api_keys_enabled else 'disabled'}")
            print(f"    WebSocket: {'enabled' if result.websocket_enabled else 'disabled'}")
            print(f"\n[*] Endpoints found:")
            for ep in result.endpoints_found:
                print(f"    - {ep}")
            print(f"\n[*] Vulnerability assessment:")
            for v in result.vulnerabilities:
                status_icon = '⚠️' if v['status'] == 'VULNERABLE' else '⚡' if v['status'] == 'potentially_vulnerable' else '✅'
                print(f"    {status_icon} {v['cve_id']}: {v['status']}")
        else:
            print("[-] No Open WebUI instance found")


if __name__ == "__main__":
    asyncio.run(main())
