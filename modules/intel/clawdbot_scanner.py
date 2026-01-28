"""
Clawdbot/Moltbot Gateway Scanner Module

Specialized scanner for Clawdbot Control Panel instances.
Identifies exposed gateways and extracts intelligence.
"""

import json
import asyncio
import aiohttp
import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime
from pathlib import Path


@dataclass
class ClawdbotInstance:
    """A discovered Clawdbot instance"""
    ip: str
    port: int = 18789
    accessible: bool = False
    version: Optional[str] = None
    assistant_name: str = "Assistant"
    js_bundle_url: Optional[str] = None
    sourcemap_url: Optional[str] = None
    sourcemap_exposed: bool = False
    websocket_url: Optional[str] = None
    technologies: Set[str] = field(default_factory=set)
    vulnerabilities: List[str] = field(default_factory=list)
    scan_time: str = ""


@dataclass
class ClawdbotScanResult:
    """Result of Clawdbot scanning operation"""
    targets_scanned: int
    accessible_count: int
    vulnerable_count: int
    instances: List[ClawdbotInstance]
    scan_duration: float


class ClawdbotScanner:
    """
    Specialized scanner for Clawdbot/Moltbot gateway instances.

    Features:
    - Detect exposed control panels
    - Extract configuration from HTML
    - Check for source map exposure
    - Identify WebSocket endpoints
    - Enumerate vulnerabilities
    """

    SIGNATURES = [
        b'Clawdbot Control',
        b'clawdbot-app',
        b'__CLAWDBOT_',
        b'clawdbot-control-ui',
    ]

    def __init__(self, concurrency: int = 20, timeout: float = 10.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            }
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def scan_targets(self, targets: List[str], port: int = 18789) -> ClawdbotScanResult:
        """
        Scan multiple targets for Clawdbot instances.

        Args:
            targets: List of IP addresses or hostnames
            port: Port to scan (default 18789)
        """
        start_time = datetime.now()
        instances: List[ClawdbotInstance] = []

        semaphore = asyncio.Semaphore(self.concurrency)

        async def scan_target(target: str):
            async with semaphore:
                instance = await self._scan_single(target, port)
                return instance

        async with self:
            results = await asyncio.gather(*[scan_target(t) for t in targets])
            instances = [r for r in results if r is not None]

        duration = (datetime.now() - start_time).total_seconds()

        return ClawdbotScanResult(
            targets_scanned=len(targets),
            accessible_count=sum(1 for i in instances if i.accessible),
            vulnerable_count=sum(1 for i in instances if i.vulnerabilities),
            instances=instances,
            scan_duration=duration
        )

    async def _scan_single(self, target: str, port: int) -> Optional[ClawdbotInstance]:
        """Scan a single target"""
        instance = ClawdbotInstance(
            ip=target,
            port=port,
            scan_time=datetime.now().isoformat()
        )

        base_url = f"http://{target}:{port}"

        try:
            # Check if accessible and is Clawdbot
            async with self.session.get(base_url) as resp:
                if resp.status != 200:
                    return instance

                content = await resp.read()

                # Check for Clawdbot signatures
                is_clawdbot = any(sig in content for sig in self.SIGNATURES)
                if not is_clawdbot:
                    return instance

                instance.accessible = True

                # Parse HTML for configuration
                html = content.decode('utf-8', errors='ignore')
                self._parse_html_config(html, instance)

            # Check for source map exposure
            if instance.js_bundle_url:
                await self._check_sourcemap(instance)

            # Check WebSocket
            instance.websocket_url = f"ws://{target}:{port}"

            # Determine vulnerabilities
            if instance.sourcemap_exposed:
                instance.vulnerabilities.append("SOURCE_MAP_EXPOSURE")
            if instance.accessible:
                instance.vulnerabilities.append("UNAUTHENTICATED_UI_ACCESS")

        except Exception as e:
            pass

        return instance

    def _parse_html_config(self, html: str, instance: ClawdbotInstance):
        """Parse HTML to extract configuration"""
        # Extract JS bundle URL
        js_match = re.search(r'src="([^"]+index-[a-zA-Z0-9-]+\.js)"', html)
        if js_match:
            instance.js_bundle_url = js_match.group(1)

        # Extract assistant name
        name_match = re.search(r'__CLAWDBOT_ASSISTANT_NAME__="([^"]+)"', html)
        if name_match:
            instance.assistant_name = name_match.group(1)

        # Extract base path
        path_match = re.search(r'__CLAWDBOT_CONTROL_UI_BASE_PATH__="([^"]*)"', html)
        if path_match:
            instance.technologies.add('clawdbot-control-ui')

        # Check for version hints
        version_match = re.search(r'version["\']?\s*[:=]\s*["\']([0-9.]+)', html)
        if version_match:
            instance.version = version_match.group(1)

    async def _check_sourcemap(self, instance: ClawdbotInstance):
        """Check if source map is accessible"""
        if not instance.js_bundle_url:
            return

        base_url = f"http://{instance.ip}:{instance.port}"
        map_url = f"{base_url}/{instance.js_bundle_url}.map"

        try:
            async with self.session.get(map_url) as resp:
                if resp.status == 200:
                    # Verify it's actually a source map
                    content = await resp.text()
                    if '"sources"' in content and '"sourcesContent"' in content:
                        instance.sourcemap_exposed = True
                        instance.sourcemap_url = map_url
                        instance.vulnerabilities.append("FULL_SOURCE_CODE_DISCLOSURE")
        except:
            pass

    async def deep_scan(self, instance: ClawdbotInstance) -> Dict:
        """Perform deep scan on a confirmed instance"""
        result = {
            'instance': instance,
            'source_files': [],
            'rpc_methods': [],
            'technologies': set(),
            'secrets': [],
        }

        if not instance.sourcemap_exposed:
            return result

        # Download and analyze source map
        try:
            async with self.session.get(instance.sourcemap_url) as resp:
                if resp.status == 200:
                    content = await resp.text()
                    data = json.loads(content)

                    sources = data.get('sources', [])
                    contents = data.get('sourcesContent', [])

                    for i, src in enumerate(sources):
                        if 'node_modules' not in src:
                            result['source_files'].append(src)

                            # Analyze content for RPC methods
                            if i < len(contents) and contents[i]:
                                code = contents[i]
                                # Find RPC methods
                                methods = re.findall(r'request\("([a-zA-Z._]+)"', code)
                                result['rpc_methods'].extend(methods)

                                # Find technologies
                                if 'LitElement' in code:
                                    result['technologies'].add('lit')
                                if 'WebSocket' in code:
                                    result['technologies'].add('websocket')

                    result['rpc_methods'] = list(set(result['rpc_methods']))

        except:
            pass

        return result

    def generate_report(self, scan_result: ClawdbotScanResult) -> str:
        """Generate markdown report"""
        report = f"""# Clawdbot Gateway Scan Report

## Summary
- **Targets Scanned:** {scan_result.targets_scanned}
- **Accessible:** {scan_result.accessible_count}
- **Vulnerable:** {scan_result.vulnerable_count}
- **Scan Duration:** {scan_result.scan_duration:.2f}s

## Instances

| IP | Port | Accessible | Source Map | Vulnerabilities |
|----|------|------------|------------|-----------------|
"""
        for inst in scan_result.instances:
            accessible = '✅' if inst.accessible else '❌'
            sourcemap = '⚠️ EXPOSED' if inst.sourcemap_exposed else '✅ Hidden'
            vulns = ', '.join(inst.vulnerabilities) if inst.vulnerabilities else 'None'
            report += f"| {inst.ip} | {inst.port} | {accessible} | {sourcemap} | {vulns} |\n"

        report += "\n## Vulnerable Instances\n"
        for inst in scan_result.instances:
            if inst.vulnerabilities:
                report += f"\n### {inst.ip}:{inst.port}\n"
                report += f"- **Assistant Name:** {inst.assistant_name}\n"
                report += f"- **JS Bundle:** {inst.js_bundle_url}\n"
                report += f"- **Source Map:** {inst.sourcemap_url}\n"
                report += f"- **Vulnerabilities:**\n"
                for vuln in inst.vulnerabilities:
                    report += f"  - {vuln}\n"

        return report


# CLI interface
async def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python clawdbot_scanner.py <target_file_or_ip> [port]")
        print("  target_file: File with one IP per line, or single IP")
        print("  port: Port to scan (default: 18789)")
        sys.exit(1)

    target_input = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 18789

    # Load targets
    if Path(target_input).exists():
        targets = Path(target_input).read_text().strip().split('\n')
    else:
        targets = [target_input]

    print(f"[*] Scanning {len(targets)} targets on port {port}...")

    scanner = ClawdbotScanner()
    async with scanner:
        result = await scanner.scan_targets(targets, port)
        print(scanner.generate_report(result))

        # Deep scan vulnerable instances
        for inst in result.instances:
            if inst.sourcemap_exposed:
                print(f"\n[*] Deep scanning {inst.ip}...")
                deep = await scanner.deep_scan(inst)
                print(f"    Source files: {len(deep['source_files'])}")
                print(f"    RPC methods: {len(deep['rpc_methods'])}")


if __name__ == "__main__":
    asyncio.run(main())
