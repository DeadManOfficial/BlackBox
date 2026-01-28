#!/usr/bin/env python3
"""
BlackBox Intel Scanner CLI

Unified CLI for all intel gathering modules.

Usage:
    python -m intel.scanner_cli <command> [args]

Commands:
    clawdbot <target|file> [port]    - Scan for Clawdbot instances
    openwebui <target|file> [port]   - Scan for Open WebUI instances
    sourcemap <url>                  - Extract source from .js.map
    jsanalyze <url>                  - Analyze JavaScript bundle
    wsanalyze <url>                  - Analyze WebSocket protocol
    fullscan <target>                - Full multi-service scan
"""

import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime

# Import modules
from .clawdbot_scanner import ClawdbotScanner, ClawdbotInstance
from .openwebui_scanner import OpenWebUIScanner, OpenWebUIInstance
from .sourcemap_extractor import SourceMapExtractor
from .js_intel import JSIntelligence
from .websocket_analyzer import WebSocketAnalyzer


class IntelScannerCLI:
    """Unified CLI for BlackBox intel modules"""

    def __init__(self):
        self.results_dir = Path.home() / "BlackBox" / "targets"

    async def scan_clawdbot(self, targets: list, port: int = 18789, deep: bool = False) -> dict:
        """Scan for Clawdbot Control Panel instances"""
        scanner = ClawdbotScanner()
        async with scanner:
            result = await scanner.scan_targets(targets, port)

            output = {
                'scan_type': 'clawdbot',
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'scanned': result.targets_scanned,
                    'accessible': result.accessible_count,
                    'vulnerable': result.vulnerable_count,
                    'duration': result.scan_duration
                },
                'instances': []
            }

            for inst in result.instances:
                inst_data = {
                    'ip': inst.ip,
                    'port': inst.port,
                    'accessible': inst.accessible,
                    'version': inst.version,
                    'assistant_name': inst.assistant_name,
                    'js_bundle': inst.js_bundle_url,
                    'sourcemap_exposed': inst.sourcemap_exposed,
                    'sourcemap_url': inst.sourcemap_url,
                    'vulnerabilities': inst.vulnerabilities,
                    'technologies': list(inst.technologies)
                }

                if deep and inst.sourcemap_exposed:
                    deep_result = await scanner.deep_scan(inst)
                    inst_data['deep_scan'] = {
                        'source_files': len(deep_result['source_files']),
                        'rpc_methods': deep_result['rpc_methods'],
                        'technologies': list(deep_result['technologies'])
                    }

                output['instances'].append(inst_data)

            return output

    async def scan_openwebui(self, targets: list, port: int = 443, use_https: bool = True) -> dict:
        """Scan for Open WebUI instances"""
        scanner = OpenWebUIScanner()
        async with scanner:
            results = await scanner.scan_targets(targets, port)

            output = {
                'scan_type': 'openwebui',
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'scanned': len(targets),
                    'accessible': len(results)
                },
                'instances': []
            }

            for inst in results:
                output['instances'].append({
                    'host': inst.host,
                    'port': inst.port,
                    'version': inst.version,
                    'signup_enabled': inst.signup_enabled,
                    'api_keys_enabled': inst.api_keys_enabled,
                    'websocket_enabled': inst.websocket_enabled,
                    'oauth_providers': inst.oauth_providers,
                    'endpoints': inst.endpoints_found,
                    'vulnerabilities': inst.vulnerabilities,
                    'technologies': list(inst.technologies)
                })

            return output

    async def extract_sourcemap(self, url: str) -> dict:
        """Extract source from JavaScript source maps"""
        extractor = SourceMapExtractor()
        result = await extractor.fetch_and_extract(url)

        return {
            'scan_type': 'sourcemap',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'sources_count': len(result.get('sources', [])),
            'sources': result.get('sources', []),
            'technologies': result.get('technologies', []),
            'secrets': result.get('secrets', []),
            'endpoints': result.get('endpoints', [])
        }

    async def analyze_js(self, url: str) -> dict:
        """Analyze JavaScript bundle for security intel"""
        analyzer = JSIntelligence()

        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, ssl=False) as resp:
                content = await resp.text()

        result = analyzer.analyze(content)

        return {
            'scan_type': 'jsanalyze',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'size': len(content),
            'technologies': list(result.technologies),
            'secrets': result.secrets,
            'endpoints': result.endpoints,
            'hidden_routes': result.hidden_routes,
            'feature_flags': result.feature_flags,
            'security_issues': result.security_issues
        }

    async def analyze_websocket(self, url: str) -> dict:
        """Analyze WebSocket protocol"""
        analyzer = WebSocketAnalyzer()
        result = await analyzer.analyze(url)

        return {
            'scan_type': 'websocket',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'connected': result.get('connected', False),
            'protocol': result.get('protocol'),
            'methods': result.get('methods', []),
            'auth_required': result.get('auth_required'),
            'technologies': result.get('technologies', [])
        }

    async def full_scan(self, target: str) -> dict:
        """Perform full multi-service scan on a target"""
        import aiohttp

        output = {
            'scan_type': 'full',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'services': {}
        }

        # Common ports to check
        ports_to_check = [
            (443, 'https', 'Open WebUI / HTTPS'),
            (8080, 'http', 'code-server / HTTP Alt'),
            (18789, 'http', 'Clawdbot Control'),
            (80, 'http', 'HTTP'),
            (3000, 'http', 'Dev Server'),
            (8000, 'http', 'API Server'),
        ]

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            connector=aiohttp.TCPConnector(ssl=False)
        ) as session:
            for port, scheme, desc in ports_to_check:
                try:
                    url = f"{scheme}://{target}:{port}"
                    async with session.get(url) as resp:
                        content = await resp.text()
                        headers = dict(resp.headers)

                        service_info = {
                            'port': port,
                            'status': resp.status,
                            'description': desc,
                            'server': headers.get('Server', 'Unknown'),
                            'content_type': headers.get('Content-Type', ''),
                            'detected': []
                        }

                        # Detect Open WebUI
                        if 'Open WebUI' in content or '/api/config' in content:
                            service_info['detected'].append('Open WebUI')
                            owui = await self.scan_openwebui([target], port, scheme == 'https')
                            if owui['instances']:
                                service_info['openwebui'] = owui['instances'][0]

                        # Detect Clawdbot
                        if 'clawdbot' in content.lower() or '__CLAWDBOT_' in content:
                            service_info['detected'].append('Clawdbot')
                            cbot = await self.scan_clawdbot([target], port)
                            if cbot['instances']:
                                service_info['clawdbot'] = cbot['instances'][0]

                        # Detect code-server
                        if 'code-server' in content or 'coder-options' in content:
                            service_info['detected'].append('code-server')

                        output['services'][f"{port}/{scheme}"] = service_info

                except Exception as e:
                    output['services'][f"{port}/{scheme}"] = {
                        'port': port,
                        'status': 'unreachable',
                        'error': str(e)
                    }

        return output


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    command = sys.argv[1].lower()
    cli = IntelScannerCLI()

    try:
        if command == 'clawdbot':
            target = sys.argv[2] if len(sys.argv) > 2 else None
            port = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 18789
            deep = '--deep' in sys.argv

            if not target:
                print("Usage: clawdbot <target|file> [port] [--deep]")
                return

            if Path(target).exists():
                targets = Path(target).read_text().strip().split('\n')
            else:
                targets = [target]

            result = asyncio.run(cli.scan_clawdbot(targets, port, deep))
            print(json.dumps(result, indent=2))

        elif command == 'openwebui':
            target = sys.argv[2] if len(sys.argv) > 2 else None
            port = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3].isdigit() else 443

            if not target:
                print("Usage: openwebui <target|file> [port]")
                return

            if Path(target).exists():
                targets = Path(target).read_text().strip().split('\n')
            else:
                targets = [target]

            result = asyncio.run(cli.scan_openwebui(targets, port))
            print(json.dumps(result, indent=2))

        elif command == 'sourcemap':
            url = sys.argv[2] if len(sys.argv) > 2 else None
            if not url:
                print("Usage: sourcemap <url>")
                return
            result = asyncio.run(cli.extract_sourcemap(url))
            print(json.dumps(result, indent=2))

        elif command == 'jsanalyze':
            url = sys.argv[2] if len(sys.argv) > 2 else None
            if not url:
                print("Usage: jsanalyze <url>")
                return
            result = asyncio.run(cli.analyze_js(url))
            print(json.dumps(result, indent=2))

        elif command == 'wsanalyze':
            url = sys.argv[2] if len(sys.argv) > 2 else None
            if not url:
                print("Usage: wsanalyze <url>")
                return
            result = asyncio.run(cli.analyze_websocket(url))
            print(json.dumps(result, indent=2))

        elif command == 'fullscan':
            target = sys.argv[2] if len(sys.argv) > 2 else None
            if not target:
                print("Usage: fullscan <target>")
                return
            result = asyncio.run(cli.full_scan(target))
            print(json.dumps(result, indent=2))

        else:
            print(f"Unknown command: {command}")
            print(__doc__)

    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)


if __name__ == '__main__':
    main()
