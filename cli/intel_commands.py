#!/usr/bin/env python3
"""
BlackBox Intel Commands - CLI Interface

Provides CLI commands for intelligence gathering operations.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# Styles
HEADER = "bold cyan"
SUCCESS = "bold green"
WARN = "bold yellow"
FAIL = "bold red"
INFO = "white"


def register_intel_commands(app: typer.Typer):
    """Register intel commands with the main app"""

    intel_app = typer.Typer(name="intel", help="Intelligence gathering operations")
    app.add_typer(intel_app, name="intel")

    @intel_app.command("clawdbot")
    def scan_clawdbot(
        target: str = typer.Argument(..., help="Target IP/hostname or file with targets"),
        port: int = typer.Option(18789, "-p", "--port", help="Port to scan"),
        deep: bool = typer.Option(False, "--deep", help="Perform deep scan on vulnerable instances"),
        output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save results to file"),
    ):
        """Scan for Clawdbot Control Panel instances"""
        console.print(f"[{HEADER}]Clawdbot Scanner[/] - Scanning for exposed control panels")

        async def _scan():
            sys.path.insert(0, str(Path.home() / "BlackBox" / "modules"))
            from intel.clawdbot_scanner import ClawdbotScanner

            # Parse targets
            if Path(target).exists():
                targets = Path(target).read_text().strip().split('\n')
            else:
                targets = [target]

            console.print(f"[{INFO}]Scanning {len(targets)} target(s) on port {port}...[/]")

            scanner = ClawdbotScanner()
            async with scanner:
                result = await scanner.scan_targets(targets, port)

                # Display results
                table = Table(title="Scan Results")
                table.add_column("Target", style="cyan")
                table.add_column("Accessible", style="green")
                table.add_column("Source Map", style="yellow")
                table.add_column("Vulnerabilities", style="red")

                for inst in result.instances:
                    access = "[green]YES[/]" if inst.accessible else "[red]NO[/]"
                    srcmap = "[yellow]EXPOSED[/]" if inst.sourcemap_exposed else "[green]Hidden[/]"
                    vulns = ", ".join(inst.vulnerabilities) if inst.vulnerabilities else "-"
                    table.add_row(f"{inst.ip}:{inst.port}", access, srcmap, vulns)

                console.print(table)
                console.print(f"\n[{SUCCESS}]Scanned:[/] {result.targets_scanned} | "
                             f"[{SUCCESS}]Accessible:[/] {result.accessible_count} | "
                             f"[{WARN}]Vulnerable:[/] {result.vulnerable_count}")

                # Deep scan vulnerable instances
                if deep:
                    for inst in result.instances:
                        if inst.sourcemap_exposed:
                            console.print(f"\n[{HEADER}]Deep scanning {inst.ip}...[/]")
                            deep_result = await scanner.deep_scan(inst)
                            console.print(f"  Source files: {len(deep_result['source_files'])}")
                            console.print(f"  RPC methods: {len(deep_result['rpc_methods'])}")
                            if deep_result['rpc_methods']:
                                console.print(f"  Methods: {', '.join(deep_result['rpc_methods'][:10])}...")

                # Save output
                if output:
                    data = {
                        'scan_type': 'clawdbot',
                        'timestamp': datetime.now().isoformat(),
                        'summary': {
                            'scanned': result.targets_scanned,
                            'accessible': result.accessible_count,
                            'vulnerable': result.vulnerable_count
                        },
                        'instances': [
                            {
                                'ip': i.ip,
                                'port': i.port,
                                'accessible': i.accessible,
                                'sourcemap_exposed': i.sourcemap_exposed,
                                'vulnerabilities': i.vulnerabilities
                            }
                            for i in result.instances
                        ]
                    }
                    output.write_text(json.dumps(data, indent=2))
                    console.print(f"[{SUCCESS}]Results saved to {output}[/]")

        asyncio.run(_scan())

    @intel_app.command("openwebui")
    def scan_openwebui(
        target: str = typer.Argument(..., help="Target IP/hostname or file with targets"),
        port: int = typer.Option(443, "-p", "--port", help="Port to scan"),
        http: bool = typer.Option(False, "--http", help="Use HTTP instead of HTTPS"),
        output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save results to file"),
    ):
        """Scan for Open WebUI instances and check for CVEs"""
        console.print(f"[{HEADER}]Open WebUI Scanner[/] - Scanning for AI/LLM interfaces")

        async def _scan():
            sys.path.insert(0, str(Path.home() / "BlackBox" / "modules"))
            from intel.openwebui_scanner import OpenWebUIScanner

            # Parse targets
            if Path(target).exists():
                targets = Path(target).read_text().strip().split('\n')
            else:
                targets = [target]

            console.print(f"[{INFO}]Scanning {len(targets)} target(s) on port {port}...[/]")

            scanner = OpenWebUIScanner()
            async with scanner:
                results = await scanner.scan_targets(targets, port)

                # Display results
                table = Table(title="Open WebUI Instances")
                table.add_column("Host", style="cyan")
                table.add_column("Version", style="green")
                table.add_column("Signup", style="yellow")
                table.add_column("CVE Status", style="red")

                for inst in results:
                    signup = "[green]Enabled[/]" if inst.signup_enabled else "[red]Disabled[/]"

                    cve_status = "[green]OK[/]"
                    for v in inst.vulnerabilities:
                        if v['status'] == 'VULNERABLE':
                            cve_status = f"[red]{v['cve_id']}[/]"
                            break
                        elif v['status'] == 'potentially_vulnerable':
                            cve_status = f"[yellow]{v['cve_id']}[/]"

                    table.add_row(f"{inst.host}:{inst.port}", inst.version or "Unknown", signup, cve_status)

                console.print(table)
                console.print(f"\n[{SUCCESS}]Found:[/] {len(results)} instance(s)")

                # Save output
                if output:
                    data = {
                        'scan_type': 'openwebui',
                        'timestamp': datetime.now().isoformat(),
                        'instances': [
                            {
                                'host': i.host,
                                'port': i.port,
                                'version': i.version,
                                'signup_enabled': i.signup_enabled,
                                'vulnerabilities': i.vulnerabilities
                            }
                            for i in results
                        ]
                    }
                    output.write_text(json.dumps(data, indent=2))
                    console.print(f"[{SUCCESS}]Results saved to {output}[/]")

        asyncio.run(_scan())

    @intel_app.command("sourcemap")
    def extract_sourcemap(
        url: str = typer.Argument(..., help="URL to source map file"),
        output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output directory for sources"),
    ):
        """Extract source code from JavaScript source maps"""
        console.print(f"[{HEADER}]Source Map Extractor[/] - Extracting source from {url}")

        async def _extract():
            sys.path.insert(0, str(Path.home() / "BlackBox" / "modules"))
            from intel.sourcemap_extractor import SourceMapExtractor

            extractor = SourceMapExtractor()
            result = await extractor.fetch_and_extract(url)

            console.print(f"\n[{SUCCESS}]Extracted {len(result.get('sources', []))} source files[/]")

            if result.get('technologies'):
                console.print(f"[{INFO}]Technologies: {', '.join(result['technologies'])}[/]")

            if result.get('secrets'):
                console.print(f"[{WARN}]Secrets found: {len(result['secrets'])}[/]")

            if result.get('endpoints'):
                console.print(f"[{INFO}]Endpoints found: {len(result['endpoints'])}[/]")

            # Save sources if output specified
            if output:
                output.mkdir(parents=True, exist_ok=True)
                for i, src in enumerate(result.get('sources', [])):
                    content = result.get('sourcesContent', [])[i] if i < len(result.get('sourcesContent', [])) else None
                    if content:
                        src_path = output / src.lstrip('../')
                        src_path.parent.mkdir(parents=True, exist_ok=True)
                        src_path.write_text(content)
                console.print(f"[{SUCCESS}]Sources saved to {output}[/]")

        asyncio.run(_extract())

    @intel_app.command("fullscan")
    def full_scan(
        target: str = typer.Argument(..., help="Target IP/hostname"),
        output: Optional[Path] = typer.Option(None, "-o", "--output", help="Save results to file"),
    ):
        """Perform comprehensive multi-service scan"""
        console.print(f"[{HEADER}]Full Service Scan[/] - Scanning {target}")

        async def _scan():
            import aiohttp

            services = {}
            ports = [
                (443, 'https'),
                (8080, 'http'),
                (18789, 'http'),
                (80, 'http'),
                (3000, 'http'),
            ]

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10),
                connector=aiohttp.TCPConnector(ssl=False)
            ) as session:
                for port, scheme in ports:
                    try:
                        url = f"{scheme}://{target}:{port}"
                        console.print(f"  Probing {url}...", end=" ")
                        async with session.get(url) as resp:
                            content = await resp.text()
                            detected = []

                            if 'Open WebUI' in content:
                                detected.append('Open WebUI')
                            if 'clawdbot' in content.lower():
                                detected.append('Clawdbot')
                            if 'code-server' in content:
                                detected.append('code-server')

                            services[port] = {
                                'status': resp.status,
                                'detected': detected
                            }

                            if detected:
                                console.print(f"[{SUCCESS}]{resp.status}[/] - {', '.join(detected)}")
                            else:
                                console.print(f"[{INFO}]{resp.status}[/]")
                    except Exception as e:
                        console.print(f"[{FAIL}]Failed[/]")
                        services[port] = {'status': 'unreachable'}

            console.print(f"\n[{SUCCESS}]Scan complete[/]")

            if output:
                data = {'target': target, 'timestamp': datetime.now().isoformat(), 'services': services}
                output.write_text(json.dumps(data, indent=2))
                console.print(f"[{SUCCESS}]Results saved to {output}[/]")

        asyncio.run(_scan())

    @intel_app.command("h1-status")
    def hackerone_status():
        """Show HackerOne submission status"""
        h1_file = Path.home() / "BlackBox" / "targets" / "HACKERONE_TRACKER.md"

        if h1_file.exists():
            console.print(Panel(h1_file.read_text(), title="HackerOne Submissions", border_style="green"))
        else:
            console.print(f"[{WARN}]No HackerOne tracker found. Creating...[/]")
            h1_file.parent.mkdir(parents=True, exist_ok=True)
            h1_file.write_text("""# HackerOne Submission Tracker

## Active Bounties

| ID | Target | Finding | Severity | Status | Bounty |
|----|--------|---------|----------|--------|--------|

## Pending Submissions

| ID | Target | Finding | Severity | Status |
|----|--------|---------|----------|--------|

## Templates
- Source Map Exposure: `findings/h1_drafts/sourcemap_exposure.md`
- Config Disclosure: `findings/h1_drafts/config_disclosure.md`

---
*Updated: """ + datetime.now().isoformat() + """*
""")
            console.print(f"[{SUCCESS}]Created {h1_file}[/]")
