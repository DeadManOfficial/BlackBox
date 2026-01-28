"""
Reconnaissance Tools Integration for DeadMan Ultimate Scraper
=============================================================

Integrates industry-standard bug bounty recon tools into the scraper.

Tools Integrated:
- Nuclei: Vulnerability scanning with 10,000+ templates
- Subfinder: Passive subdomain enumeration
- httpx: HTTP probing and analysis
- Katana: Next-gen web crawling
- ffuf: Directory/parameter fuzzing
- GAU: Get All URLs from archives
- Waybackurls: Historical URL discovery
- ParamSpider: Parameter mining
- Arjun: Parameter discovery
- LinkFinder: JS endpoint extraction
- SecretFinder: Secret/API key detection

Author: DeadMan Security Research
License: MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Tool availability status."""
    INSTALLED = "installed"
    MISSING = "missing"
    ERROR = "error"


@dataclass
class ToolResult:
    """Result from running a recon tool."""
    tool: str
    success: bool
    data: list[str] = field(default_factory=list)
    raw_output: str = ""
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconTarget:
    """Target for reconnaissance."""
    domain: str
    include_subdomains: bool = True
    depth: int = 2
    threads: int = 50
    timeout: int = 30


class ReconTool(ABC):
    """Abstract base class for recon tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name."""
        pass

    @property
    @abstractmethod
    def command(self) -> str:
        """Command to execute the tool."""
        pass

    @abstractmethod
    async def run(self, target: ReconTarget) -> ToolResult:
        """Run the tool against target."""
        pass

    def is_installed(self) -> bool:
        """Check if tool is installed."""
        return shutil.which(self.command) is not None

    async def _run_command(
        self,
        args: list[str],
        timeout: int = 300
    ) -> tuple[str, str, int]:
        """Run command and return stdout, stderr, returncode."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            return stdout.decode(), stderr.decode(), proc.returncode or 0
        except asyncio.TimeoutError:
            proc.kill()
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1


# =============================================================================
# SUBDOMAIN ENUMERATION
# =============================================================================

class Subfinder(ReconTool):
    """
    Subfinder - Fast passive subdomain enumeration.

    Uses 50+ sources: crt.sh, VirusTotal, Censys, SecurityTrails, etc.
    """

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def command(self) -> str:
        return "subfinder"

    async def run(self, target: ReconTarget) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="Subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )

        args = [
            self.command,
            "-d", target.domain,
            "-silent",
            "-all",  # Use all sources
            "-t", str(target.threads),
            "-timeout", str(target.timeout),
        ]

        stdout, stderr, code = await self._run_command(args, timeout=600)

        if code != 0:
            return ToolResult(
                tool=self.name,
                success=False,
                error=stderr,
                raw_output=stdout
            )

        subdomains = [line.strip() for line in stdout.split("\n") if line.strip()]

        return ToolResult(
            tool=self.name,
            success=True,
            data=subdomains,
            raw_output=stdout,
            metadata={"count": len(subdomains)}
        )


# =============================================================================
# HTTP PROBING
# =============================================================================

class Httpx(ReconTool):
    """
    httpx - Fast multi-purpose HTTP toolkit.

    Probes hosts, extracts titles, status codes, technologies, etc.
    """

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def command(self) -> str:
        return "httpx"

    async def run(
        self,
        target: ReconTarget,
        urls: list[str] | None = None
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="httpx not installed. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )

        # Create temp file with URLs
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            if urls:
                f.write("\n".join(urls))
            else:
                f.write(target.domain)
            temp_file = f.name

        try:
            args = [
                self.command,
                "-l", temp_file,
                "-silent",
                "-json",
                "-tech-detect",  # Technology detection
                "-title",        # Extract titles
                "-status-code",  # Status codes
                "-content-length",
                "-web-server",
                "-threads", str(target.threads),
                "-timeout", str(target.timeout),
            ]

            stdout, stderr, code = await self._run_command(args, timeout=600)

            results = []
            for line in stdout.split("\n"):
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

            return ToolResult(
                tool=self.name,
                success=True,
                data=[json.dumps(r) for r in results],
                raw_output=stdout,
                metadata={"probed": len(results)}
            )

        finally:
            os.unlink(temp_file)


# =============================================================================
# WEB CRAWLING
# =============================================================================

class Katana(ReconTool):
    """
    Katana - Next-generation web crawler.

    Headless browser crawling, JavaScript rendering, endpoint extraction.
    """

    @property
    def name(self) -> str:
        return "katana"

    @property
    def command(self) -> str:
        return "katana"

    async def run(
        self,
        target: ReconTarget,
        headless: bool = True
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )

        url = f"https://{target.domain}" if not target.domain.startswith("http") else target.domain

        args = [
            self.command,
            "-u", url,
            "-silent",
            "-d", str(target.depth),
            "-jc",  # JavaScript crawl
            "-kf", "all",  # Known files
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf",  # Exclude static
            "-c", str(target.threads),
            "-timeout", str(target.timeout),
        ]

        if headless:
            args.extend(["-hl"])  # Headless mode

        stdout, stderr, code = await self._run_command(args, timeout=900)

        urls = [line.strip() for line in stdout.split("\n") if line.strip()]

        return ToolResult(
            tool=self.name,
            success=True,
            data=urls,
            raw_output=stdout,
            metadata={"urls_found": len(urls)}
        )


# =============================================================================
# DIRECTORY FUZZING
# =============================================================================

class Ffuf(ReconTool):
    """
    ffuf - Fast web fuzzer.

    Directory discovery, parameter fuzzing, virtual host enumeration.
    """

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def command(self) -> str:
        return "ffuf"

    async def run(
        self,
        target: ReconTarget,
        wordlist: str | None = None,
        extensions: list[str] | None = None
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="ffuf not installed. Install: go install github.com/ffuf/ffuf/v2@latest"
            )

        # Default wordlist
        if not wordlist:
            wordlist = "~/.claude-home/BlackBox/external-tools/SecLists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wordlist):
                wordlist = "~/.claude-home/BlackBox/external-tools/SecLists/Discovery/Web-Content/common.txt"

        url = f"https://{target.domain}/FUZZ" if not target.domain.startswith("http") else f"{target.domain}/FUZZ"

        args = [
            self.command,
            "-u", url,
            "-w", wordlist,
            "-t", str(target.threads),
            "-timeout", str(target.timeout),
            "-mc", "200,201,202,204,301,302,307,308,401,403,405,500",
            "-o", "/dev/stdout",
            "-of", "json",
            "-s",  # Silent
        ]

        if extensions:
            args.extend(["-e", ",".join(extensions)])

        stdout, stderr, code = await self._run_command(args, timeout=900)

        try:
            data = json.loads(stdout)
            results = data.get("results", [])
            return ToolResult(
                tool=self.name,
                success=True,
                data=[json.dumps(r) for r in results],
                raw_output=stdout,
                metadata={"paths_found": len(results)}
            )
        except json.JSONDecodeError:
            return ToolResult(
                tool=self.name,
                success=True,
                data=[],
                raw_output=stdout
            )


# =============================================================================
# VULNERABILITY SCANNING
# =============================================================================

class Nuclei(ReconTool):
    """
    Nuclei - Fast vulnerability scanner.

    10,000+ community templates, CVE scanning, misconfig detection.
    """

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def command(self) -> str:
        return "nuclei"

    async def run(
        self,
        target: ReconTarget,
        severity: list[str] | None = None,
        tags: list[str] | None = None
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="Nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )

        url = f"https://{target.domain}" if not target.domain.startswith("http") else target.domain

        args = [
            self.command,
            "-u", url,
            "-silent",
            "-json",
            "-c", str(target.threads),
            "-timeout", str(target.timeout),
        ]

        if severity:
            args.extend(["-severity", ",".join(severity)])
        else:
            args.extend(["-severity", "critical,high,medium"])

        if tags:
            args.extend(["-tags", ",".join(tags)])

        stdout, stderr, code = await self._run_command(args, timeout=1800)

        findings = []
        for line in stdout.split("\n"):
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        return ToolResult(
            tool=self.name,
            success=True,
            data=[json.dumps(f) for f in findings],
            raw_output=stdout,
            metadata={
                "findings": len(findings),
                "critical": sum(1 for f in findings if f.get("info", {}).get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("info", {}).get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("info", {}).get("severity") == "medium"),
            }
        )


# =============================================================================
# ARCHIVE URL DISCOVERY
# =============================================================================

class GAU(ReconTool):
    """
    GAU - Get All URLs.

    Fetches URLs from Wayback Machine, Common Crawl, URLScan, AlienVault OTX.
    """

    @property
    def name(self) -> str:
        return "gau"

    @property
    def command(self) -> str:
        return "gau"

    async def run(self, target: ReconTarget) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="GAU not installed. Install: go install github.com/lc/gau/v2/cmd/gau@latest"
            )

        args = [
            self.command,
            "--subs" if target.include_subdomains else "",
            "--threads", str(target.threads),
            "--timeout", str(target.timeout),
            target.domain,
        ]
        args = [a for a in args if a]  # Remove empty

        stdout, stderr, code = await self._run_command(args, timeout=900)

        urls = list(set(line.strip() for line in stdout.split("\n") if line.strip()))

        return ToolResult(
            tool=self.name,
            success=True,
            data=urls,
            raw_output=stdout,
            metadata={"urls_found": len(urls)}
        )


class Waybackurls(ReconTool):
    """
    Waybackurls - Fetch URLs from Wayback Machine.
    """

    @property
    def name(self) -> str:
        return "waybackurls"

    @property
    def command(self) -> str:
        return "waybackurls"

    async def run(self, target: ReconTarget) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="Waybackurls not installed. Install: go install github.com/tomnomnom/waybackurls@latest"
            )

        # Waybackurls reads from stdin
        proc = await asyncio.create_subprocess_exec(
            self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(input=target.domain.encode())

        urls = list(set(line.strip() for line in stdout.decode().split("\n") if line.strip()))

        return ToolResult(
            tool=self.name,
            success=True,
            data=urls,
            raw_output=stdout.decode(),
            metadata={"urls_found": len(urls)}
        )


# =============================================================================
# PARAMETER DISCOVERY
# =============================================================================

class ParamSpider(ReconTool):
    """
    ParamSpider - Mining parameters from dark corners.
    """

    @property
    def name(self) -> str:
        return "paramspider"

    @property
    def command(self) -> str:
        return "paramspider"

    async def run(self, target: ReconTarget) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="ParamSpider not installed. Install: pip install paramspider"
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            args = [
                self.command,
                "-d", target.domain,
                "-o", tmpdir,
                "--level", "high",
            ]

            stdout, stderr, code = await self._run_command(args, timeout=600)

            # Read output file
            urls = []
            for f in Path(tmpdir).glob("*.txt"):
                urls.extend(f.read_text().strip().split("\n"))

            return ToolResult(
                tool=self.name,
                success=True,
                data=list(set(urls)),
                raw_output=stdout,
                metadata={"params_found": len(urls)}
            )


class Arjun(ReconTool):
    """
    Arjun - HTTP parameter discovery.
    """

    @property
    def name(self) -> str:
        return "arjun"

    @property
    def command(self) -> str:
        return "arjun"

    async def run(
        self,
        target: ReconTarget,
        url: str | None = None
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="Arjun not installed. Install: pip install arjun"
            )

        target_url = url or f"https://{target.domain}"

        args = [
            self.command,
            "-u", target_url,
            "-t", str(target.threads),
            "--stable",
            "-oJ", "/dev/stdout",
        ]

        stdout, stderr, code = await self._run_command(args, timeout=600)

        try:
            data = json.loads(stdout)
            params = data.get(target_url, [])
            return ToolResult(
                tool=self.name,
                success=True,
                data=params,
                raw_output=stdout,
                metadata={"params_found": len(params)}
            )
        except json.JSONDecodeError:
            return ToolResult(
                tool=self.name,
                success=True,
                data=[],
                raw_output=stdout
            )


# =============================================================================
# JAVASCRIPT ANALYSIS
# =============================================================================

class LinkFinder(ReconTool):
    """
    LinkFinder - Extract endpoints from JavaScript files.
    """

    @property
    def name(self) -> str:
        return "linkfinder"

    @property
    def command(self) -> str:
        return "linkfinder"

    async def run(
        self,
        target: ReconTarget,
        js_url: str | None = None
    ) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.name,
                success=False,
                error="LinkFinder not installed. Install: pip install linkfinder"
            )

        target_url = js_url or f"https://{target.domain}"

        args = [
            "python", "-m", "linkfinder",
            "-i", target_url,
            "-o", "cli",
        ]

        stdout, stderr, code = await self._run_command(args, timeout=300)

        endpoints = list(set(line.strip() for line in stdout.split("\n") if line.strip()))

        return ToolResult(
            tool=self.name,
            success=True,
            data=endpoints,
            raw_output=stdout,
            metadata={"endpoints_found": len(endpoints)}
        )


class SecretFinder(ReconTool):
    """
    SecretFinder - Find secrets in JavaScript files.
    """

    @property
    def name(self) -> str:
        return "secretfinder"

    @property
    def command(self) -> str:
        return "secretfinder"

    # Regex patterns for common secrets
    SECRET_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r"[A-Za-z0-9/+=]{40}",
        "google_api": r"AIza[0-9A-Za-z-_]{35}",
        "google_oauth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "firebase": r"[a-z0-9-]+\.firebaseio\.com",
        "github_token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "stripe_key": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
        "slack_token": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
        "slack_webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
        "jwt": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
        "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "basic_auth": r"[a-zA-Z0-9+/]{20,}={0,2}:[a-zA-Z0-9+/]{20,}={0,2}",
        "bearer_token": r"[Bb]earer\s+[A-Za-z0-9\-_\.~\+\/]+=*",
        "api_key_generic": r"['\"]?api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9-_]{20,}['\"]",
        "password_field": r"['\"]?password['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "internal_ip": r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        "s3_bucket": r"[a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+",
    }

    async def run(
        self,
        target: ReconTarget,
        js_content: str | None = None
    ) -> ToolResult:
        """
        Scan for secrets. Can scan URL or provided JS content.
        """
        secrets_found = []

        if js_content:
            content = js_content
        else:
            # Fetch JS from URL
            try:
                import httpx
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(f"https://{target.domain}")
                    content = resp.text
            except Exception as e:
                return ToolResult(
                    tool=self.name,
                    success=False,
                    error=str(e)
                )

        # Search for secrets
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                secrets_found.append({
                    "type": secret_type,
                    "value": match[:50] + "..." if len(str(match)) > 50 else match,
                    "pattern": pattern,
                })

        return ToolResult(
            tool=self.name,
            success=True,
            data=[json.dumps(s) for s in secrets_found],
            raw_output=json.dumps(secrets_found, indent=2),
            metadata={"secrets_found": len(secrets_found)}
        )


# =============================================================================
# RECON ORCHESTRATOR
# =============================================================================

class ReconOrchestrator:
    """
    Orchestrates multiple recon tools for comprehensive reconnaissance.
    """

    def __init__(self):
        self.tools: dict[str, ReconTool] = {
            "subfinder": Subfinder(),
            "httpx": Httpx(),
            "katana": Katana(),
            "ffuf": Ffuf(),
            "nuclei": Nuclei(),
            "gau": GAU(),
            "waybackurls": Waybackurls(),
            "paramspider": ParamSpider(),
            "arjun": Arjun(),
            "linkfinder": LinkFinder(),
            "secretfinder": SecretFinder(),
        }

    def check_tools(self) -> dict[str, ToolStatus]:
        """Check which tools are installed."""
        status = {}
        for name, tool in self.tools.items():
            try:
                if tool.is_installed():
                    status[name] = ToolStatus.INSTALLED
                else:
                    status[name] = ToolStatus.MISSING
            except Exception:
                status[name] = ToolStatus.ERROR
        return status

    async def run_full_recon(
        self,
        target: ReconTarget,
        tools: list[str] | None = None
    ) -> dict[str, ToolResult]:
        """
        Run full reconnaissance pipeline.

        Pipeline:
        1. Subdomain enumeration (subfinder)
        2. Archive URL discovery (gau, waybackurls)
        3. HTTP probing (httpx)
        4. Web crawling (katana)
        5. Parameter discovery (paramspider, arjun)
        6. JavaScript analysis (linkfinder, secretfinder)
        7. Directory fuzzing (ffuf)
        8. Vulnerability scanning (nuclei)
        """
        results = {}
        tools_to_run = tools or list(self.tools.keys())

        logger.info(f"[RECON] Starting reconnaissance on {target.domain}")
        logger.info(f"[RECON] Tools: {', '.join(tools_to_run)}")

        # Phase 1: Subdomain enumeration
        if "subfinder" in tools_to_run:
            logger.info("[RECON] Phase 1: Subdomain enumeration...")
            results["subfinder"] = await self.tools["subfinder"].run(target)
            subdomains = results["subfinder"].data

        # Phase 2: Archive URL discovery (parallel)
        archive_tasks = []
        if "gau" in tools_to_run:
            archive_tasks.append(("gau", self.tools["gau"].run(target)))
        if "waybackurls" in tools_to_run:
            archive_tasks.append(("waybackurls", self.tools["waybackurls"].run(target)))

        if archive_tasks:
            logger.info("[RECON] Phase 2: Archive URL discovery...")
            for name, coro in archive_tasks:
                results[name] = await coro

        # Phase 3: HTTP probing
        if "httpx" in tools_to_run:
            logger.info("[RECON] Phase 3: HTTP probing...")
            all_urls = []
            if "subfinder" in results:
                all_urls.extend(results["subfinder"].data)
            results["httpx"] = await self.tools["httpx"].run(target, all_urls or None)

        # Phase 4: Web crawling
        if "katana" in tools_to_run:
            logger.info("[RECON] Phase 4: Web crawling...")
            results["katana"] = await self.tools["katana"].run(target)

        # Phase 5: Parameter discovery
        if "paramspider" in tools_to_run:
            logger.info("[RECON] Phase 5: Parameter discovery...")
            results["paramspider"] = await self.tools["paramspider"].run(target)

        # Phase 6: JavaScript analysis
        if "secretfinder" in tools_to_run:
            logger.info("[RECON] Phase 6: JavaScript analysis...")
            results["secretfinder"] = await self.tools["secretfinder"].run(target)

        # Phase 7: Directory fuzzing
        if "ffuf" in tools_to_run:
            logger.info("[RECON] Phase 7: Directory fuzzing...")
            results["ffuf"] = await self.tools["ffuf"].run(target)

        # Phase 8: Vulnerability scanning
        if "nuclei" in tools_to_run:
            logger.info("[RECON] Phase 8: Vulnerability scanning...")
            results["nuclei"] = await self.tools["nuclei"].run(target)

        logger.info(f"[RECON] Complete. {len(results)} tools executed.")

        return results


# =============================================================================
# CLI INTERFACE
# =============================================================================

async def main():
    """CLI entry point for recon tools."""
    import argparse

    parser = argparse.ArgumentParser(description="DeadMan Recon Tools")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-t", "--tools", nargs="+", help="Specific tools to run")
    parser.add_argument("--threads", type=int, default=50, help="Threads")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth")
    parser.add_argument("--check", action="store_true", help="Check installed tools")

    args = parser.parse_args()

    orchestrator = ReconOrchestrator()

    if args.check:
        print("\n[*] Checking installed tools...\n")
        status = orchestrator.check_tools()
        for tool, st in status.items():
            icon = "✓" if st == ToolStatus.INSTALLED else "✗"
            print(f"  {icon} {tool}: {st.value}")
        return

    target = ReconTarget(
        domain=args.domain,
        threads=args.threads,
        depth=args.depth,
    )

    results = await orchestrator.run_full_recon(target, args.tools)

    print("\n" + "=" * 60)
    print("RECONNAISSANCE RESULTS")
    print("=" * 60)

    for tool, result in results.items():
        print(f"\n[{tool}]")
        if result.success:
            print(f"  Found: {len(result.data)} items")
            if result.metadata:
                for k, v in result.metadata.items():
                    print(f"  {k}: {v}")
        else:
            print(f"  Error: {result.error}")


# =============================================================================
# BACKWARD COMPATIBILITY ALIASES
# =============================================================================
# These aliases support the naming convention used by enhanced_pipeline.py

SubfinderTool = Subfinder
HttpxTool = Httpx
KatanaTool = Katana
FFufTool = Ffuf
NucleiTool = Nuclei
GAUTool = GAU
WaybackurlsTool = Waybackurls
ParamSpiderTool = ParamSpider
ArjunTool = Arjun
LinkFinderTool = LinkFinder
SecretFinderTool = SecretFinder


if __name__ == "__main__":
    asyncio.run(main())
