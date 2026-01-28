"""
Pentest Mission Control - Unified Tool Registry
================================================

Integrates HexStrike AI's 150+ security tools with our extraction engines.
Provides a unified interface for the LLM to execute tools.

Architecture:
- Wraps external tools (nmap, nuclei, ghidra, frida, etc.)
- Provides extraction engines (web, binary, process, network)
- Routes [EXEC:tool.method(params)] commands from LLM
"""

import subprocess
import logging
import json
import os
import re
import asyncio
import shutil
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolCategory(Enum):
    """Categories of security tools"""
    NETWORK = "network"        # nmap, masscan, rustscan
    WEB = "web"                # gobuster, ffuf, nuclei, nikto
    BINARY = "binary"          # ghidra, radare2, binwalk
    PROCESS = "process"        # frida, gdb, strace
    CLOUD = "cloud"            # prowler, trivy, scout-suite
    PASSWORD = "password"      # hydra, john, hashcat
    OSINT = "osint"            # amass, theharvester, sherlock
    FORENSICS = "forensics"    # volatility, foremost, steghide
    EXPLOITATION = "exploit"   # metasploit, sqlmap, msfvenom


@dataclass
class ToolResult:
    """Result from tool execution"""
    success: bool
    tool: str
    method: str
    output: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    artifacts: List[str] = field(default_factory=list)
    entities: List[Dict] = field(default_factory=list)  # For knowledge graph


class BaseTool(ABC):
    """Abstract base class for all tools"""

    name: str = "base"
    category: ToolCategory = ToolCategory.NETWORK
    description: str = "Base tool"

    @abstractmethod
    def is_available(self) -> bool:
        """Check if tool is installed and available"""
        pass

    @abstractmethod
    async def execute(self, method: str, **params) -> ToolResult:
        """Execute a tool method with parameters"""
        pass

    def get_methods(self) -> List[str]:
        """Get list of available methods"""
        return [m for m in dir(self) if not m.startswith('_') and callable(getattr(self, m))]


# =============================================================================
# NETWORK TOOLS
# =============================================================================

class NmapTool(BaseTool):
    """Nmap port scanner and service detection"""

    name = "nmap"
    category = ToolCategory.NETWORK
    description = "Port scanning and service detection"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "scan": self._scan,
            "quick_scan": self._quick_scan,
            "full_scan": self._full_scan,
            "vuln_scan": self._vuln_scan,
            "service_scan": self._service_scan,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _scan(self, target: str, ports: str = "", scan_type: str = "-sV", **kwargs) -> ToolResult:
        """Basic nmap scan"""
        cmd = ["nmap", scan_type]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

        return await self._run_command(cmd, "scan")

    async def _quick_scan(self, target: str, **kwargs) -> ToolResult:
        """Quick scan of common ports"""
        cmd = ["nmap", "-T4", "-F", target]
        return await self._run_command(cmd, "quick_scan")

    async def _full_scan(self, target: str, **kwargs) -> ToolResult:
        """Full port scan with service detection"""
        cmd = ["nmap", "-sV", "-sC", "-p-", "-T4", target]
        return await self._run_command(cmd, "full_scan")

    async def _vuln_scan(self, target: str, **kwargs) -> ToolResult:
        """Vulnerability scan using NSE scripts"""
        cmd = ["nmap", "-sV", "--script=vuln", target]
        return await self._run_command(cmd, "vuln_scan")

    async def _service_scan(self, target: str, ports: str = "", **kwargs) -> ToolResult:
        """Detailed service and version detection"""
        cmd = ["nmap", "-sV", "-sC", "-A"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)
        return await self._run_command(cmd, "service_scan")

    async def _run_command(self, cmd: List[str], method: str) -> ToolResult:
        """Execute nmap command"""
        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            # Parse entities from output
            entities = self._parse_entities(stdout.decode())

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method=method,
                output=stdout.decode(),
                error=stderr.decode() if proc.returncode != 0 else None,
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method=method, error=str(e))

    def _parse_entities(self, output: str) -> List[Dict]:
        """Parse nmap output for knowledge graph entities"""
        entities = []

        # Parse open ports
        port_pattern = r"(\d+)/tcp\s+open\s+(\S+)"
        for match in re.finditer(port_pattern, output):
            port, service = match.groups()
            entities.append({
                "type": "service",
                "port": int(port),
                "name": service,
                "source": "nmap"
            })

        return entities


class MasscanTool(BaseTool):
    """Masscan high-speed port scanner"""

    name = "masscan"
    category = ToolCategory.NETWORK
    description = "High-speed port scanning"

    def is_available(self) -> bool:
        return shutil.which("masscan") is not None

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "scan": self._scan,
            "fast_scan": self._fast_scan,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _scan(self, target: str, ports: str = "1-65535", rate: int = 1000, **kwargs) -> ToolResult:
        """Basic masscan"""
        cmd = ["masscan", target, "-p", ports, "--rate", str(rate)]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="scan",
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="scan", error=str(e))

    async def _fast_scan(self, target: str, **kwargs) -> ToolResult:
        """Fast scan with high rate"""
        return await self._scan(target, ports="1-65535", rate=10000)


# =============================================================================
# WEB APPLICATION TOOLS
# =============================================================================

class NucleiTool(BaseTool):
    """Nuclei vulnerability scanner"""

    name = "nuclei"
    category = ToolCategory.WEB
    description = "Template-based vulnerability scanning"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "scan": self._scan,
            "cve_scan": self._cve_scan,
            "exposure_scan": self._exposure_scan,
            "full_scan": self._full_scan,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _scan(self, target: str, severity: str = "", tags: str = "", **kwargs) -> ToolResult:
        """Basic nuclei scan"""
        cmd = ["nuclei", "-u", target, "-json"]
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])

        return await self._run_scan(cmd, "scan")

    async def _cve_scan(self, target: str, **kwargs) -> ToolResult:
        """Scan for CVEs only"""
        cmd = ["nuclei", "-u", target, "-tags", "cve", "-json"]
        return await self._run_scan(cmd, "cve_scan")

    async def _exposure_scan(self, target: str, **kwargs) -> ToolResult:
        """Scan for exposures and misconfigurations"""
        cmd = ["nuclei", "-u", target, "-tags", "exposure,misconfig", "-json"]
        return await self._run_scan(cmd, "exposure_scan")

    async def _full_scan(self, target: str, **kwargs) -> ToolResult:
        """Full scan with all templates"""
        cmd = ["nuclei", "-u", target, "-json"]
        return await self._run_scan(cmd, "full_scan")

    async def _run_scan(self, cmd: List[str], method: str) -> ToolResult:
        """Execute nuclei scan"""
        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            # Parse vulnerabilities
            entities = self._parse_vulnerabilities(stdout.decode())

            return ToolResult(
                success=True,  # Nuclei returns 0 even with no findings
                tool=self.name,
                method=method,
                output=stdout.decode(),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method=method, error=str(e))

    def _parse_vulnerabilities(self, output: str) -> List[Dict]:
        """Parse nuclei JSON output for vulnerabilities"""
        entities = []
        for line in output.strip().split('\n'):
            if line:
                try:
                    vuln = json.loads(line)
                    entities.append({
                        "type": "vulnerability",
                        "name": vuln.get("info", {}).get("name", "Unknown"),
                        "severity": vuln.get("info", {}).get("severity", "unknown"),
                        "url": vuln.get("matched-at", ""),
                        "template": vuln.get("template-id", ""),
                        "source": "nuclei"
                    })
                except json.JSONDecodeError:
                    continue
        return entities


class GobusterTool(BaseTool):
    """Gobuster directory and file enumeration"""

    name = "gobuster"
    category = ToolCategory.WEB
    description = "Directory and file brute forcing"

    def is_available(self) -> bool:
        return shutil.which("gobuster") is not None

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "dir": self._dir_scan,
            "dns": self._dns_scan,
            "vhost": self._vhost_scan,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _dir_scan(self, url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", **kwargs) -> ToolResult:
        """Directory enumeration"""
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            # Parse directories
            entities = self._parse_dirs(stdout.decode())

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="dir",
                output=stdout.decode(),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="dir", error=str(e))

    async def _dns_scan(self, domain: str, wordlist: str = "/usr/share/wordlists/subdomains.txt", **kwargs) -> ToolResult:
        """Subdomain enumeration"""
        cmd = ["gobuster", "dns", "-d", domain, "-w", wordlist]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="dns",
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="dns", error=str(e))

    async def _vhost_scan(self, url: str, wordlist: str = "/usr/share/wordlists/vhosts.txt", **kwargs) -> ToolResult:
        """Virtual host enumeration"""
        cmd = ["gobuster", "vhost", "-u", url, "-w", wordlist]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="vhost",
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="vhost", error=str(e))

    def _parse_dirs(self, output: str) -> List[Dict]:
        """Parse gobuster output for directories"""
        entities = []
        for line in output.split('\n'):
            # Match: /path (Status: 200) [Size: 1234]
            match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
            if match:
                path, status = match.groups()
                entities.append({
                    "type": "endpoint",
                    "path": path,
                    "status": int(status),
                    "source": "gobuster"
                })
        return entities


# =============================================================================
# BINARY ANALYSIS TOOLS
# =============================================================================

class GhidraTool(BaseTool):
    """Ghidra reverse engineering framework"""

    name = "ghidra"
    category = ToolCategory.BINARY
    description = "Software reverse engineering"

    def __init__(self):
        self.ghidra_path = os.environ.get("GHIDRA_HOME", "/opt/ghidra")

    def is_available(self) -> bool:
        return os.path.exists(os.path.join(self.ghidra_path, "analyzeHeadless"))

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "analyze": self._analyze,
            "decompile": self._decompile,
            "strings": self._strings,
            "imports": self._imports,
            "functions": self._functions,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _analyze(self, path: str, **kwargs) -> ToolResult:
        """Run full Ghidra analysis"""
        # Ghidra headless analysis
        project_path = "/tmp/ghidra_projects"
        project_name = f"analysis_{os.path.basename(path)}"

        cmd = [
            os.path.join(self.ghidra_path, "support", "analyzeHeadless"),
            project_path, project_name,
            "-import", path,
            "-scriptPath", os.path.join(self.ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts"),
            "-postScript", "ExportFunctions.py",
            "-deleteProject"
        ]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="analyze",
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="analyze", error=str(e))

    async def _decompile(self, path: str, function: str = "", **kwargs) -> ToolResult:
        """Decompile binary to pseudo-C"""
        # This would run a Ghidra script to decompile
        return ToolResult(
            success=False,
            tool=self.name,
            method="decompile",
            error="Decompilation requires custom Ghidra script setup"
        )

    async def _strings(self, path: str, min_length: int = 4, **kwargs) -> ToolResult:
        """Extract strings from binary"""
        cmd = ["strings", "-n", str(min_length), path]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            strings = stdout.decode().split('\n')

            # Look for interesting strings
            entities = []
            for s in strings:
                if re.search(r'(password|secret|key|token|api)', s, re.IGNORECASE):
                    entities.append({
                        "type": "secret_string",
                        "value": s[:100],  # Truncate
                        "source": "strings"
                    })

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="strings",
                output=stdout.decode(),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="strings", error=str(e))

    async def _imports(self, path: str, **kwargs) -> ToolResult:
        """List imports from binary"""
        # Use objdump for ELF or pefile for PE
        cmd = ["objdump", "-T", path]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="imports",
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="imports", error=str(e))

    async def _functions(self, path: str, **kwargs) -> ToolResult:
        """List functions in binary"""
        cmd = ["nm", "-C", path]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            # Parse functions
            entities = []
            for line in stdout.decode().split('\n'):
                if ' T ' in line or ' t ' in line:  # Text (code) symbols
                    parts = line.split()
                    if len(parts) >= 3:
                        entities.append({
                            "type": "function",
                            "name": parts[-1],
                            "address": parts[0] if len(parts[0]) > 4 else None,
                            "source": "nm"
                        })

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method="functions",
                output=stdout.decode(),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="functions", error=str(e))


class Radare2Tool(BaseTool):
    """Radare2 reverse engineering framework"""

    name = "radare2"
    category = ToolCategory.BINARY
    description = "Advanced reverse engineering"

    def is_available(self) -> bool:
        return shutil.which("r2") is not None

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "analyze": self._analyze,
            "info": self._info,
            "strings": self._strings,
            "functions": self._functions,
            "disasm": self._disasm,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _analyze(self, path: str, **kwargs) -> ToolResult:
        """Full analysis"""
        return await self._run_r2(path, ["aaa", "aflj"], "analyze")

    async def _info(self, path: str, **kwargs) -> ToolResult:
        """Get binary info"""
        return await self._run_r2(path, ["ij"], "info")

    async def _strings(self, path: str, **kwargs) -> ToolResult:
        """Extract strings"""
        return await self._run_r2(path, ["izzj"], "strings")

    async def _functions(self, path: str, **kwargs) -> ToolResult:
        """List functions"""
        return await self._run_r2(path, ["aaa", "aflj"], "functions")

    async def _disasm(self, path: str, function: str = "main", **kwargs) -> ToolResult:
        """Disassemble function"""
        return await self._run_r2(path, ["aaa", f"pdf @ {function}"], "disasm")

    async def _run_r2(self, path: str, commands: List[str], method: str) -> ToolResult:
        """Run r2 with commands"""
        cmd = ["r2", "-q", "-c", ";".join(commands), path]

        try:
            import time
            start = time.time()

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            duration = time.time() - start

            return ToolResult(
                success=proc.returncode == 0,
                tool=self.name,
                method=method,
                output=stdout.decode(),
                duration=duration
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method=method, error=str(e))


# =============================================================================
# PROCESS ANALYSIS TOOLS
# =============================================================================

class FridaTool(BaseTool):
    """Frida dynamic instrumentation"""

    name = "frida"
    category = ToolCategory.PROCESS
    description = "Dynamic instrumentation and hooking"

    def is_available(self) -> bool:
        try:
            import frida
            return True
        except ImportError:
            return False

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "attach": self._attach,
            "spawn": self._spawn,
            "enumerate": self._enumerate,
            "hook": self._hook,
            "trace": self._trace,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _attach(self, target: str, **kwargs) -> ToolResult:
        """Attach to process"""
        try:
            import frida

            # Try PID first
            try:
                pid = int(target)
                session = frida.attach(pid)
            except ValueError:
                # Target is process name
                session = frida.attach(target)

            return ToolResult(
                success=True,
                tool=self.name,
                method="attach",
                output=f"Attached to {target}"
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="attach", error=str(e))

    async def _spawn(self, path: str, **kwargs) -> ToolResult:
        """Spawn and attach to process"""
        try:
            import frida

            pid = frida.spawn([path])
            session = frida.attach(pid)

            return ToolResult(
                success=True,
                tool=self.name,
                method="spawn",
                output=f"Spawned {path} with PID {pid}"
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="spawn", error=str(e))

    async def _enumerate(self, **kwargs) -> ToolResult:
        """List running processes"""
        try:
            import frida

            device = frida.get_local_device()
            processes = device.enumerate_processes()

            entities = []
            for p in processes:
                entities.append({
                    "type": "process",
                    "pid": p.pid,
                    "name": p.name,
                    "source": "frida"
                })

            output = "\n".join([f"{p.pid}\t{p.name}" for p in processes])

            return ToolResult(
                success=True,
                tool=self.name,
                method="enumerate",
                output=output,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="enumerate", error=str(e))

    async def _hook(self, target: str, apis: List[str], **kwargs) -> ToolResult:
        """Hook specific APIs"""
        # This would require a more complex Frida script setup
        return ToolResult(
            success=False,
            tool=self.name,
            method="hook",
            error="API hooking requires custom script implementation"
        )

    async def _trace(self, target: str, **kwargs) -> ToolResult:
        """Trace API calls"""
        return ToolResult(
            success=False,
            tool=self.name,
            method="trace",
            error="API tracing requires custom script implementation"
        )


# =============================================================================
# WEB EXTRACTION TOOLS (Custom)
# =============================================================================

class WebExtractor(BaseTool):
    """Web content extraction and analysis"""

    name = "web"
    category = ToolCategory.WEB
    description = "Web extraction and JavaScript analysis"

    def is_available(self) -> bool:
        return True  # Uses Python libraries

    async def execute(self, method: str, **params) -> ToolResult:
        methods = {
            "spider": self._spider,
            "extract_js": self._extract_js,
            "extract_apis": self._extract_apis,
            "extract_forms": self._extract_forms,
            "screenshot": self._screenshot,
        }

        if method not in methods:
            return ToolResult(success=False, tool=self.name, method=method,
                            error=f"Unknown method: {method}")

        return await methods[method](**params)

    async def _spider(self, url: str, depth: int = 2, **kwargs) -> ToolResult:
        """Spider website for links"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin, urlparse
            import time

            start = time.time()
            visited = set()
            to_visit = [(url, 0)]
            links = []

            base_domain = urlparse(url).netloc

            async with aiohttp.ClientSession() as session:
                while to_visit and len(visited) < 100:  # Limit
                    current_url, current_depth = to_visit.pop(0)

                    if current_url in visited or current_depth > depth:
                        continue

                    visited.add(current_url)

                    try:
                        async with session.get(current_url, timeout=10) as response:
                            if response.status == 200 and 'text/html' in response.headers.get('content-type', ''):
                                html = await response.text()
                                soup = BeautifulSoup(html, 'html.parser')

                                for link in soup.find_all('a', href=True):
                                    href = urljoin(current_url, link['href'])
                                    if urlparse(href).netloc == base_domain:
                                        links.append(href)
                                        if href not in visited:
                                            to_visit.append((href, current_depth + 1))
                    except:
                        continue

            duration = time.time() - start

            entities = [{"type": "endpoint", "url": link, "source": "spider"} for link in set(links)]

            return ToolResult(
                success=True,
                tool=self.name,
                method="spider",
                output="\n".join(set(links)),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="spider", error=str(e))

    async def _extract_js(self, url: str, **kwargs) -> ToolResult:
        """Extract JavaScript from page"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            import time

            start = time.time()
            js_files = []
            inline_js = []

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    # External JS
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(url, script['src'])
                        js_files.append(js_url)

                    # Inline JS
                    for script in soup.find_all('script', src=False):
                        if script.string:
                            inline_js.append(script.string[:500])  # Truncate

            duration = time.time() - start

            entities = [{"type": "javascript", "url": js, "source": "extractor"} for js in js_files]

            return ToolResult(
                success=True,
                tool=self.name,
                method="extract_js",
                output=json.dumps({
                    "external": js_files,
                    "inline_count": len(inline_js)
                }, indent=2),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="extract_js", error=str(e))

    async def _extract_apis(self, url: str, **kwargs) -> ToolResult:
        """Extract API endpoints from JavaScript"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            import time

            start = time.time()
            endpoints = set()

            # Patterns for API endpoints
            api_patterns = [
                r'["\']/(api|v\d+)/[^"\']+["\']',
                r'["\']https?://[^"\']+/(api|v\d+)/[^"\']+["\']',
                r'fetch\s*\(\s*["\'][^"\']+["\']',
                r'\.get\s*\(\s*["\'][^"\']+["\']',
                r'\.post\s*\(\s*["\'][^"\']+["\']',
            ]

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    # Get JS content
                    js_content = []
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(url, script['src'])
                        try:
                            async with session.get(js_url, timeout=10) as js_resp:
                                js_content.append(await js_resp.text())
                        except:
                            pass

                    for script in soup.find_all('script', src=False):
                        if script.string:
                            js_content.append(script.string)

                    # Extract endpoints
                    full_js = '\n'.join(js_content)
                    for pattern in api_patterns:
                        for match in re.finditer(pattern, full_js):
                            endpoint = match.group()
                            # Clean up
                            endpoint = re.sub(r'^["\']|["\']$', '', endpoint)
                            endpoint = re.sub(r'^(fetch|\.get|\.post)\s*\(\s*', '', endpoint)
                            endpoints.add(endpoint[:200])

            duration = time.time() - start

            entities = [{"type": "api_endpoint", "path": ep, "source": "js_analysis"} for ep in endpoints]

            return ToolResult(
                success=True,
                tool=self.name,
                method="extract_apis",
                output="\n".join(endpoints),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="extract_apis", error=str(e))

    async def _extract_forms(self, url: str, **kwargs) -> ToolResult:
        """Extract forms from page"""
        try:
            import aiohttp
            from bs4 import BeautifulSoup
            import time

            start = time.time()
            forms = []

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    for form in soup.find_all('form'):
                        form_data = {
                            "action": form.get('action', ''),
                            "method": form.get('method', 'GET').upper(),
                            "inputs": []
                        }

                        for inp in form.find_all(['input', 'textarea', 'select']):
                            form_data["inputs"].append({
                                "name": inp.get('name', ''),
                                "type": inp.get('type', 'text'),
                                "value": inp.get('value', '')
                            })

                        forms.append(form_data)

            duration = time.time() - start

            entities = [{"type": "form", "action": f["action"], "method": f["method"], "source": "extractor"} for f in forms]

            return ToolResult(
                success=True,
                tool=self.name,
                method="extract_forms",
                output=json.dumps(forms, indent=2),
                duration=duration,
                entities=entities
            )
        except Exception as e:
            return ToolResult(success=False, tool=self.name, method="extract_forms", error=str(e))

    async def _screenshot(self, url: str, **kwargs) -> ToolResult:
        """Take screenshot of page"""
        # Would use playwright or selenium
        return ToolResult(
            success=False,
            tool=self.name,
            method="screenshot",
            error="Screenshot requires browser automation setup"
        )


# =============================================================================
# TOOL REGISTRY
# =============================================================================

class ToolRegistry:
    """
    Central registry for all security tools.
    Routes [EXEC:tool.method(params)] commands from LLM to appropriate tools.
    """

    def __init__(self):
        self.tools: Dict[str, BaseTool] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        """Register all default tools"""
        default_tools = [
            # Network
            NmapTool(),
            MasscanTool(),

            # Web
            NucleiTool(),
            GobusterTool(),
            WebExtractor(),

            # Binary
            GhidraTool(),
            Radare2Tool(),

            # Process
            FridaTool(),
        ]

        for tool in default_tools:
            self.register(tool)

    def register(self, tool: BaseTool):
        """Register a tool"""
        self.tools[tool.name] = tool
        logger.info(f"Registered tool: {tool.name} ({tool.category.value})")

    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get tool by name"""
        return self.tools.get(name)

    def list_tools(self) -> Dict[str, Dict]:
        """List all registered tools with their status"""
        result = {}
        for name, tool in self.tools.items():
            result[name] = {
                "category": tool.category.value,
                "description": tool.description,
                "available": tool.is_available(),
                "methods": tool.get_methods()
            }
        return result

    def list_available(self) -> List[str]:
        """List names of available tools"""
        return [name for name, tool in self.tools.items() if tool.is_available()]

    async def execute(self, tool_name: str, method: str, **params) -> ToolResult:
        """Execute a tool method"""
        tool = self.get_tool(tool_name)
        if not tool:
            return ToolResult(
                success=False,
                tool=tool_name,
                method=method,
                error=f"Unknown tool: {tool_name}"
            )

        if not tool.is_available():
            return ToolResult(
                success=False,
                tool=tool_name,
                method=method,
                error=f"Tool not available: {tool_name}"
            )

        logger.info(f"Executing: {tool_name}.{method}({params})")
        return await tool.execute(method, **params)

    def execute_sync(self, tool_name: str, method: str, **params) -> ToolResult:
        """Synchronous wrapper for execute"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.execute(tool_name, method, **params))


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get or create the global tool registry"""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)

    registry = get_tool_registry()

    print("\n=== Available Tools ===")
    for name, info in registry.list_tools().items():
        status = "✓" if info["available"] else "✗"
        print(f"  {status} {name}: {info['description']}")
        print(f"      Methods: {', '.join(info['methods'][:5])}...")

    print("\n=== Test Execution ===")

    async def test():
        # Test web extraction
        result = await registry.execute("web", "extract_js", url="https://example.com")
        print(f"web.extract_js: success={result.success}")

        # Test nmap (if available)
        if "nmap" in registry.list_available():
            result = await registry.execute("nmap", "quick_scan", target="127.0.0.1")
            print(f"nmap.quick_scan: success={result.success}")

    asyncio.run(test())
