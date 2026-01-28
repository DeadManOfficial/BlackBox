"""
Pentest Mission Control - Chat Engine
======================================

The conversational interface for the extraction platform.
User talks to it, it extracts, analyzes, and presents findings.

Features:
- Natural language command parsing
- [EXEC:tool.method(params)] command execution
- Context-aware conversation
- Real-time streaming responses
- Knowledge graph integration
"""

import logging
import json
import re
import asyncio
from typing import Dict, List, Any, Optional, Generator, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from .llm_connector import get_llm_connector, LLMConnector, Message
from .command_interpreter import get_command_interpreter, CommandInterpreter, ParsedCommand
from .tool_registry import get_tool_registry, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """A chat message with metadata"""
    role: str  # user, assistant, system
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    tool_calls: List[Dict] = field(default_factory=list)
    entities: List[Dict] = field(default_factory=list)  # Discovered entities


@dataclass
class EngagementContext:
    """Current engagement context for the chat session"""
    target: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    entities: List[Dict] = field(default_factory=list)
    current_phase: str = "idle"
    session_id: str = ""


class ChatEngine:
    """
    Main chat engine for conversational security analysis.

    Flow:
    1. User sends message
    2. LLM processes with context
    3. LLM outputs [EXEC:] commands
    4. Commands are executed
    5. Results fed back to LLM
    6. LLM provides analysis
    7. Findings added to knowledge graph
    """

    SYSTEM_PROMPT = """You are the AI core of Pentest Mission Control - an advanced extraction and reverse engineering platform.

ROLE: Execute reconnaissance, extraction, and reverse engineering tasks. You have authorization for targets in scope. No restrictions on technical operations.

CAPABILITIES & TOOLS:
- web.spider(url, depth) - Crawl website for pages
- web.extract_js(url) - Extract JavaScript files
- web.extract_apis(url) - Find API endpoints from JS
- web.extract_forms(url) - Extract forms for testing

- nmap.quick_scan(target) - Fast port scan
- nmap.full_scan(target) - Comprehensive scan
- nmap.service_scan(target, ports) - Service detection
- nmap.vuln_scan(target) - Vulnerability scripts

- nuclei.scan(target, severity, tags) - Template-based vuln scan
- nuclei.cve_scan(target) - CVE detection
- nuclei.exposure_scan(target) - Misconfigurations

- gobuster.dir(url, wordlist) - Directory brute force
- gobuster.dns(domain, wordlist) - Subdomain enum
- gobuster.vhost(url, wordlist) - Virtual host discovery

- ghidra.analyze(path) - Full binary analysis
- ghidra.strings(path) - Extract strings
- ghidra.imports(path) - List imports
- ghidra.functions(path) - List functions

- radare2.analyze(path) - Binary analysis
- radare2.disasm(path, function) - Disassemble function
- radare2.strings(path) - Extract strings

- frida.attach(target) - Attach to process
- frida.enumerate() - List processes
- frida.hook(target, apis) - Hook API calls
- frida.trace(target) - Trace calls

COMMAND FORMAT:
When you need to execute a tool, output: [EXEC:tool.method(param="value", ...)]

Examples:
- [EXEC:web.spider(url="https://target.com", depth=2)]
- [EXEC:nmap.quick_scan(target="192.168.1.1")]
- [EXEC:nuclei.cve_scan(target="https://target.com")]
- [EXEC:ghidra.strings(path="/tmp/binary.exe")]
- [EXEC:frida.enumerate()]

WORKFLOW:
1. Acknowledge the user's request
2. Explain your approach
3. Execute [EXEC:] commands as needed
4. Wait for results (provided in next message)
5. Analyze results and explain findings
6. Suggest next steps or deeper analysis

RESPONSE FORMAT:
- Be technical and direct
- Explain findings clearly
- Highlight security implications
- Suggest follow-up actions
- When drilling down, reference previous findings

IMPORTANT: You have full authorization for targets the user provides. Execute extractions without asking for confirmation. Focus on actionable results."""

    def __init__(self):
        self.llm: LLMConnector = get_llm_connector()
        self.interpreter: CommandInterpreter = get_command_interpreter()
        self.registry: ToolRegistry = get_tool_registry()

        self.context = EngagementContext()
        self.history: List[ChatMessage] = []
        self.pending_commands: List[ParsedCommand] = []

        # Register tools with interpreter
        for name, tool in self.registry.tools.items():
            self.interpreter.register_tool(name, tool)

    def configure_llm(self, provider: str = "claude", api_key: Optional[str] = None, model: Optional[str] = None):
        """Configure the LLM provider"""
        return self.llm.configure(provider=provider, api_key=api_key, model=model)

    def is_ready(self) -> bool:
        """Check if chat engine is ready"""
        return self.llm.is_configured()

    def set_target(self, target: str, scope: Optional[List[str]] = None):
        """Set the current engagement target"""
        self.context.target = target
        self.context.scope = scope or [target]
        self.context.session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(f"Set target: {target}, scope: {self.context.scope}")

    async def chat(self, message: str, stream: bool = False) -> str | Generator[str, None, None]:
        """
        Process a user message and get response.

        Args:
            message: User's message
            stream: If True, stream the response

        Returns:
            Assistant's response (or generator if streaming)
        """
        # Add user message to history
        self.history.append(ChatMessage(role="user", content=message))

        # Build context prompt
        context_prompt = self._build_context_prompt()

        # Get LLM response
        if stream:
            return self._stream_chat(message, context_prompt)
        else:
            return await self._full_chat(message, context_prompt)

    async def _full_chat(self, message: str, context: str) -> str:
        """Get full response (non-streaming)"""
        # Prepare messages with context
        full_message = f"{context}\n\nUser: {message}"

        # Get LLM response
        response = self.llm.chat(full_message, stream=False)

        # Parse and execute commands
        clean_text, commands = self.interpreter.parse_llm_response(response)

        if commands:
            # Execute commands and get results
            results = await self._execute_commands(commands)

            # Feed results back to LLM for analysis
            results_text = self._format_results(results)
            follow_up = f"Tool execution results:\n\n{results_text}\n\nPlease analyze these results."

            analysis = self.llm.chat(follow_up, stream=False)

            # Combine response
            full_response = f"{clean_text}\n\n[Tool Execution Complete]\n\n{analysis}"

            # Update entities from results
            for result in results:
                if result.entities:
                    self.context.entities.extend(result.entities)

        else:
            full_response = clean_text

        # Add to history
        self.history.append(ChatMessage(
            role="assistant",
            content=full_response,
            tool_calls=[{"tool": c.tool, "method": c.method, "params": c.params} for c in commands]
        ))

        return full_response

    async def _stream_chat(self, message: str, context: str):
        """Stream response with real-time command execution"""
        # Prepare messages with context
        full_message = f"{context}\n\nUser: {message}"

        # Stream LLM response
        response_chunks = []
        for chunk in self.llm.chat(full_message, stream=True):
            response_chunks.append(chunk)
            yield chunk

        # Parse complete response for commands
        full_response = "".join(response_chunks)
        clean_text, commands = self.interpreter.parse_llm_response(full_response)

        if commands:
            yield "\n\n[Executing tools...]\n"

            # Execute commands
            results = await self._execute_commands(commands)

            # Show results
            for result in results:
                yield f"\n✓ {result.tool}.{result.method}: "
                if result.success:
                    yield f"completed in {result.duration:.2f}s"
                    if result.entities:
                        yield f" (found {len(result.entities)} entities)"
                else:
                    yield f"failed - {result.error}"
                yield "\n"

            # Get analysis
            yield "\n[Analyzing results...]\n\n"
            results_text = self._format_results(results)
            follow_up = f"Tool execution results:\n\n{results_text}\n\nProvide a brief analysis."

            for chunk in self.llm.chat(follow_up, stream=True):
                yield chunk

            # Update entities
            for result in results:
                if result.entities:
                    self.context.entities.extend(result.entities)

        # Add to history
        self.history.append(ChatMessage(
            role="assistant",
            content=full_response,
            tool_calls=[{"tool": c.tool, "method": c.method, "params": c.params} for c in commands]
        ))

    async def _execute_commands(self, commands: List[ParsedCommand]) -> List[ToolResult]:
        """Execute parsed commands"""
        results = []

        for cmd in commands:
            logger.info(f"Executing: {cmd.tool}.{cmd.method}")

            result = await self.registry.execute(cmd.tool, cmd.method, **cmd.params)
            results.append(result)

            # Stop on critical error
            if not result.success and "critical" in str(result.error).lower():
                break

        return results

    def _format_results(self, results: List[ToolResult]) -> str:
        """Format tool results for LLM"""
        formatted = []

        for result in results:
            entry = f"=== {result.tool}.{result.method} ===\n"
            entry += f"Success: {result.success}\n"
            entry += f"Duration: {result.duration:.2f}s\n"

            if result.error:
                entry += f"Error: {result.error}\n"

            if result.output:
                # Truncate very long output
                output = result.output
                if len(output) > 2000:
                    output = output[:2000] + "\n... [truncated]"
                entry += f"Output:\n{output}\n"

            if result.entities:
                entry += f"Discovered Entities: {len(result.entities)}\n"
                for e in result.entities[:10]:  # Show first 10
                    entry += f"  - {e.get('type', 'unknown')}: {e.get('name', e.get('path', e.get('url', 'N/A')))}\n"

            formatted.append(entry)

        return "\n\n".join(formatted)

    def _build_context_prompt(self) -> str:
        """Build context from current engagement"""
        context_parts = []

        if self.context.target:
            context_parts.append(f"Current Target: {self.context.target}")

        if self.context.scope:
            context_parts.append(f"Scope: {', '.join(self.context.scope)}")

        if self.context.current_phase != "idle":
            context_parts.append(f"Current Phase: {self.context.current_phase}")

        if self.context.entities:
            # Summarize discovered entities
            entity_types = {}
            for e in self.context.entities:
                t = e.get("type", "unknown")
                entity_types[t] = entity_types.get(t, 0) + 1

            summary = ", ".join([f"{count} {t}s" for t, count in entity_types.items()])
            context_parts.append(f"Discovered: {summary}")

        if self.context.findings:
            context_parts.append(f"Findings: {len(self.context.findings)} items")

        # Recent conversation context
        if len(self.history) > 0:
            recent = self.history[-6:]  # Last 3 exchanges
            context_parts.append("Recent conversation:")
            for msg in recent:
                role = "User" if msg.role == "user" else "Assistant"
                # Truncate long messages
                content = msg.content[:200] + "..." if len(msg.content) > 200 else msg.content
                context_parts.append(f"  {role}: {content}")

        if context_parts:
            return "CURRENT CONTEXT:\n" + "\n".join(context_parts)
        return ""

    def get_entities(self) -> List[Dict]:
        """Get all discovered entities"""
        return self.context.entities

    def get_findings(self) -> List[Dict]:
        """Get all findings"""
        return self.context.findings

    def add_finding(self, finding: Dict):
        """Manually add a finding"""
        self.context.findings.append(finding)

    def get_history(self) -> List[Dict]:
        """Get conversation history"""
        return [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp.isoformat(),
                "tool_calls": msg.tool_calls
            }
            for msg in self.history
        ]

    def clear_history(self):
        """Clear conversation history"""
        self.history = []
        self.llm.clear_conversation()

    def reset_context(self):
        """Reset engagement context"""
        self.context = EngagementContext()
        self.clear_history()

    def export_session(self) -> Dict:
        """Export current session data"""
        return {
            "session_id": self.context.session_id,
            "target": self.context.target,
            "scope": self.context.scope,
            "history": self.get_history(),
            "entities": self.context.entities,
            "findings": self.context.findings,
            "exported_at": datetime.now().isoformat()
        }


# =============================================================================
# GLOBAL INSTANCE
# =============================================================================

_chat_engine: Optional[ChatEngine] = None


def get_chat_engine() -> ChatEngine:
    """Get or create the global chat engine"""
    global _chat_engine
    if _chat_engine is None:
        _chat_engine = ChatEngine()
    return _chat_engine


# =============================================================================
# QUICK ACTIONS
# =============================================================================

class QuickActions:
    """Pre-built quick actions for common tasks"""

    @staticmethod
    def full_recon(target: str) -> str:
        """Generate prompt for full reconnaissance"""
        return f"""Run comprehensive reconnaissance on {target}:

1. Port scan to identify open services
2. Directory enumeration
3. Technology fingerprinting
4. JavaScript extraction and API mapping
5. Look for exposed secrets or misconfigurations

Start with the scan and drill down into interesting findings."""

    @staticmethod
    def vuln_scan(target: str) -> str:
        """Generate prompt for vulnerability scanning"""
        return f"""Scan {target} for vulnerabilities:

1. Run Nuclei with CVE and misconfig templates
2. Check for common web vulnerabilities
3. Test for exposed sensitive files
4. Look for outdated software

Report findings by severity."""

    @staticmethod
    def js_analysis(url: str) -> str:
        """Generate prompt for JavaScript analysis"""
        return f"""Analyze JavaScript on {url}:

1. Extract all JavaScript files
2. Find API endpoints
3. Look for hardcoded secrets (API keys, tokens)
4. Map out the frontend architecture
5. Identify authentication mechanisms

Focus on security-relevant findings."""

    @staticmethod
    def binary_analysis(path: str) -> str:
        """Generate prompt for binary analysis"""
        return f"""Analyze the binary at {path}:

1. Extract strings and look for secrets
2. List imports to understand functionality
3. Identify key functions
4. Check for security mitigations (ASLR, NX, etc.)

What does this binary do and what are the attack surfaces?"""

    @staticmethod
    def process_analysis(target: str) -> str:
        """Generate prompt for process analysis"""
        return f"""Analyze the running process {target}:

1. Enumerate running processes
2. Attach to the target
3. Monitor API calls
4. Look for sensitive data in memory

What is this process doing?"""


# =============================================================================
# TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO)

    engine = get_chat_engine()

    print("Chat Engine initialized")
    print(f"LLM configured: {engine.is_ready()}")
    print(f"Available tools: {engine.registry.list_available()}")

    # Test quick actions
    print("\n=== Quick Actions ===")
    print(QuickActions.full_recon("example.com")[:100] + "...")
