"""
Pentest Mission Control - Command Interpreter
==============================================

Parses LLM output for [EXEC:] commands and routes them to extraction engines.
Also handles direct user commands.
"""

import re
import json
import logging
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Types of commands"""
    EXEC = "exec"           # Execute extraction tool
    QUERY = "query"         # Query knowledge graph
    FOCUS = "focus"         # Focus on specific component
    EXPORT = "export"       # Export data
    VISUALIZE = "viz"       # Update visualization


@dataclass
class ParsedCommand:
    """A parsed command from LLM or user input"""
    type: CommandType
    tool: str
    method: str
    params: Dict[str, Any] = field(default_factory=dict)
    raw: str = ""


@dataclass
class CommandResult:
    """Result of command execution"""
    success: bool
    data: Any = None
    error: Optional[str] = None
    artifacts: List[str] = field(default_factory=list)  # Paths to generated files
    entities: List[Dict] = field(default_factory=list)  # Entities to add to graph


class CommandInterpreter:
    """
    Interprets and executes commands from LLM or direct user input.

    Supports:
    - [EXEC:tool.method(params)] format from LLM
    - Natural language commands from user (routed through LLM)
    - Direct API calls
    """

    # Pattern to match [EXEC:tool.method(params)] commands
    EXEC_PATTERN = re.compile(
        r'\[EXEC:(\w+)\.(\w+)\((.*?)\)\]',
        re.DOTALL
    )

    def __init__(self):
        self.tools: Dict[str, Any] = {}  # Registered extraction tools
        self.hooks: Dict[str, List[Callable]] = {
            "pre_execute": [],
            "post_execute": [],
            "on_error": [],
        }

    def register_tool(self, name: str, tool: Any):
        """Register an extraction tool"""
        self.tools[name] = tool
        logger.info(f"Registered tool: {name}")

    def register_hook(self, event: str, callback: Callable):
        """Register a hook for command events"""
        if event in self.hooks:
            self.hooks[event].append(callback)

    def parse_llm_response(self, response: str) -> Tuple[str, List[ParsedCommand]]:
        """
        Parse LLM response for [EXEC:] commands.

        Returns:
            Tuple of (text_without_commands, list_of_commands)
        """
        commands = []

        for match in self.EXEC_PATTERN.finditer(response):
            tool = match.group(1)
            method = match.group(2)
            params_str = match.group(3).strip()

            # Parse parameters
            params = self._parse_params(params_str)

            commands.append(ParsedCommand(
                type=CommandType.EXEC,
                tool=tool,
                method=method,
                params=params,
                raw=match.group(0)
            ))

        # Remove commands from text for display
        clean_text = self.EXEC_PATTERN.sub('', response).strip()

        return clean_text, commands

    def _parse_params(self, params_str: str) -> Dict[str, Any]:
        """Parse parameter string into dict"""
        if not params_str:
            return {}

        params = {}

        # Handle key=value pairs
        # Supports: key="value", key='value', key=123, key=true, key=["a","b"]
        param_pattern = re.compile(
            r'(\w+)\s*=\s*('
            r'"[^"]*"|'           # double quoted string
            r"'[^']*'|"           # single quoted string
            r'\[[^\]]*\]|'        # array
            r'\{[^}]*\}|'         # object
            r'[^,\s]+'            # unquoted value
            r')'
        )

        for match in param_pattern.finditer(params_str):
            key = match.group(1)
            value_str = match.group(2)

            # Parse value
            value = self._parse_value(value_str)
            params[key] = value

        return params

    def _parse_value(self, value_str: str) -> Any:
        """Parse a parameter value string"""
        value_str = value_str.strip()

        # Remove quotes from strings
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]

        # Try JSON for arrays/objects
        if value_str.startswith('[') or value_str.startswith('{'):
            try:
                return json.loads(value_str)
            except json.JSONDecodeError:
                return value_str

        # Booleans
        if value_str.lower() == 'true':
            return True
        if value_str.lower() == 'false':
            return False

        # Numbers
        try:
            if '.' in value_str:
                return float(value_str)
            return int(value_str)
        except ValueError:
            pass

        return value_str

    async def execute(self, command: ParsedCommand) -> CommandResult:
        """Execute a parsed command"""
        logger.info(f"Executing: {command.tool}.{command.method}({command.params})")

        # Pre-execute hooks
        for hook in self.hooks["pre_execute"]:
            try:
                hook(command)
            except Exception as e:
                logger.warning(f"Pre-execute hook error: {e}")

        try:
            # Get tool
            tool = self.tools.get(command.tool)
            if not tool:
                return CommandResult(
                    success=False,
                    error=f"Unknown tool: {command.tool}"
                )

            # Get method
            method = getattr(tool, command.method, None)
            if not method:
                return CommandResult(
                    success=False,
                    error=f"Unknown method: {command.tool}.{command.method}"
                )

            # Execute
            if hasattr(method, '__call__'):
                # Check if async
                import asyncio
                if asyncio.iscoroutinefunction(method):
                    result = await method(**command.params)
                else:
                    result = method(**command.params)

                # Wrap result if not already CommandResult
                if not isinstance(result, CommandResult):
                    result = CommandResult(success=True, data=result)

                # Post-execute hooks
                for hook in self.hooks["post_execute"]:
                    try:
                        hook(command, result)
                    except Exception as e:
                        logger.warning(f"Post-execute hook error: {e}")

                return result

        except Exception as e:
            logger.error(f"Command execution error: {e}")

            # Error hooks
            for hook in self.hooks["on_error"]:
                try:
                    hook(command, e)
                except Exception:
                    pass

            return CommandResult(
                success=False,
                error=str(e)
            )

    def execute_sync(self, command: ParsedCommand) -> CommandResult:
        """Synchronous execution wrapper"""
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(self.execute(command))

    async def execute_batch(self, commands: List[ParsedCommand]) -> List[CommandResult]:
        """Execute multiple commands"""
        results = []
        for cmd in commands:
            result = await self.execute(cmd)
            results.append(result)

            # Stop on critical error
            if not result.success and "critical" in str(result.error).lower():
                break

        return results

    def get_available_commands(self) -> Dict[str, List[str]]:
        """Get list of available tools and their methods"""
        available = {}

        for name, tool in self.tools.items():
            methods = []
            for attr in dir(tool):
                if not attr.startswith('_') and callable(getattr(tool, attr)):
                    methods.append(attr)
            available[name] = methods

        return available


# =============================================================================
# Natural Language Command Patterns
# =============================================================================

# Maps common phrases to command templates
NATURAL_COMMANDS = {
    # Scanning/Recon
    r"scan\s+(.+)": "web.scan(target=\"{0}\")",
    r"recon\s+(.+)": "web.full_recon(target=\"{0}\")",
    r"map\s+(.+)": "web.spider(target=\"{0}\")",

    # JavaScript
    r"extract\s+(?:all\s+)?js(?:avascript)?\s+(?:from\s+)?(.+)": "web.extract_js(url=\"{0}\")",
    r"deobfuscate\s+(.+)": "web.deobfuscate(url=\"{0}\")",
    r"find\s+api\s*(?:endpoint)?s?\s+(?:in\s+)?(.+)": "web.extract_apis(url=\"{0}\")",

    # Binary
    r"decompile\s+(.+)": "binary.decompile(path=\"{0}\")",
    r"analyze\s+(?:binary\s+)?(.+\.(?:exe|dll|so|dylib))": "binary.analyze(path=\"{0}\")",
    r"extract\s+strings?\s+(?:from\s+)?(.+)": "binary.extract_strings(path=\"{0}\")",
    r"(?:list\s+)?imports?\s+(?:from\s+)?(.+)": "binary.list_imports(path=\"{0}\")",

    # Process
    r"hook\s+(.+)": "process.attach(target=\"{0}\")",
    r"monitor\s+(.+)": "process.monitor(target=\"{0}\")",
    r"dump\s+(?:memory\s+)?(?:from\s+)?(.+)": "process.dump_memory(target=\"{0}\")",
    r"trace\s+(?:api\s*)?(?:calls\s+)?(?:from\s+)?(.+)": "process.trace_apis(target=\"{0}\")",

    # Network
    r"port\s*scan\s+(.+)": "network.port_scan(target=\"{0}\")",
    r"fingerprint\s+(.+)": "network.fingerprint(target=\"{0}\")",

    # General
    r"focus\s+(?:on\s+)?(.+)": "graph.focus(entity=\"{0}\")",
    r"show\s+(?:me\s+)?(.+)": "graph.query(query=\"{0}\")",
    r"export\s+(.+)": "export.all(target=\"{0}\")",
}


def parse_natural_command(text: str) -> Optional[str]:
    """
    Try to parse a natural language command into an EXEC command.
    Returns None if no pattern matches.
    """
    text = text.strip().lower()

    for pattern, template in NATURAL_COMMANDS.items():
        match = re.match(pattern, text, re.IGNORECASE)
        if match:
            # Fill in template with matched groups
            cmd = template
            for i, group in enumerate(match.groups()):
                cmd = cmd.replace(f"{{{i}}}", group)
            return f"[EXEC:{cmd}]"

    return None


# =============================================================================
# Global instance
# =============================================================================

_interpreter: Optional[CommandInterpreter] = None


def get_command_interpreter() -> CommandInterpreter:
    """Get or create the global command interpreter"""
    global _interpreter
    if _interpreter is None:
        _interpreter = CommandInterpreter()
    return _interpreter


# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    interpreter = CommandInterpreter()

    # Test LLM response parsing
    test_response = """
    I'll analyze the target website for you.

    First, let me spider the site to find all pages:
    [EXEC:web.spider(url="https://example.com", depth=3)]

    Then I'll extract and deobfuscate the JavaScript:
    [EXEC:web.extract_js(url="https://example.com", deobfuscate=true)]

    Finally, I'll map the API endpoints:
    [EXEC:web.extract_apis(url="https://example.com", include_params=true)]
    """

    clean_text, commands = interpreter.parse_llm_response(test_response)

    print("Clean text:")
    print(clean_text)
    print("\nParsed commands:")
    for cmd in commands:
        print(f"  {cmd.tool}.{cmd.method}({cmd.params})")

    # Test natural language parsing
    print("\nNatural language tests:")
    test_phrases = [
        "scan example.com",
        "decompile /usr/bin/nano",
        "hook chrome.exe",
        "extract js from https://target.com",
        "find api endpoints in main.js",
    ]

    for phrase in test_phrases:
        result = parse_natural_command(phrase)
        print(f"  '{phrase}' -> {result}")
