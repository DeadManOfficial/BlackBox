"""
Base wrapper classes for tool integration.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod
from enum import Enum, auto


class ModuleStatus(Enum):
    """Module loading status."""
    UNLOADED = auto()
    LOADING = auto()
    LOADED = auto()
    ERROR = auto()
    DISABLED = auto()


class ModuleCategory(Enum):
    """Module categories."""
    RECON = "reconnaissance"
    RECONNAISSANCE = "reconnaissance"  # Alias
    ATTACK = "attack"
    EXPLOIT = "exploit"
    POST = "post-exploitation"
    UTIL = "utility"
    UTILITY = "utility"  # Alias
    WORKFLOW = "workflow"
    REPORT = "reporting"
    METHODOLOGY = "methodology"
    INTEL = "intelligence"
    SCRAPER = "scraper"
    PENTEST = "pentest"
    AI_SECURITY = "ai-security"
    SECURITY = "security"
    MOBILE = "mobile"
    PAYLOADS = "payloads"
    INFRASTRUCTURE = "infrastructure"
    ARSENAL = "arsenal"
    BUGBOUNTY = "bugbounty"
    COMMAND = "command"
    INTEGRATIONS = "integrations"
    DARKWEB = "darkweb"


@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    output: str = ""
    error: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    exit_code: int = 0

    @classmethod
    def ok(cls, output: str = "", data: Dict[str, Any] = None) -> "ToolResult":
        return cls(success=True, output=output, data=data or {})

    @classmethod
    def fail(cls, error: str, exit_code: int = 1) -> "ToolResult":
        return cls(success=False, error=error, exit_code=exit_code)


class ToolWrapper(ABC):
    """Base class for wrapping external tools."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

    @abstractmethod
    def run(self, *args, **kwargs) -> ToolResult:
        """Execute the tool."""
        pass

    def is_available(self) -> bool:
        """Check if the tool is available."""
        return True

    def get_version(self) -> Optional[str]:
        """Get tool version."""
        return None


@dataclass
class ToolDefinition:
    """Definition of a tool for MCP registration."""
    name: str
    description: str
    input_schema: Dict[str, Any] = field(default_factory=dict)
    handler: Any = None


@dataclass
class RouteDefinition:
    """Definition of an HTTP route."""
    path: str
    methods: List[str] = field(default_factory=lambda: ["GET"])
    handler: Any = None
    description: str = ""


class BaseModule(ABC):
    """Base class for all BlackBox modules."""

    name: str = "base_module"
    description: str = ""
    category: ModuleCategory = ModuleCategory.UTIL
    version: str = "1.0.0"

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.status = ModuleStatus.UNLOADED
        self._tools: List[ToolWrapper] = []
        self._routes: List[RouteDefinition] = []

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the module."""
        pass

    def shutdown(self) -> None:
        """Cleanup module resources."""
        pass

    def register_tool(self, tool: ToolWrapper) -> None:
        """Register a tool with this module."""
        self._tools.append(tool)

    def get_tools(self) -> List[ToolWrapper]:
        """Get all registered tools."""
        return self._tools

    def is_available(self) -> bool:
        """Check if module is available."""
        return self.status == ModuleStatus.LOADED
