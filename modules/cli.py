"""
CLI tool wrappers for command-line tools.
"""

import subprocess
import shutil
from typing import Any, Dict, List, Optional

from .base import ToolWrapper, ToolResult


class CLIToolWrapper(ToolWrapper):
    """Wrapper for CLI-based tools."""

    binary: str = ""
    default_args: List[str] = []

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = config.get("timeout", 300) if config else 300

    def run(self, *args, **kwargs) -> ToolResult:
        """Execute the CLI tool."""
        if not self.is_available():
            return ToolResult.fail(f"{self.binary} not found in PATH")

        cmd = [self.binary] + list(self.default_args) + list(args)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            return ToolResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                exit_code=result.returncode
            )
        except subprocess.TimeoutExpired:
            return ToolResult.fail("Command timed out", exit_code=-1)
        except Exception as e:
            return ToolResult.fail(str(e))

    def is_available(self) -> bool:
        """Check if binary exists in PATH."""
        return shutil.which(self.binary) is not None


class SubfinderWrapper(CLIToolWrapper):
    """Wrapper for subfinder subdomain enumeration."""
    name = "subfinder"
    binary = "subfinder"
    description = "Fast subdomain enumeration tool"


class HttpxWrapper(CLIToolWrapper):
    """Wrapper for httpx HTTP toolkit."""
    name = "httpx"
    binary = "httpx"
    description = "Fast HTTP toolkit"


# Registry of available wrappers
_WRAPPERS: Dict[str, type] = {
    "subfinder": SubfinderWrapper,
    "httpx": HttpxWrapper,
}


def get_wrapper(name: str, config: Dict[str, Any] = None) -> Optional[CLIToolWrapper]:
    """Get a wrapper instance by name."""
    wrapper_cls = _WRAPPERS.get(name)
    if wrapper_cls:
        return wrapper_cls(config)
    return None
