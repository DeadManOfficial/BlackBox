"""
Docker-based tool wrappers.
"""

import subprocess
import shutil
from typing import Any, Dict, List, Optional

from .base import ToolWrapper, ToolResult


class DockerToolWrapper(ToolWrapper):
    """Wrapper for Docker-based tools."""

    image: str = ""
    container_args: List[str] = []

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.timeout = config.get("timeout", 600) if config else 600

    def run(self, *args, **kwargs) -> ToolResult:
        """Execute tool in Docker container."""
        if not self.is_available():
            return ToolResult.fail("Docker not available or image not found")

        cmd = ["docker", "run", "--rm"] + self.container_args + [self.image] + list(args)

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
            return ToolResult.fail("Container timed out", exit_code=-1)
        except Exception as e:
            return ToolResult.fail(str(e))

    def is_available(self) -> bool:
        """Check if Docker is available."""
        return shutil.which("docker") is not None

    def pull_image(self) -> ToolResult:
        """Pull the Docker image."""
        try:
            result = subprocess.run(
                ["docker", "pull", self.image],
                capture_output=True,
                text=True,
                timeout=300
            )
            return ToolResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr
            )
        except Exception as e:
            return ToolResult.fail(str(e))
