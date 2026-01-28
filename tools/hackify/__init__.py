"""
Hackify - Collaborative Coding Rooms
====================================

Node.js tool for real-time collaborative development sessions.
Like plug.dj for coding - share code, chat, music in sync.

Usage:
    from tools.hackify import Hackify

    h = Hackify()
    h.start(name="my-room", readonly=False)

CLI:
    cd tools/hackify && npm install
    hackify --name my-room

Requirements:
    - Node.js
    - npm install hackify -g (or local)
"""

import subprocess
import shutil
from pathlib import Path
from typing import Optional


class Hackify:
    """Python wrapper for Hackify collaborative coding."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).parent
        self.node = shutil.which("node")
        self.npm = shutil.which("npm")
        self.host_js = self.base_dir / "host.js"

    @property
    def is_available(self) -> bool:
        """Check if Node.js is available."""
        return self.node is not None and self.host_js.exists()

    def install(self) -> bool:
        """Install npm dependencies."""
        if not self.npm:
            return False
        try:
            result = subprocess.run(
                [self.npm, "install"],
                cwd=self.base_dir,
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    def start(
        self,
        name: Optional[str] = None,
        password: Optional[str] = None,
        readonly: bool = False,
        server: str = "http://www.hackify.org",
        ignore: str = "/(node_modules|.git)/"
    ) -> subprocess.Popen:
        """Start a hackify room."""
        cmd = [self.node, str(self.host_js)]

        if name:
            cmd.extend(["--name", name])
        if password:
            cmd.extend(["--pass", password])
        if readonly:
            cmd.append("--readonly")
        if server != "http://www.hackify.org":
            cmd.extend(["--server", server])
        if ignore != "/(node_modules|.git)/":
            cmd.extend(["--ignore", ignore])

        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )


# Module-level instance
_hackify: Optional[Hackify] = None


def get_hackify() -> Hackify:
    """Get or create hackify instance."""
    global _hackify
    if _hackify is None:
        _hackify = Hackify()
    return _hackify
