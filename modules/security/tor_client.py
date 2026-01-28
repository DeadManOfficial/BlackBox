"""
Tor Client Integration for BlackBox
Provides anonymous network access for dark web research

Usage:
    from modules.security.tor_client import TorClient, check_tor

    # Quick check
    status = check_tor()
    print(f"Connected: {status['connected']}, IP: {status['ip']}")

    # Anonymous request
    client = TorClient(use_torpy=True)
    with client.session():
        response = client.get("http://example.onion")
"""

import time
import subprocess
from typing import Optional, Dict, Any
from contextlib import contextmanager

# Check for torpy availability
try:
    from torpy.http.requests import TorRequests
    TORPY_AVAILABLE = True
except ImportError:
    TORPY_AVAILABLE = False

# Check for requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class TorClient:
    """Unified Tor client for anonymous operations."""

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        tor_binary: Optional[str] = None,
        use_torpy: bool = True
    ):
        """
        Initialize Tor client.

        Args:
            socks_port: SOCKS5 proxy port (default 9050)
            control_port: Tor control port (default 9051)
            tor_binary: Path to Tor binary (optional)
            use_torpy: Use pure Python torpy library (default True)
        """
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_binary = tor_binary
        self.use_torpy = use_torpy and TORPY_AVAILABLE
        self._tor_process = None
        self._tor_requests = None

    @property
    def proxies(self) -> Dict[str, str]:
        """Get proxy configuration for requests library."""
        return {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }

    def start(self) -> None:
        """Start Tor connection."""
        if self.use_torpy:
            self._tor_requests = TorRequests()
            self._tor_requests.__enter__()

    def stop(self) -> None:
        """Stop Tor connection."""
        if self._tor_requests:
            self._tor_requests.__exit__(None, None, None)
            self._tor_requests = None

    def new_identity(self) -> None:
        """Request new Tor circuit (new IP)."""
        if self.use_torpy:
            # torpy creates new circuits per session
            pass
        # Rate limit
        time.sleep(10)

    def get(self, url: str, **kwargs) -> Any:
        """Make anonymous GET request."""
        if self.use_torpy and self._tor_requests:
            with self._tor_requests.get_session() as session:
                return session.get(url, **kwargs)
        elif REQUESTS_AVAILABLE:
            return requests.get(url, proxies=self.proxies, **kwargs)
        else:
            raise RuntimeError("No HTTP library available")

    def post(self, url: str, **kwargs) -> Any:
        """Make anonymous POST request."""
        if self.use_torpy and self._tor_requests:
            with self._tor_requests.get_session() as session:
                return session.post(url, **kwargs)
        elif REQUESTS_AVAILABLE:
            return requests.post(url, proxies=self.proxies, **kwargs)
        else:
            raise RuntimeError("No HTTP library available")

    @contextmanager
    def session(self):
        """Context manager for Tor session."""
        self.start()
        try:
            yield self
        finally:
            self.stop()


def check_tor() -> Dict[str, Any]:
    """
    Check Tor connectivity and get exit node info.

    Returns:
        Dict with connection status and IP info
    """
    if not TORPY_AVAILABLE:
        return {
            "connected": False,
            "error": "torpy not installed. Run: pipx install torpy"
        }

    try:
        client = TorClient(use_torpy=True)
        with client.session():
            response = client.get('https://check.torproject.org/api/ip', timeout=60)
            data = response.json()
            return {
                "connected": data.get("IsTor", False),
                "ip": data.get("IP"),
            }
    except Exception as e:
        return {
            "connected": False,
            "error": str(e)
        }


def check_torpy_cli() -> Dict[str, Any]:
    """Check torpy CLI availability."""
    try:
        result = subprocess.run(
            ["torpy_cli", "--help"],
            capture_output=True,
            timeout=5
        )
        return {
            "available": result.returncode == 0,
            "path": subprocess.run(["which", "torpy_cli"], capture_output=True).stdout.decode().strip()
        }
    except:
        return {"available": False}


# Module info
def get_status() -> Dict[str, Any]:
    """Get Tor integration status."""
    return {
        "torpy_available": TORPY_AVAILABLE,
        "requests_available": REQUESTS_AVAILABLE,
        "torpy_cli": check_torpy_cli()
    }
