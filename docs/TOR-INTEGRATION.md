# Portable Tor Integration Guide
## BlackBox Anonymous Operations Framework

**Status:** Implementation Ready
**Purpose:** Dark web research, anonymous operations, credential intelligence

---

## 1. Integration Options

### Option Comparison
| Approach | Portability | Speed | Reliability | Dependencies |
|----------|-------------|-------|-------------|--------------|
| **torpy** (Pure Python) | Excellent | Medium | Good | None |
| **stem + Tor Binary** | Good | Fast | Excellent | Tor daemon |
| **Tor Browser Extract** | Good | Fast | Excellent | Tor Browser |
| **Docker Container** | Moderate | Fast | Excellent | Docker |

---

## 2. Pure Python Implementation (torpy)

### Installation
```bash
pip install torpy[requests]
```

### Basic Usage
```python
from torpy.http.requests import TorRequests

# Anonymous HTTP request (no Tor daemon needed)
with TorRequests() as tor_requests:
    with tor_requests.get_session() as session:
        response = session.get("http://check.torproject.org")
        print(response.text)
```

### SOCKS5 Proxy Mode
```python
from torpy import TorClient

# Create a SOCKS5 proxy
with TorClient() as tor:
    with tor.create_circuit(3) as circuit:  # 3 hops
        with circuit.create_stream(('check.torproject.org', 80)) as stream:
            # Direct socket operations
            stream.send(b'GET / HTTP/1.0\r\nHost: check.torproject.org\r\n\r\n')
            print(stream.recv(1024))
```

### Dark Web Access (.onion)
```python
from torpy.http.requests import TorRequests

with TorRequests() as tor_requests:
    with tor_requests.get_session() as session:
        # Access hidden service
        response = session.get("http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion")
        print(response.text)
```

---

## 3. Stem + Tor Binary Integration

### A. Extract Tor from Tor Browser (Portable)

**Linux/macOS:**
```bash
# Download Tor Browser
wget https://www.torproject.org/dist/torbrowser/13.0/tor-browser-linux-x86_64-13.0.tar.xz
tar xf tor-browser-linux-x86_64-13.0.tar.xz

# Extract Tor binary
TOR_PATH="./tor-browser/Browser/TorBrowser/Tor/tor"
```

**Windows:**
```powershell
# Tor binary location after Tor Browser install
$TOR_PATH = "$env:USERPROFILE\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"
```

### B. Programmatic Tor Launch

```python
import stem.process
from stem.control import Controller
import requests

# Configuration
SOCKS_PORT = 9050
CONTROL_PORT = 9051
TOR_PATH = "./tor"  # Path to tor binary

# Launch Tor
tor_process = stem.process.launch_tor_with_config(
    config={
        'SocksPort': str(SOCKS_PORT),
        'ControlPort': str(CONTROL_PORT),
        'DataDirectory': './tor_data',
        'Log': 'notice stdout',
    },
    init_msg_handler=lambda line: print(f"[TOR] {line}") if 'Bootstrapped' in line else None,
    tor_cmd=TOR_PATH
)

# Use with requests
proxies = {
    'http': f'socks5h://127.0.0.1:{SOCKS_PORT}',
    'https': f'socks5h://127.0.0.1:{SOCKS_PORT}'
}

response = requests.get('http://check.torproject.org', proxies=proxies)
print(response.text)

# Cleanup
tor_process.terminate()
```

### C. Identity Rotation (New Circuit)

```python
from stem import Signal
from stem.control import Controller

def rotate_identity():
    """Request new Tor circuit for new IP."""
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()  # Uses cookie auth
        controller.signal(Signal.NEWNYM)
        print("New Tor circuit established")

# Rate limit: Wait 10 seconds between rotations
import time
rotate_identity()
time.sleep(10)
rotate_identity()
```

---

## 4. Docker-Based Tor

### docker-compose.yml
```yaml
version: '3'
services:
  tor:
    image: dperson/torproxy
    ports:
      - "9050:9050"  # SOCKS5
      - "9051:9051"  # Control
    environment:
      - PASSWORD=your_control_password
    restart: unless-stopped

  blackbox:
    build: .
    depends_on:
      - tor
    environment:
      - TOR_PROXY=socks5://tor:9050
```

### Usage from BlackBox
```python
import os
import requests

TOR_PROXY = os.environ.get('TOR_PROXY', 'socks5://127.0.0.1:9050')

proxies = {
    'http': TOR_PROXY,
    'https': TOR_PROXY
}

response = requests.get('http://check.torproject.org', proxies=proxies)
```

---

## 5. BlackBox Integration Module

### File: `modules/tor/client.py`

```python
"""
BlackBox Tor Integration Module
Provides anonymous network access for dark web research
"""

import os
import time
import tempfile
import requests
from typing import Optional
from contextlib import contextmanager

try:
    from torpy.http.requests import TorRequests
    TORPY_AVAILABLE = True
except ImportError:
    TORPY_AVAILABLE = False

try:
    import stem.process
    from stem.control import Controller
    from stem import Signal
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False


class TorClient:
    """Unified Tor client for BlackBox operations."""

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        tor_binary: Optional[str] = None,
        use_torpy: bool = False
    ):
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_binary = tor_binary
        self.use_torpy = use_torpy
        self.tor_process = None
        self._session = None

    @property
    def proxies(self) -> dict:
        """Get proxy configuration for requests library."""
        return {
            'http': f'socks5h://127.0.0.1:{self.socks_port}',
            'https': f'socks5h://127.0.0.1:{self.socks_port}'
        }

    def start(self) -> None:
        """Start Tor connection."""
        if self.use_torpy and TORPY_AVAILABLE:
            # Pure Python mode - no daemon needed
            return

        if self.tor_binary and STEM_AVAILABLE:
            # Launch Tor daemon
            self.tor_process = stem.process.launch_tor_with_config(
                config={
                    'SocksPort': str(self.socks_port),
                    'ControlPort': str(self.control_port),
                    'DataDirectory': tempfile.mkdtemp(),
                    'CookieAuthentication': '1',
                },
                tor_cmd=self.tor_binary
            )

    def stop(self) -> None:
        """Stop Tor connection."""
        if self.tor_process:
            self.tor_process.terminate()
            self.tor_process = None

    def new_identity(self) -> None:
        """Request new Tor circuit."""
        if self.use_torpy:
            # torpy handles this per-request
            return

        if STEM_AVAILABLE:
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
            time.sleep(10)  # Rate limit

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make anonymous GET request."""
        if self.use_torpy and TORPY_AVAILABLE:
            with TorRequests() as tor:
                with tor.get_session() as session:
                    return session.get(url, **kwargs)
        else:
            return requests.get(url, proxies=self.proxies, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        """Make anonymous POST request."""
        if self.use_torpy and TORPY_AVAILABLE:
            with TorRequests() as tor:
                with tor.get_session() as session:
                    return session.post(url, **kwargs)
        else:
            return requests.post(url, proxies=self.proxies, **kwargs)

    @contextmanager
    def session(self):
        """Context manager for Tor session."""
        self.start()
        try:
            yield self
        finally:
            self.stop()


# Convenience function
def anonymous_request(url: str, method: str = 'GET', **kwargs) -> requests.Response:
    """Quick anonymous request without managing client."""
    client = TorClient(use_torpy=TORPY_AVAILABLE)
    with client.session():
        if method.upper() == 'GET':
            return client.get(url, **kwargs)
        elif method.upper() == 'POST':
            return client.post(url, **kwargs)


# Check Tor connectivity
def check_tor() -> dict:
    """Verify Tor connection and get exit node info."""
    client = TorClient(use_torpy=TORPY_AVAILABLE)
    with client.session():
        response = client.get('https://check.torproject.org/api/ip')
        data = response.json()
        return {
            'connected': data.get('IsTor', False),
            'ip': data.get('IP'),
            'country': data.get('Country', 'Unknown')
        }
```

---

## 6. Dark Web Research Integration

### A. TorBot Integration (Already in BlackBox)

```bash
# Location
external-tools/TorBot/

# Usage
cd external-tools/TorBot
poetry install
poetry run python torbot -u http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion --depth 2 --visualize tree
```

### B. Dark Web Intelligence Sources

**Available in BlackBox:**
| Source | Location | Purpose |
|--------|----------|---------|
| **deepdarkCTI** | `external-tools/deepdarkCTI/` | Markets, Telegram channels |
| **TorBot** | `external-tools/TorBot/` | Onion crawler |
| **darkdump** | `external-tools/darkdump/` | Dark web search |

### C. Credential Intelligence Workflow

```python
from modules.tor.client import TorClient

# Initialize Tor client
tor = TorClient(use_torpy=True)

with tor.session():
    # 1. Check credential leak sites
    # (Use responsibly for defensive research only)

    # 2. Monitor paste sites
    response = tor.get("http://stronghold...onion/paste/recent")

    # 3. Rotate identity between sensitive queries
    tor.new_identity()
```

---

## 7. Security Considerations

### DNS Leak Prevention
```python
# Use socks5h:// (h = host resolution via proxy)
proxies = {
    'http': 'socks5h://127.0.0.1:9050',  # Correct
    'https': 'socks5h://127.0.0.1:9050'
}

# NOT socks5:// which leaks DNS
# 'http': 'socks5://127.0.0.1:9050'  # WRONG - DNS leak!
```

### User Agent Rotation
```python
from fake_useragent import UserAgent

ua = UserAgent()

def get_anonymous(url):
    headers = {'User-Agent': ua.random}
    return tor.get(url, headers=headers)
```

### Rate Limiting
```python
import time
import random

def polite_scrape(urls):
    for url in urls:
        response = tor.get(url)
        # Random delay 5-15 seconds
        time.sleep(random.uniform(5, 15))
        yield response
```

---

## 8. Installation Script

### `scripts/setup-tor.sh`
```bash
#!/bin/bash
# BlackBox Tor Setup Script

echo "=== BlackBox Tor Integration Setup ==="

# Install Python dependencies
pip install torpy[requests] stem pysocks fake-useragent

# Download portable Tor (Linux)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    TOR_VERSION="13.0"
    wget -q "https://www.torproject.org/dist/torbrowser/${TOR_VERSION}/tor-browser-linux-x86_64-${TOR_VERSION}.tar.xz"
    tar xf "tor-browser-linux-x86_64-${TOR_VERSION}.tar.xz"
    ln -sf "tor-browser/Browser/TorBrowser/Tor/tor" ./tor
    rm "tor-browser-linux-x86_64-${TOR_VERSION}.tar.xz"
    echo "Tor binary: ./tor"
fi

# Verify
python -c "from torpy.http.requests import TorRequests; print('torpy: OK')"
python -c "import stem; print('stem: OK')"

echo "=== Setup Complete ==="
echo "Usage:"
echo "  Pure Python: TorClient(use_torpy=True)"
echo "  With daemon: TorClient(tor_binary='./tor')"
```

---

## 9. Tools Available

### In BlackBox
| Tool | Location | Purpose |
|------|----------|---------|
| **TorBot** | `external-tools/TorBot/` | OWASP onion crawler |
| **darkdump** | `external-tools/darkdump/` (if installed) | Dark web search |
| **OnionSearch** | `external-tools/OnionSearch/` (if installed) | Onion URL search |
| **deepdarkCTI** | `external-tools/deepdarkCTI/` | Dark web intelligence |

### MCP Tools
| Tool | Purpose |
|------|---------|
| `stealth_fetch` | Anti-detect browser fetch |
| `hyperbrowser` | Profile-based browser automation |

### External Tools to Add
| Tool | Source | Purpose |
|------|--------|---------|
| **DarkScrape** | github.com/JoelGMSec/DarkScrape | Dark web scraping |
| **Ahmia** | ahmia.fi | Hidden service search |
| **torch** | torch search engine | Onion indexer |

---

## 10. Usage Examples

### Basic Anonymous Request
```python
from modules.tor.client import check_tor, anonymous_request

# Verify Tor
status = check_tor()
print(f"Connected: {status['connected']}, IP: {status['ip']}")

# Anonymous GET
response = anonymous_request('https://api.ipify.org')
print(f"Exit IP: {response.text}")
```

### Dark Web Crawling
```python
from modules.tor.client import TorClient

tor = TorClient(use_torpy=True)

onion_urls = [
    "http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    # Add more onion URLs for research
]

with tor.session():
    for url in onion_urls:
        try:
            response = tor.get(url, timeout=30)
            print(f"{url}: {response.status_code}")
        except Exception as e:
            print(f"{url}: Error - {e}")
        tor.new_identity()  # Rotate between sites
```

### Credential Intelligence
```python
from modules.tor.client import TorClient
import json

tor = TorClient(use_torpy=True)

with tor.session():
    # Check Have I Been Pwned via Tor
    # (Example - replace with actual API usage)
    response = tor.get("https://haveibeenpwned.com/api/v3/breachedaccount/test@test.com")

    # Monitor paste sites for leaks
    # (Defensive research only)
```

---

## 11. References

- [torpy - Pure Python Tor](https://github.com/torpyorg/torpy)
- [stem - Tor Controller Library](https://stem.torproject.org/)
- [TorBot - OWASP Dark Web Crawler](https://github.com/DedSecInside/TorBot)
- [Tor Project Downloads](https://www.torproject.org/download/)
- [Using Tor with Python](https://sylvaindurand.org/use-tor-with-python/)

---

*Documentation completed: 2026-01-27*
*Part of BlackBox - DEADMAN Security Platform*
