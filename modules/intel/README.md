# BlackBox Intelligence Gathering Modules

Advanced modules for extracting intelligence from targets during security assessments.

## Modules

### 1. Source Map Extractor (`sourcemap_extractor.py`)
Extracts original source code from exposed JavaScript source maps.

**Features:**
- Download and parse .map files
- Extract all original source files
- Identify vendor vs application code
- Scan for hardcoded secrets
- Discover API endpoints
- Detect technologies

**Usage:**
```python
from intel import SourceMapExtractor

extractor = SourceMapExtractor(output_dir="./extracted")
async with extractor:
    result = await extractor.extract_from_url("http://target.com/app.js.map")
    print(extractor.generate_report(result))
```

### 2. JavaScript Intelligence (`js_intel.py`)
Extracts intelligence from JavaScript bundles.

**Features:**
- Find hardcoded secrets and API keys
- Discover API endpoints
- Detect technologies (React, Vue, Angular, etc.)
- Find hidden/admin routes
- Extract feature flags
- Identify internal functions

**Usage:**
```python
from intel import JSIntelligence

intel = JSIntelligence()
result = intel.analyze_url("http://target.com/bundle.js")
print(intel.generate_report(result))
```

### 3. WebSocket Analyzer (`websocket_analyzer.py`)
Analyzes WebSocket-based APIs.

**Features:**
- Protocol handshake analysis
- RPC method enumeration
- Event type discovery
- Authentication mechanism detection
- Vulnerability identification

**Usage:**
```python
from intel import WebSocketAnalyzer

analyzer = WebSocketAnalyzer()
protocol = await analyzer.analyze("ws://target.com:8080")
print(analyzer.generate_report(protocol))
```

### 4. Endpoint Discovery (`endpoint_discovery.py`)
Discovers and maps API endpoints.

**Features:**
- JavaScript bundle analysis
- Common path enumeration
- Swagger/OpenAPI detection
- GraphQL introspection
- WebSocket endpoint detection

**Usage:**
```python
from intel import EndpointDiscovery

discovery = EndpointDiscovery()
async with discovery:
    result = await discovery.discover("http://target.com", deep=True)
    print(discovery.generate_report(result))
```

### 5. Clawdbot Scanner (`clawdbot_scanner.py`)
Specialized scanner for Clawdbot/Moltbot gateway instances.

**Features:**
- Detect exposed control panels
- Check for source map exposure
- Extract configuration
- Identify vulnerabilities

**Usage:**
```python
from intel import ClawdbotScanner

scanner = ClawdbotScanner()
async with scanner:
    result = await scanner.scan_targets(["1.2.3.4", "5.6.7.8"], port=18789)
    print(scanner.generate_report(result))
```

### 6. Open WebUI Scanner (`openwebui_scanner.py`)
Specialized scanner for Open WebUI (AI/LLM Interface) instances.

**Features:**
- Detect exposed deployments
- Extract configuration from /api/config
- Check for known CVEs (CVE-2025-64496, CVE-2025-64495, ZDI-26-031)
- Enumerate API endpoints
- Identify authentication configuration

**Usage:**
```python
from intel import OpenWebUIScanner

scanner = OpenWebUIScanner()
async with scanner:
    result = await scanner.scan_target("1.2.3.4", port=443)
    print(f"Version: {result.version}")
    print(f"Vulnerabilities: {result.vulnerabilities}")
```

## CLI Usage

### BlackBox CLI Integration

```bash
# Scan for Clawdbot instances
blackbox intel clawdbot <target> [--deep]

# Scan for Open WebUI instances
blackbox intel openwebui <target> [port]

# Extract source from source maps
blackbox intel sourcemap <url> [-o output_dir]

# Full multi-service scan
blackbox intel fullscan <target>

# Check HackerOne status
blackbox intel h1-status
```

### Direct Module Usage

Each module can be run directly:

```bash
# Source map extraction
python -m intel.sourcemap_extractor http://target.com/app.js.map

# JavaScript analysis
python -m intel.js_intel http://target.com/bundle.js

# WebSocket analysis
python -m intel.websocket_analyzer ws://target.com:8080

# Endpoint discovery
python -m intel.endpoint_discovery http://target.com

# Clawdbot scanning
python -m intel.clawdbot_scanner targets.txt 18789
```

## Secret Detection

The modules detect various secret types:
- API Keys (generic, AWS, Google, Firebase)
- OAuth tokens (GitHub, Slack, Discord)
- AI API keys (OpenAI, Anthropic)
- Database connection strings
- Private keys (RSA, EC)
- JWT secrets
- Hardcoded passwords

## Integration

Import in BlackBox pipelines:
```python
from modules.intel import (
    SourceMapExtractor,
    JSIntelligence,
    WebSocketAnalyzer,
    EndpointDiscovery,
    ClawdbotScanner
)
```

---
*BlackBox Security Assessment Framework*
