# Reverse Engineering Methodology for Web Applications

## Sources
- [Black Hat Arsenal Tools](https://github.com/toolswatch/blackhat-arsenal-tools)
- [Awesome Black Hat Tools](https://github.com/UCYBERS/Awesome-Blackhat-Tools)
- [Black Hat Rust](https://github.com/skerkour/black-hat-rust)
- [freeCodeCamp RE Guide](https://www.freecodecamp.org/news/how-to-reverse-engineer-a-website/)

---

## Complete Extraction Checklist

### 1. Initial Reconnaissance
- [ ] Identify all subdomains
- [ ] Port scan all discovered hosts
- [ ] Fingerprint services and versions
- [ ] Check for known CVEs

### 2. Frontend Extraction
- [ ] Download HTML source
- [ ] Extract all JavaScript bundle URLs
- [ ] Check for source maps (.js.map files)
- [ ] Extract source from source maps
- [ ] Identify frontend framework (React, Vue, Svelte, Angular)
- [ ] Look for embedded config/secrets in JS

### 3. API Discovery
- [ ] Analyze Network tab for API calls
- [ ] Extract all endpoint URLs from JS
- [ ] Check OpenAPI/Swagger endpoints
- [ ] Test unauthenticated endpoints
- [ ] Document request/response formats

### 4. Configuration Extraction
- [ ] /api/config, /config, /api/v1/config
- [ ] /api/version, /version
- [ ] /health, /healthz, /status
- [ ] /manifest.json
- [ ] /.well-known/*
- [ ] /robots.txt, /sitemap.xml

### 5. Source Map Extraction
```bash
# Find source maps in HTML
grep -oP 'src="[^"]+\.js"' index.html

# Check if .map exists
curl -I "https://target/bundle.js.map"

# Extract sources from map
python3 -c "
import json
with open('bundle.js.map') as f:
    data = json.load(f)
    for i, src in enumerate(data['sources']):
        if data['sourcesContent'][i]:
            # Save source file
            pass
"
```

### 6. Authentication Analysis
- [ ] Identify auth mechanism (JWT, session, API key)
- [ ] Check for auth bypass on endpoints
- [ ] Look for hardcoded credentials in source
- [ ] Test OAuth flows if present

### 7. WebSocket Analysis
- [ ] Connect to WebSocket endpoints
- [ ] Document message formats
- [ ] Identify RPC methods
- [ ] Check for auth requirements

### 8. Technology Stack Identification
- [ ] Frontend framework
- [ ] Backend framework
- [ ] Database type
- [ ] Cache systems
- [ ] Message queues
- [ ] Cloud provider

---

## BlackBox Integration

### Available Tools
```bash
# Source map extraction
python -m modules.intel.sourcemap_extractor <url>

# Clawdbot scanner
python -m modules.intel.clawdbot_scanner <target>

# Open WebUI scanner
python -m modules.intel.openwebui_scanner <target>

# Endpoint discovery
python -m modules.intel.endpoint_discovery <target>

# JS intelligence
python -m modules.intel.js_intel <js_file>

# WebSocket analysis
python -m modules.intel.websocket_analyzer <ws_url>
```

### CLI Commands
```bash
blackbox intel clawdbot <target> [--deep]
blackbox intel openwebui <target> [port]
blackbox intel sourcemap <url> [-o output_dir]
blackbox intel fullscan <target>
blackbox intel h1-status
```

---

## External Tool References

### Black Hat Arsenal
- [toolswatch/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools)
- Categories: Web, Mobile, Network, OSINT, Exploitation

### Reconnaissance
- Amass - subdomain enumeration
- httpx - HTTP probing
- nuclei - vulnerability scanning
- katana - crawler

### Source Extraction
- @electron/asar - Electron app extraction
- Bytecode Viewer - Java decompilation
- source-map-explorer - JS source map analysis
- webpack-bundle-analyzer

---

*BlackBox Security Assessment Framework*
*DeadMan Toolkit v5.3*
