# Getting Started with BlackBox AI

## Overview

BlackBox AI is a unified security platform that consolidates 150+ security tools into a single, extensible framework. It provides:

- **CLI Interface** - Command-line access to all tools
- **REST API** - HTTP endpoints for automation
- **MCP Interface** - AI agent integration via Model Context Protocol
- **Modular Architecture** - Easily extend with custom modules

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/blackbox/blackbox-ai.git
cd blackbox-ai

# Create virtual environment
python3 -m venv blackbox-env
source blackbox-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install CLI
pip install -e .
```

### 2. Verify Installation

```bash
# Check CLI
blackbox --version
# BlackBox AI 1.0.0

# List modules
blackbox modules list
```

### 3. Basic Usage

```bash
# Port scan
blackbox scan ports scanme.nmap.org

# Vulnerability scan
blackbox scan nuclei https://example.com

# Subdomain enumeration
blackbox recon subdomain example.com
```

---

## Core Concepts

### Modules

BlackBox is organized into **modules**, each containing related tools:

| Module | Purpose | Key Tools |
|--------|---------|-----------|
| `core_scanning` | Vulnerability scanning | nmap, nuclei, gobuster |
| `reconnaissance` | Information gathering | subfinder, amass, httpx |
| `web_attacks` | Web app testing | sqlmap, XSStrike, commix |
| `cloud_security` | Cloud assessment | prowler, trivy, cloudfox |
| `pentest` | Penetration testing | Phase-based methodology |
| `ctf` | CTF utilities | Crypto, encoding, forensics |
| `payloads` | Payload generation | Shellcode, encoders |
| `agents` | AI agent prompts | Security personas |

### Wrappers

External tools are integrated via **wrappers** that provide:
- Standardized input/output
- Timeout handling
- Output parsing
- Error management

### Workflows

Combine tools into **workflows** for complex assessments:
- Pentest phases (P1-P6)
- Bug bounty methodology
- Red team operations

---

## Using the CLI

### Command Structure

```bash
blackbox [global-options] <command-group> <command> [options] [arguments]
```

### Global Options

```bash
-v, --verbose    # Detailed output
-q, --quiet      # Suppress banner
-o, --output     # Output format (text/json/table)
```

### Examples

```bash
# Quiet mode with JSON output
blackbox -q -o json scan nuclei example.com

# Verbose scanning
blackbox -v scan ports target.com --ports 1-65535

# Help for any command
blackbox scan nuclei --help
```

---

## Using the API

### Start the Server

```bash
blackbox server --port 8888
```

### Make Requests

```bash
# Health check
curl http://localhost:8888/health

# Scan request
curl -X POST http://localhost:8888/api/scan/nuclei \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "severity": "high,critical"}'
```

### Python Client

```python
import requests

BASE_URL = "http://localhost:8888"

# List modules
response = requests.get(f"{BASE_URL}/api/modules")
modules = response.json()

# Run scan
response = requests.post(f"{BASE_URL}/api/scan/nmap", json={
    "target": "192.168.1.1",
    "ports": "1-1000"
})
results = response.json()
```

---

## Using with AI Agents

BlackBox integrates with AI agents via MCP (Model Context Protocol).

### MCP Integration

BlackBox integrates with Claude via the **deadman-toolkit** MCP server (116 tools).

See `~/.claude/MCP.md` for server configuration.

### Available MCP Tools

Tools available through deadman-toolkit:

- `nuclei_scan`, `nuclei_templates` - Vulnerability scanning
- `intel_*` - Intelligence gathering (CVE, exploits, MITRE)
- `js_analyze`, `secret_scan_*` - Static analysis
- `ssrf_scan`, `jwt_analyze`, `idor_scan` - Web attacks
- `pentest_run`, `pentest_attack_path` - Penetration testing

---

## Penetration Testing Workflow

BlackBox uses a 6-phase pentest methodology:

### Phases

| Phase | Name | Focus |
|-------|------|-------|
| P1 | Reconnaissance | Information gathering |
| P2 | Surface Discovery | Attack surface mapping |
| P3 | Authentication | Auth mechanism testing |
| P4 | Injection | Input validation |
| P5 | Logic/Access | Business logic, access control |
| P6 | Post-Exploitation | Persistence, lateral movement |

### Workflow Example

```bash
# Start assessment
blackbox pentest start target.com

# Check current status
blackbox pentest status

# Get phase-appropriate tools
blackbox pentest tools P1

# Add finding
blackbox pentest finding \
  -p P2 -s high \
  -t "SQL Injection" \
  -d "SQLi in login form parameter"

# Export report
blackbox pentest export -f md -o report.md
```

---

## CTF Utilities

Quick tools for CTF challenges:

```bash
# Decode base64
blackbox ctf decode "SGVsbG8gV29ybGQh"

# ROT cipher
blackbox ctf rot "uryyb" --shift 13

# All ROT shifts
blackbox ctf rot "gur_synt" --all

# Hash generation
blackbox ctf hash "password123"

# Hash identification
blackbox ctf identify-hash "5f4dcc3b5aa765d61d8327deb882cf99"

# File analysis
blackbox ctf analyze suspicious.bin
```

---

## Creating Custom Modules

### Module Structure

```
modules/
└── my_module/
    ├── __init__.py
    └── module.py
```

### Basic Module

```python
# modules/my_module/module.py
from modules.base import BaseModule, ModuleCategory

class MyModule(BaseModule):
    name = "my_module"
    version = "1.0.0"
    category = ModuleCategory.UTILITY
    description = "My custom module"

    def register_tools(self, mcp, client):
        @mcp.tool()
        def my_tool(target: str) -> str:
            """My custom security tool"""
            return f"Scanning {target}"

    def register_routes(self, app):
        @app.route('/api/my-module/scan', methods=['POST'])
        def my_scan():
            return {"status": "complete"}
```

### Enable the Module

Add to `config/modules.yaml`:

```yaml
modules:
  my_module:
    enabled: true
    custom_setting: "value"
```

---

## Security Considerations

- Run BlackBox in isolated environments for production use
- Only test systems you own or have explicit permission to test
- Review tool outputs before automated processing
- Implement authentication for exposed API endpoints
- Monitor resource usage during intensive scans

---

## Troubleshooting

### Common Issues

**Tool not found**:
```bash
# Check if tool is installed
which nmap nuclei

# Install missing tools
sudo apt install nmap
```

**Module not loading**:
```bash
# Check module status
blackbox modules list

# Enable module
blackbox modules enable <module_name>
```

**API server issues**:
```bash
# Check port availability
netstat -tlnp | grep 8888

# Start with debug
blackbox server --debug
```

---

## Next Steps

- Explore the [CLI Reference](cli-reference.md)
- Read the [API Reference](api-reference.md)
- Learn about [Module Development](module-development.md)
- Check out [Example Workflows](workflows/)
