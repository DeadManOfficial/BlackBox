# BlackBox AI - CLI Reference

## Installation

```bash
# Install from source
pip install -e .

# Verify installation
blackbox --version
```

---

## Global Options

```bash
blackbox [OPTIONS] COMMAND [ARGS]...

Options:
  -v, --verbose          Enable verbose output
  -q, --quiet            Suppress banner and info messages
  -o, --output FORMAT    Output format: text, json, table (default: text)
  -c, --config-file PATH Path to config file
  --version              Show version and exit
  --help                 Show help and exit
```

---

## Command Groups

### modules - Module Management

```bash
# List all modules
blackbox modules list

# Get module info
blackbox modules info <module_name>

# Reload a module
blackbox modules reload <module_name>

# Enable/disable modules
blackbox modules enable <module_name>
blackbox modules disable <module_name>
```

### scan - Security Scanning

```bash
# Nuclei vulnerability scan
blackbox scan nuclei <target> [OPTIONS]
  --severity TEXT     Severity filter (default: high,critical)
  --tags TEXT         Template tags
  --timeout INTEGER   Timeout in seconds (default: 600)

# Nmap port scan
blackbox scan nmap <target> [OPTIONS]
  --ports TEXT        Port range (default: 1-1000)
  --args TEXT         Additional nmap arguments
  --timeout INTEGER   Timeout in seconds (default: 300)

# Gobuster directory scan
blackbox scan gobuster <target> [OPTIONS]
  --wordlist PATH     Wordlist path
  --extensions TEXT   File extensions to search
  --threads INTEGER   Number of threads (default: 50)

# Port scan shorthand
blackbox scan ports <target> [OPTIONS]
  --ports TEXT        Port range
  --fast              Fast scan mode

# Vulnerability scan shorthand
blackbox scan vuln <target> [OPTIONS]
  --severity TEXT     Severity filter

# Web application scan
blackbox scan web <url> [OPTIONS]
  --full              Full web assessment
```

### recon - Reconnaissance

```bash
# Subdomain enumeration
blackbox recon subdomain <domain> [OPTIONS]
  --tools TEXT        Tools to use (subfinder, amass)
  --passive           Passive only mode

# Technology detection
blackbox recon tech <target>

# WHOIS lookup
blackbox recon whois <domain>

# DNS records
blackbox recon dns <domain> [OPTIONS]
  --type TEXT         Record type (A, AAAA, MX, TXT, etc.)
```

### web - Web Application Testing

```bash
# Directory enumeration
blackbox web directories <url> [OPTIONS]
  --wordlist PATH     Custom wordlist

# Parameter discovery
blackbox web params <url>

# SQLMap scan
blackbox web sqlmap <url> [OPTIONS]
  --method TEXT       HTTP method (GET, POST)
  --data TEXT         POST data
  --level INTEGER     Testing level (1-5)
```

### pentest - Penetration Testing

```bash
# Start assessment
blackbox pentest start <target> [OPTIONS]
  --scope TEXT        Scope definition

# Check status
blackbox pentest status

# Set current phase
blackbox pentest phase <P1|P2|P3|P4|P5|P6>

# List phase tools
blackbox pentest tools <phase>

# Add finding
blackbox pentest finding [OPTIONS]
  -p, --phase TEXT      Phase (P1-P6) [required]
  -s, --severity TEXT   Severity [required]
  -t, --title TEXT      Finding title [required]
  -d, --description TEXT Description [required]
  --tool TEXT           Tool that found it (default: manual)

# Export report
blackbox pentest export [OPTIONS]
  -f, --format TEXT     Format: json, md, html (default: json)
  -o, --output PATH     Output file [required]
```

### ctf - CTF Utilities

```bash
# Decode data (auto-detect encoding)
blackbox ctf decode <data>

# ROT cipher
blackbox ctf rot <text> [OPTIONS]
  --shift INTEGER     Rotation amount (default: 13)
  --all               Try all rotations

# XOR operations
blackbox ctf xor <data> --key TEXT

# Generate hashes
blackbox ctf hash <text>

# Identify hash type
blackbox ctf identify-hash <hash>

# Analyze file
blackbox ctf analyze <file_path>
```

### payloads - Payload Generation

```bash
# List available templates
blackbox payloads list

# Generate shellcode
blackbox payloads shellcode <template> [OPTIONS]
  --lhost TEXT        Local host IP
  --lport INTEGER     Local port (default: 4444)
  --format TEXT       Output format

# Encode payload
blackbox payloads encode <payload> [OPTIONS]
  --methods TEXT      Encoding methods (comma-separated)
                      Options: base64, hex, url, unicode, html, rot13

# List XSS payloads
blackbox payloads xss

# List SQLi payloads
blackbox payloads sqli
```

### agent - AI Security Agents

```bash
# List available agents
blackbox agent list

# Get agent system prompt
blackbox agent prompt <agent_name>

# Run agent task
blackbox agent run <agent_name> --task TEXT

# Available agents:
#   - penetration-tester
#   - red-team
#   - bug-bounty-hunter
#   - threat-analyst
#   - security-auditor
#   - code-reviewer
#   - forensics-analyst
#   - osint-researcher
```

### server - API Server

```bash
# Start server
blackbox server [OPTIONS]
  --port INTEGER      Port to listen on (default: 8888)
  --host TEXT         Host to bind to (default: 0.0.0.0)
  --debug             Enable debug mode
```

---

## Examples

### Basic Scanning Workflow

```bash
# 1. Port scan
blackbox -q scan ports example.com --ports 1-10000

# 2. Subdomain enumeration
blackbox -q recon subdomain example.com

# 3. Vulnerability scan
blackbox -q scan nuclei example.com --severity high,critical

# 4. Web application scan
blackbox -q scan web https://example.com --full
```

### CTF Challenge Workflow

```bash
# Decode base64 flag
blackbox -q ctf decode "SGVsbG8gV29ybGQh"
# Output: Hello World!

# Try ROT13
blackbox -q ctf rot "uryyb" --shift 13
# Output: hello

# Identify hash
blackbox -q ctf identify-hash "d41d8cd98f00b204e9800998ecf8427e"
# Output: MD5

# Analyze suspicious file
blackbox -q ctf analyze challenge.bin
```

### Pentest Workflow

```bash
# Start assessment
blackbox pentest start target.com

# Check phase 1 tools
blackbox pentest tools P1

# Add finding
blackbox pentest finding \
  -p P2 \
  -s high \
  -t "SQL Injection" \
  -d "Found SQLi in login form"

# Export report
blackbox pentest export -f md -o report.md
```

### Payload Generation

```bash
# Generate reverse shell
blackbox payloads shellcode reverse_shell_bash --lhost 10.0.0.1 --lport 4444

# Encode for evasion
blackbox payloads encode "malicious_payload" --methods base64,hex
```

### JSON Output

```bash
# Get JSON output for scripting
blackbox -q -o json scan nuclei example.com | jq '.findings'

# Parse module list
blackbox -q -o json modules list | jq '.modules[].name'
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BLACKBOX_CONFIG` | Path to config file | `~/.blackbox/config.yaml` |
| `BLACKBOX_OUTPUT_DIR` | Default output directory | `./output` |
| `BLACKBOX_LOG_LEVEL` | Logging level | `INFO` |
| `BLACKBOX_TIMEOUT` | Default timeout (seconds) | `300` |

---

## Configuration File

`~/.blackbox/config.yaml`:

```yaml
defaults:
  output_format: text
  timeout: 300
  verbose: false

scanning:
  nuclei:
    severity: "high,critical"
    rate_limit: 150
  nmap:
    default_args: "-sV"

pentest:
  auto_save: true
  report_format: md

modules:
  disabled:
    - darkweb
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Tool not available |
| 4 | Timeout exceeded |
| 5 | Permission denied |
