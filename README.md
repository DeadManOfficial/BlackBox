<p align="center">
  <img src="https://img.shields.io/badge/Version-6.0-black?style=for-the-badge&logo=github" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux&logoColor=white" alt="Platform"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/MCP-Enabled-purple?style=flat-square" alt="MCP"/>
  <img src="https://img.shields.io/badge/Claude-Opus%204.5-blueviolet?style=flat-square" alt="Claude"/>
  <img src="https://img.shields.io/badge/Security-Audited-brightgreen?style=flat-square" alt="Audited"/>
</p>

```
██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
```

<p align="center">
  <strong>Autonomous Security Research Platform</strong><br>
  <em>Extract Everything • Attack Everything • Document Everything</em>
</p>

---

## Overview

**BlackBox** is a modular, AI-powered security research platform designed for authorized penetration testing and bug bounty hunting. Built on the **DeadMan Toolkit** framework, it provides a comprehensive suite of tools for reconnaissance, vulnerability discovery, exploitation, and reporting.

### Philosophy

```
SAFETY > DETERMINISM > OPTIMIZATION > LEARNING
```

### Core Principles

- **Authorization First** — Never test without explicit permission
- **Evidence-Based** — All findings require reproducible proof
- **Minimal Impact** — Use least-invasive techniques
- **Ethical Conduct** — Responsible disclosure always

---

## Features

<table>
<tr>
<td width="50%">

### 🔍 Reconnaissance
- Multi-engine search aggregation
- Subdomain enumeration
- Technology fingerprinting
- JavaScript analysis & RE

</td>
<td width="50%">

### 🎯 Vulnerability Scanning
- Nuclei template integration
- Custom payload libraries
- SSRF/XSS/SQLi detection
- API endpoint discovery

</td>
</tr>
<tr>
<td>

### 🌐 Scraping & Extraction
- 5-layer adaptive downloader
- Anti-detection stealth suite
- TOR/proxy rotation
- Dark web crawling

</td>
<td>

### 🤖 AI Integration
- Free LLM routing (Mistral, Groq, Cerebras)
- Intelligent relevance filtering
- Automated vulnerability analysis
- Report generation

</td>
</tr>
<tr>
<td>

### 📊 Reporting
- HackerOne draft generation
- Markdown/HTML/JSON export
- Evidence management
- CVSS scoring

</td>
<td>

### 🔧 MCP Tools
- 116+ security tools via MCP
- Claude Code integration
- Pipeline orchestration
- Real-time dashboards

</td>
</tr>
</table>

---

## Architecture

```
BlackBox/
├── blackbox.py              # CLI entry point
├── modules/
│   ├── pentest/             # Attack orchestration
│   │   ├── mcp_bridge.py    # MCP tool executor
│   │   ├── bounty.py        # Bug bounty tracking
│   │   └── orchestrator.py  # Phase management
│   ├── scraper/             # 5-layer adaptive scraper
│   │   ├── core/            # Engine, scheduler, config
│   │   ├── ai/              # LLM routing, token optimization
│   │   ├── fetch/           # TOR, proxies, downloader
│   │   ├── stealth/         # Anti-detection, fingerprinting
│   │   ├── storage/         # MongoDB, Elasticsearch
│   │   └── darkweb/         # Onion scraping
│   ├── intel/               # Intelligence gathering
│   ├── security/            # Security scanners
│   └── reporting/           # Report generation
├── workflows/
│   ├── pipeline.py          # GATE orchestrator
│   └── *.yaml               # Workflow definitions
├── cli/                     # Command extensions
├── docs/                    # Methodology & playbooks
├── config/                  # Configuration files
└── targets/                 # Per-target data
```

---

## GATE Pipeline

The BlackBox pipeline follows a strict gate-based methodology:

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│ GATE 0  │──▶│ GATE 1  │──▶│ GATE 2  │──▶│ GATE 3  │──▶│ GATE 4  │──▶│ GATE 5  │
│  INIT   │   │  INTEL  │   │  RECON  │   │ EXTRACT │   │ ATTACK  │   │ VERIFY  │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘   └─────────┘
     │             │             │             │             │             │
     ▼             ▼             ▼             ▼             ▼             ▼
  Scope &      Threat       Surface        Data         Vuln        Double
  Auth         Intel        Mapping      Extraction   Discovery    Verify
```

**Rule:** No halts. Checkpoint and continue.

---

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/DeadManOfficial/BlackBox.git
cd BlackBox

# Install dependencies
pip install -r requirements.txt

# Verify installation
python scripts/verify_imports.py
```

### Usage

```bash
# Full pipeline scan
python blackbox.py scan --target example.com

# Individual phases
python blackbox.py intel example.com
python blackbox.py recon example.com
python blackbox.py extract example.com
python blackbox.py attack example.com
python blackbox.py verify example.com

# Generate report
python blackbox.py report example.com --format markdown
```

### Docker

```bash
docker build -t blackbox .
docker run -it --rm blackbox scan --target example.com
```

---

## MCP Integration

BlackBox integrates with **116+ security tools** via the Model Context Protocol:

<details>
<summary><b>🔧 Available Tool Categories (Click to expand)</b></summary>

| Category | Tools | Description |
|----------|-------|-------------|
| `intel_*` | 8 | CVE search, exploit DB, threat intel |
| `nuclei_*` | 2 | Template scanning |
| `js_*` | 3 | JavaScript analysis |
| `secret_*` | 5 | Secret/credential scanning |
| `ssrf_*` | 1 | SSRF detection |
| `jwt_*` | 1 | JWT analysis |
| `llm_*` | 3 | LLM red teaming |
| `pentest_*` | 3 | Penetration testing |
| `oauth_*` | 2 | OAuth flow testing |
| `idor_*` | 1 | IDOR detection |
| `graphql_*` | 1 | GraphQL scanning |
| `cors_*` | 1 | CORS misconfiguration |
| `waf_*` | 2 | WAF bypass techniques |
| `race_*` | 2 | Race condition testing |
| `cache_*` | 1 | Cache poisoning |
| `websocket_*` | 1 | WebSocket security |
| `...` | 80+ | And many more |

</details>

---

## Token Optimization

BlackBox implements strict token management for efficient AI operations:

```
┌────────────────────────────────────────────────────────────────┐
│  T0: ToolSearch BEFORE MCP calls          │  46% reduction    │
│  T1: Truncate responses > 10KB            │  head+tail        │
│  T2: Checkpoint after each gate           │  state preserved  │
│  T3: Files for data, context summary      │  minimal context  │
│  T4: Batch operations in chunks           │  10 items max     │
└────────────────────────────────────────────────────────────────┘
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [BOUNTY_RULEBOOK.md](docs/BOUNTY_RULEBOOK.md) | Bug bounty methodology |
| [ATTACK-PLAYBOOK.md](docs/ATTACK-PLAYBOOK.md) | Attack techniques |
| [TOOLKIT_REFERENCE.md](docs/TOOLKIT_REFERENCE.md) | Tool documentation |
| [getting-started.md](docs/getting-started.md) | Setup guide |
| [AUDIT_PROTOCOL.md](docs/AUDIT_PROTOCOL.md) | Double-gate verification |

---

## Audit Protocol

All code changes go through double-gate verification:

```
GATE_1 (DETECT) ──▶ GATE_2 (VERIFY) ──▶ FINAL (TEST)
```

```bash
# Verify all imports work
python scripts/verify_imports.py

# Audit for broken references
python scripts/audit_references.py
```

**Rule:** No ruling without double verification. No fix without test confirmation.

---

## Security Axioms

```python
AXIOM_0: Safety is non-negotiable and always supersedes performance
AXIOM_1: All failures must be bounded, detectable, and recoverable
AXIOM_2: Determinism is required for all safety-critical paths
AXIOM_3: Learned behaviors operate only within verified safety envelopes
AXIOM_4: No single point of failure in critical paths
AXIOM_5: All state transitions must be explicit, bounded, and reversible
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

Please ensure all code passes verification:
```bash
python scripts/verify_imports.py
python scripts/audit_references.py
```

---

## Disclaimer

> ⚠️ **This tool is for authorized security research only.**

- Always obtain written permission before testing
- Follow responsible disclosure practices
- Respect scope limitations absolutely
- Never use for malicious purposes

The authors are not responsible for misuse of this software.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>DEADMAN // DEATH INCARNATE</strong><br>
  <sub>ALL FREE FOREVER</sub>
</p>
