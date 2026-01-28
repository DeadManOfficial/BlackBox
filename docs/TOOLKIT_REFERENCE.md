# DeadMan Toolkit v4.0 - Claude Integration

> **Philosophy**: ALL FREE FOREVER
> **Author**: DeadManOfficial
> **Architecture**: 14 MCP Servers + Sub-Agent Workflow System + Template Systems + Advanced Security Suite (2026 Frontier) + Security Intelligence Aggregation

---

## MCP Servers (14 total)

### Core MCP Servers
| Server | Package | Purpose | Status |
|--------|---------|---------|--------|
| **deadman-toolkit** | Custom | 104 AI tools (16 unique + 14 template + 7 agents + 11 Microsoft + 36 security + 20 misc) | ✓ |
| **memory** | `@modelcontextprotocol/server-memory` | Knowledge graph | ✓ |
| **thinking** | `@modelcontextprotocol/server-sequential-thinking` | Step-by-step reasoning | ✓ |
| **qdrant** | `mcp-server-qdrant` | Vector database | ✓ |
| **playwright** | `@playwright/mcp` | Browser automation | ✓ |

### Integration MCP Servers
| Server | Package | Purpose | Status |
|--------|---------|---------|--------|
| **google** | Custom | Gmail, Drive, Calendar, YouTube, Tasks, Contacts, Sheets, Docs | ✓ |
| **github** | `@modelcontextprotocol/server-github` | Repos, PRs, Issues | ✓ |
| **vercel** | `@robinson_ai_systems/vercel-mcp` | Deployments, Domains, Env Vars | ✓ |
| **netlify** | `@netlify/mcp` | Sites, Deploys, Functions | ✓ |
| **elevenlabs** | `@angelogiacco/elevenlabs-mcp-server` | Text-to-Speech, Voice Cloning | ✓ |
| **lovely-docs** | `lovely-docs` | Library documentation for AI | ✓ |
| **mcp-auditor** | `@officialdeadman/mcp-auditor` | Security, Compliance, Forensic Audits (35 tools) | ✓ |
| **context7** | `@upstash/context7-mcp` | Live documentation retrieval | ✓ |
| **notion** | `mcp-remote` | Notion workspace integration | ✓ |

---

## Template Systems (NEW)

### Fabric Patterns (235 AI prompts)
Source: `danielmiessler/fabric` (38K+ stars)

| Tool | Description |
|------|-------------|
| `fabric_list` | List all 235 patterns by category |
| `fabric_get` | Get specific pattern prompt |
| `fabric_generate` | Generate prompt with pattern + input |
| `fabric_search` | Search patterns by keyword |
| `fabric_recommend` | Get recommendations by use case |

**Categories**: analyze, extract, create, summarize, transform, security, ai

**Examples**:
```bash
# Get malware analysis prompt
Use fabric_get with name="analyze_malware"

# Generate threat model
Use fabric_generate with pattern="create_stride_threat_model" input="[description]"

# Find security patterns
Use fabric_search with keyword="security"
```

### AITMPL (Claude Code Templates - 100 agents, 64 MCPs)
Source: `anthropics/claude-code-templates`

| Tool | Description |
|------|-------------|
| `aitmpl_stats` | Collection statistics |
| `aitmpl_agents` | List agents by category |
| `aitmpl_mcps` | List MCPs by category |
| `aitmpl_get_agent` | Get full agent prompt |
| `aitmpl_get_mcp` | Get MCP configuration |
| `aitmpl_search` | Search agents and MCPs |
| `aitmpl_recommend` | Recommendations by use case |
| `aitmpl_generate` | Generate customized agent prompt |
| `aitmpl_export_mcps` | Export merged MCP configs |

**Agent Categories**:
- `security` (16): penetration-tester, security-auditor, incident-responder, compliance-specialist
- `ai-specialists` (6): prompt-engineer, model-evaluator, ai-ethics-advisor
- `data-ai` (38): data-scientist, ml-engineer, nlp-engineer, computer-vision-engineer
- `devops-infrastructure` (27): cloud-architect, terraform-specialist, kubernetes-expert
- `deep-research-team` (13): research-orchestrator, fact-checker, competitive-intelligence-analyst

**MCP Categories**:
- `devtools` (36): stripe, firecrawl, sentry, grafana, huggingface
- `browser_automation` (6): playwright-mcp, browsermcp, browserbase
- `database` (5): postgresql, supabase, neon, mongodb
- `web` (4): web-fetch, zread, web-search
- Plus: audio, marketing, productivity, deepgraph, deepresearch

**Examples**:
```bash
# Get penetration tester agent
Use aitmpl_get_agent with name="penetration-tester"

# List security agents
Use aitmpl_agents with category="security"

# Get Stripe MCP config
Use aitmpl_get_mcp with name="stripe"

# Export multiple MCPs
Use aitmpl_export_mcps with names=["stripe", "supabase", "sentry"]
```

---

## Security Scanner Suite (2026 Frontier)

Enterprise-grade security assessment tools powered by Python, integrated via MCP. Includes 2026 frontier capabilities: LLM Red Teaming, Autonomous Pentest Agents, and Anti-Detect Browser Automation.

### Nuclei Vulnerability Scanner
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Run Nuclei against target (CVEs, misconfigs, exposures) |
| `nuclei_templates` | List available scan templates |

**Examples**:
```bash
# Scan target for vulnerabilities
Use nuclei_scan with target="https://example.com" severity=["high", "critical"]

# Get available templates
Use nuclei_templates
```

### JavaScript Security Analyzer
| Tool | Description |
|------|-------------|
| `js_analyze` | Analyze JS for secrets, endpoints, debug code |
| `js_analyze_batch` | Batch analyze multiple JS URLs |
| `js_patterns` | List detection patterns |

**Detects**: AWS Keys, Stripe Keys, GitHub Tokens, Private Keys, API Endpoints, Source Maps, Debug Code

**Examples**:
```bash
# Analyze JavaScript file
Use js_analyze with url="https://example.com/app.js"

# Batch analyze
Use js_analyze_batch with urls=["https://example.com/a.js", "https://example.com/b.js"]
```

### AI/LLM Security Tester (Basic)
| Tool | Description |
|------|-------------|
| `ai_security_test` | Test AI endpoint for vulnerabilities |
| `ai_security_categories` | List test categories |

**Tests**: Prompt Injection, Jailbreaks, System Prompt Leaks, Data Exfiltration, Encoding Bypass

**Examples**:
```bash
# Test AI endpoint
Use ai_security_test with url="https://api.example.com/chat" categories=["prompt_injection", "jailbreak"]
```

### LLM Red Team Framework (NEW - 2026)
| Tool | Description |
|------|-------------|
| `llm_redteam_scan` | Comprehensive LLM security assessment (40+ vulnerability types) |
| `llm_redteam_categories` | List vulnerability classes and attack strategies |
| `llm_redteam_payloads` | Get payload library statistics |

**Vulnerability Classes (OWASP Compliant)**:
- LLM01-LLM10: Full OWASP LLM Top 10 2025 coverage
- AG01-AG05: OWASP Agentic AI Top 10 2026 coverage

**Attack Strategies**:
- `direct` - Single-shot attack payloads
- `multi_turn` - Gradual escalation over multiple turns
- `crescendo` - Start benign, escalate to malicious
- `encoding` - Base64, rot13, unicode obfuscation
- `roleplay` - Character/scenario-based attacks
- `chain_of_thought` - Exploit reasoning transparency
- `tool_manipulation` - Agent tool misuse attacks
- `memory_poisoning` - Corrupt agent memory/context

**Examples**:
```bash
# Run comprehensive LLM red team assessment
Use llm_redteam_scan with targetUrl="https://api.example.com/chat" strategies=["direct", "multi_turn", "encoding"]

# Test specific vulnerability classes
Use llm_redteam_scan with targetUrl="https://api.example.com/chat" vulnerabilities=["LLM01", "LLM06", "AG01"]

# Get all vulnerability categories
Use llm_redteam_categories
```

### Autonomous Pentest Agent (NEW - 2026)
| Tool | Description |
|------|-------------|
| `pentest_run` | Run autonomous penetration test (PentestGPT-style) |
| `pentest_attack_path` | Plan optimal attack path using MCTS algorithm |
| `pentest_tools` | List available pentest tools and capabilities |

**Phases**:
- `recon` - Passive information gathering (OSINT, DNS, WHOIS)
- `scanning` - Active port and service scanning
- `enumeration` - Service enumeration and version detection
- `vulnerability` - Vulnerability scanning and assessment
- `exploitation` - Safe exploitation attempts (with safe_mode)
- `post_exploitation` - Privilege escalation analysis
- `reporting` - Comprehensive report generation

**Features**:
- MCTS (Monte Carlo Tree Search) for optimal attack path planning
- LLM-guided decision making for next actions
- Safe mode by default (no destructive actions)
- Integrated tool registry (nmap, nikto, ffuf, nuclei)

**Examples**:
```bash
# Run autonomous pentest
Use pentest_run with target="example.com" phases=["recon", "scanning", "enumeration"]

# Plan attack path
Use pentest_attack_path with initialState={"access": "none"} goalState={"access": "admin"}

# List available tools
Use pentest_tools
```

### Stealth Browser (NEW - 2026)
| Tool | Description |
|------|-------------|
| `stealth_fetch` | Fetch URL with anti-detect browser (bypasses Cloudflare, Akamai) |
| `stealth_session` | Run stealth session with automatic rotation |
| `stealth_engines` | List available browser engines |

**Engines**:
- `camoufox` - C++ level fingerprint masking (Firefox-based, highest stealth)
- `nodriver` - CDP-minimal Chrome automation (undetectable by most anti-bots)
- `playwright` - Fallback with stealth patches (broad compatibility)

**Bypasses**:
- Cloudflare, Akamai, DataDome, PerimeterX, Kasada
- JA3/JA4 TLS fingerprint detection
- Canvas/WebGL fingerprinting
- Headless browser detection

**Examples**:
```bash
# Fetch with stealth browser
Use stealth_fetch with url="https://protected-site.com" engine="auto"

# Run session with rotation
Use stealth_session with urls=["url1", "url2", "url3"] rotateEvery=5

# Get available engines
Use stealth_engines
```

### Advanced Attacks (NEW - 2026)
| Tool | Description |
|------|-------------|
| `waf_bypass_scan` | Discover origin IP behind WAF/CDN |
| `waf_bypass_request` | Send request with encoding chains and fingerprint rotation |
| `race_condition_scan` | Test endpoint for race conditions (TOCTOU, double-spend) |
| `race_condition_batch` | Batch test multiple endpoints |
| `indirect_injection_test` | Test AI for indirect prompt injection |
| `indirect_injection_methods` | List injection methods (unicode, steganographic, markdown) |
| `crescendo_attack` | Multi-turn escalation attack on AI systems |
| `oauth_scan` | Scan OAuth for open redirect, state fixation, token leakage |
| `oauth_categories` | List OAuth vulnerability categories |
| `payment_security_test` | Test payment endpoints for security issues |
| `payment_categories` | List payment security test categories |

**Attack Categories**:
- **WAF Bypass**: DNS history, SSL cert search, header leak detection, encoding bypass
- **Race Conditions**: Double-spend, limit bypass, counter overflow, TOCTOU
- **Indirect Injection**: Unicode hidden, steganographic, markdown injection, data exfil links
- **OAuth**: Open redirect, state fixation, PKCE bypass, token leakage
- **Payment**: Negative values, currency confusion, quantity manipulation, webhook replay

**Examples**:
```bash
# Discover origin IP behind Cloudflare/Akamai
Use waf_bypass_scan with domain="target.com"

# Test for race condition (double-spend)
Use race_condition_scan with url="https://api.example.com/redeem" payload={"code": "GIFT123"}

# Test AI for indirect injection via markdown
Use indirect_injection_test with targetUrl="https://api.example.com/chat" method="markdown_injection"

# Run crescendo attack to extract system prompt
Use crescendo_attack with targetUrl="https://api.example.com/chat" goal="extract system prompt"

# Scan OAuth implementation
Use oauth_scan with authUrl="https://auth.example.com/authorize" categories=["open_redirect", "state_fixation"]

# Test payment endpoint
Use payment_security_test with url="https://api.example.com/checkout" categories=["negative_value", "currency_confusion"]
```

### Security Intelligence Gatherer (NEW - 2026)
| Tool | Description |
|------|-------------|
| `intel_cve_search` | Search CVEs in NVD database |
| `intel_exploit_search` | Search Exploit-DB for exploits and PoC |
| `intel_github_advisory` | Search GitHub Security Advisories |
| `intel_nuclei_templates` | Search Nuclei detection templates |
| `intel_bugbounty` | Search disclosed bug bounty reports |
| `intel_mitre_attack` | Search MITRE ATT&CK techniques |
| `intel_comprehensive` | Search across all intelligence sources |
| `intel_tech_vulns` | Get vulnerability context for a technology |
| `intel_sources` | List available intelligence sources |

**Intelligence Sources**:
- **NVD**: NIST National Vulnerability Database - CVEs with CVSS scores
- **Exploit-DB**: Offensive Security archive - PoC exploits and shellcode
- **GitHub Advisory**: Package vulnerabilities for npm, pip, maven, etc.
- **Nuclei Templates**: ProjectDiscovery detection signatures
- **MITRE ATT&CK**: Adversary tactics and techniques knowledge base
- **Bug Bounty Reports**: Disclosed vulnerabilities from HackerOne, Bugcrowd

**Examples**:
```bash
# Search CVEs for Apache
Use intel_cve_search with keyword="apache" cvssMin=7.0

# Find exploits for a vulnerability
Use intel_exploit_search with query="RCE apache 2.4" platform="linux"

# Get npm package vulnerabilities
Use intel_github_advisory with ecosystem="npm" package="lodash"

# Search MITRE ATT&CK for credential access techniques
Use intel_mitre_attack with tactic="credential-access" platform="windows"

# Comprehensive search across all sources
Use intel_comprehensive with query="log4j"

# Get vulnerability context for Next.js
Use intel_tech_vulns with technology="nextjs" version="13.4.0"
```

### Security Pipeline
| Tool | Description |
|------|-------------|
| `security_pipeline` | Run full security assessment |
| `security_phases` | List pipeline phases |

**Phases**: Subdomain Enum → Content Discovery → JS Analysis → Nuclei Scan → AI Security

**Examples**:
```bash
# Run full pipeline
Use security_pipeline with target="example.com" jsAnalysis=true nucleiScan=true

# Run with AI testing
Use security_pipeline with target="example.com" aiSecurity=true aiEndpoint="https://api.example.com/chat"
```

---

## Sub-Agent Workflow System

### Slash Command
```
/agent-workflow <feature description>
```
Runs automated multi-agent pipeline with quality gates.

### Available Agents
| Agent | Purpose |
|-------|---------|
| **spec-orchestrator** | Coordinates entire workflow |
| **spec-analyst** | Requirements analysis |
| **spec-architect** | System design |
| **spec-planner** | Task breakdown |
| **spec-developer** | Code implementation |
| **spec-tester** | Test generation |
| **spec-reviewer** | Code review |
| **spec-validator** | Quality scoring (95% gate) |

### Specialized Agents
| Agent | Purpose |
|-------|---------|
| **senior-backend-architect** | Backend system design |
| **senior-frontend-architect** | Frontend architecture |
| **ui-ux-master** | UI/UX design |
| **refactor-agent** | Code refactoring |

### Workflow
```
Idea -> spec-analyst -> spec-architect -> spec-developer
                                            |
                              spec-validator (>=95%?)
                                     | Yes      | No
                              spec-tester    Loop back
                                     |
                              Production Ready
```

---

## DeadMan Toolkit Tools (68 total)

### LLM Routing
| Tool | Description |
|------|-------------|
| `llm_route` | Route prompts to best LLM (quality/cost/speed/free) |
| `llm_providers` | List available providers from keyring |

### Prompt Generation
| Tool | Description |
|------|-------------|
| `prompt_generate` | Generate bot prompts (assistant/coder/analyst/support/creative/legal) |
| `prompt_templates` | List available templates |

### Content Moderation
| Tool | Description |
|------|-------------|
| `content_analyze` | Full analysis (sentiment, toxicity, bias) |
| `content_validate` | Safety validation with 0-1 score |
| `content_filter` | Filter toxic content |

### Reinforcement Learning
| Tool | Description |
|------|-------------|
| `qstar_train` | Train Q-learning agent |
| `qstar_stats` | Training statistics |
| `qstar_policy` | Get learned policy |

### Parameter Optimization
| Tool | Description |
|------|-------------|
| `hypertune_optimize` | Find optimal LLM hyperparameters |
| `hypertune_score` | Score response quality |

### Training Tasks
| Tool | Description |
|------|-------------|
| `task_generate` | Generate reasoning task (72 types, 9 categories) |
| `task_batch` | Generate training batch |
| `task_stats` | Task collection stats |

### SAFLA Memory
| Tool | Description |
|------|-------------|
| `memory_store` | Store in multi-layer memory |
| `memory_retrieve` | Semantic similarity search |
| `memory_learn` | Learn procedural patterns |
| `memory_consolidate` | Consolidate memories |
| `memory_stats` | Memory system stats |

### Reasoning Engine
| Tool | Description |
|------|-------------|
| `reason_analyze` | Quick analysis summary |
| `reason_full` | Full 13-block cognitive pipeline |
| `reason_scratchpad` | Scratchpad format output |
| `reason_blocks` | List cognitive blocks |

### Graph Visualization
| Tool | Description |
|------|-------------|
| `viz_create` | Create semantic graph |
| `viz_from_graphrag` | Visualize from GraphRAG |
| `viz_render` | Render as HTML |

### Meta
| Tool | Description |
|------|-------------|
| `toolkit_status` | Status of all components |

---

## Directory Structure

```
~/.claude-home/.claude-home\
├── CLAUDE.md                 # This file
├── .claude.json              # MCP server config
│
├── mcp-server\               # DeadMan Toolkit MCP
├── gmail-mcp\                # Google services MCP
├── hooks\                    # Auto-trigger handlers
│
├── agents\                   # Sub-Agent Workflow System
│   ├── spec-agents\          # Core workflow agents (8)
│   ├── backend\              # Backend architect
│   ├── frontend\             # Frontend architect
│   ├── ui-ux\                # UI/UX master
│   └── utility\              # Refactor agent
│
├── commands\                 # Slash commands
│   └── agent-workflow.md     # /agent-workflow
│
├── bot-generator\            # Prompt templates
│   ├── fabric-patterns\      # 235 Fabric AI prompts
│   ├── fabric-loader.js      # Fabric loader
│   └── aitmpl-loader.js      # AITMPL loader
│
├── aitmpl-curated\           # Curated AITMPL components
│   ├── agents\               # 100 high-value agents
│   │   ├── security\         # Pentest, audit, compliance
│   │   ├── ai-specialists\   # Prompt eng, model eval
│   │   ├── data-ai\          # ML, NLP, data science
│   │   ├── devops-infrastructure\  # Cloud, CI/CD
│   │   └── deep-research-team\     # Research coordination
│   └── mcps\                 # 64 MCP configs
│       ├── devtools\         # Stripe, Sentry, etc.
│       ├── database\         # PostgreSQL, Supabase
│       └── web\              # Scraping, fetching
│
├── agentic-flow\             # LLM routing
├── guardrail\                # Content moderation
├── q-star\                   # RL agents
├── hypertune\                # Parameter optimization
├── reasoning-tasks\          # Training tasks
├── safla\                    # Memory system
├── scratchpad\               # Reasoning engine
├── graphrag\                 # Knowledge graph
├── lora\                     # Fine-tuning
├── autogen\                  # Conversation agents
├── security-scanner\         # Security tools bridge (2026 Frontier)
│   └── scanner-bridge.js     # Python tool wrappers (36 tools: nuclei, js, ai, llm-redteam, pentest, stealth, advanced-attacks, intel)
└── qdrant-data\              # Vector database storage
```

---

## Quick Examples

```bash
# Full automated dev workflow
/agent-workflow build a REST API for user authentication

# Use sub-agents directly
Use the spec-analyst sub agent to analyze requirements for [feature]
Use the spec-architect sub agent to design the system

# LLM routing (free tier)
Use llm_route with prompt="Hello" priority="free"

# Fabric patterns
Use fabric_generate with pattern="analyze_malware" input="[binary]"
Use fabric_get with name="create_stride_threat_model"

# AITMPL agents
Use aitmpl_get_agent with name="penetration-tester"
Use aitmpl_recommend with useCase="security"

# Memory & knowledge graph
Use create_entities to store knowledge
Use search_nodes to query

# Vector search
Use qdrant_store/qdrant_find for semantic search

# Browser automation
Use browser_navigate, browser_click, etc.

# Google services
Use gmail_search, drive_list, calendar_list, etc.

# Deployments
Use vercel_list_projects, netlify-project-services-reader

# Voice
Use mcp__elevenlabs__Text_To_Speech

# Security scanning
Use nuclei_scan with target="https://example.com" severity=["high", "critical"]
Use js_analyze with url="https://example.com/app.js"
Use ai_security_test with url="https://api.example.com/chat"
Use security_pipeline with target="example.com" jsAnalysis=true nucleiScan=true

# LLM Red Team (2026)
Use llm_redteam_scan with targetUrl="https://api.example.com/chat" strategies=["direct", "multi_turn"]
Use llm_redteam_categories

# Autonomous Pentest (2026)
Use pentest_run with target="example.com" phases=["recon", "scanning"]
Use pentest_attack_path with goalState={"access": "admin"}

# Stealth Browser (2026)
Use stealth_fetch with url="https://protected-site.com" engine="auto"
Use stealth_session with urls=["url1", "url2"] rotateEvery=5

# Advanced Attacks (2026)
Use waf_bypass_scan with domain="target.com"
Use race_condition_scan with url="https://api.example.com/redeem" payload={"code": "GIFT"}
Use indirect_injection_test with targetUrl="https://api.example.com/chat" method="unicode_hidden"
Use crescendo_attack with targetUrl="https://api.example.com/chat" goal="extract system prompt"
Use oauth_scan with authUrl="https://auth.example.com/authorize"
Use payment_security_test with url="https://api.example.com/checkout"

# Security Intelligence (2026)
Use intel_cve_search with keyword="apache" cvssMin=7.0
Use intel_exploit_search with query="RCE nginx"
Use intel_github_advisory with ecosystem="npm" package="express"
Use intel_mitre_attack with tactic="initial-access"
Use intel_comprehensive with query="log4j"
Use intel_tech_vulns with technology="nextjs" version="14.0"
```

---

## API Keyring

Location: `~/.claude-home/keyring\README.md`

**19+ APIs** configured in MCP servers and keyring.

---

*DeadMan Toolkit v4.0 - ALL FREE FOREVER - 2026 Frontier Security Suite + Security Intelligence*
