# DeadMan Toolkit v5.3

> **Philosophy**: Safety > Determinism > Optimization > Learning
> **Spec**: FOUNDATION.md v1.0 | rules.yaml v3.0
> **Author**: DeadManOfficial

---

## Core Axioms (Immutable)

```
AXIOM_0: Safety is non-negotiable and always supersedes performance
AXIOM_1: All failures must be bounded, detectable, and recoverable
AXIOM_2: Determinism is required for all safety-critical paths
AXIOM_3: Learned behaviors operate only within verified safety envelopes
AXIOM_4: No single point of failure in critical paths
AXIOM_5: All state transitions must be explicit, bounded, and reversible
```

---

## System Architecture

### Directory Hierarchy
```
L0: ~/.claude-home/.claude              ← Supreme Authority (Claude Code settings)
    ↓
L1: ~/.claude-home/.claude-home         ← Deterministic Core (this folder)
    ↓
L2+: ~/.claude-home/BlackHat            ← Operations (security tooling)
```

### Layer Architecture (within .claude-home)
```
LAYER_0: FOUNDATION (Immutable)     ← CANNOT BE OVERRIDDEN
   └─ Safety Monitor, Invariant Checker, Emergency Controller

LAYER_1: DETERMINISTIC CORE         ← Overrides L2, L3
   └─ Rule Engine, State Machine, Resource Manager

LAYER_2: ADAPTIVE LAYER             ← Overrides L3
   └─ Learning Systems, Optimization, Heuristics

LAYER_3: INTERFACE                  ← Lowest priority
   └─ Input Validators, Output Sanitizers, External Adapters
```

### Decision Priority
```
D0_SAFETY (<1ms) > D1_DETERMINISTIC (<10ms) > D2_COMPUTED (<100ms) > D3_LEARNED (<1s)
```

### State Machine
```
OPERATIONAL (100%) → DEGRADED (60-99%) → MINIMAL (20-59%) → SAFE (0-19%) → EMERGENCY (0%)
```

### Conflict Resolution
```
1. Lower layer ALWAYS wins
2. More conservative option wins on tie
3. Fail to safe state on unresolvable conflict
```

---

## MCP Servers (18)

| Server | Purpose |
|--------|---------|
| `deadman-toolkit` | 116 AI tools (core toolkit) |
| `seo-mcp` | 20 SEO tools |
| `memory` | Knowledge graph |
| `thinking` | Sequential reasoning |
| `qdrant` | Vector database |
| `playwright` | Browser automation |
| `google` | Gmail, Drive, Calendar, YouTube, Sheets, Docs |
| `github` | Repos, PRs, Issues |
| `vercel` | Deployments |
| `netlify` | Sites, Functions |
| `elevenlabs` | Voice/TTS |
| `lovely-docs` | Library docs |
| `mcp-auditor` | Security/Compliance audits (35 tools) |
| `context7` | Live documentation |
| `notion` | Workspace integration |
| `hyperbrowser` | Anti-detect browser |
| `firecrawl` | Production scraping |
| `stripe` | Payment processing |

---

## Tools by Layer

### LAYER_0: Safety (Always Active)

| Tool | Description |
|------|-------------|
| `rules_evaluate` | Evaluate context, get active agents/tools |
| `rules_status` | Current engine state |
| `rules_workflow_status` | Workflow progress |

### LAYER_1: Deterministic

#### Security (suggest when: security keywords, security-audit project)
| Tool | Description |
|------|-------------|
| `nuclei_scan` | Vulnerability scanning |
| `js_analyze` | JavaScript secrets/endpoints |
| `ai_security_test` | AI endpoint testing |
| `llm_redteam_scan` | LLM red team (OWASP LLM Top 10) |
| `pentest_run` | Autonomous pentest |
| `stealth_fetch` | Anti-detect browser |
| `security_pipeline` | Full assessment pipeline |
| `intel_comprehensive` | Multi-source threat intel |

**Advanced Scanners**: `ssrf_scan`, `graphql_scan`, `cors_scan`, `xxe_scan`, `ssti_scan`, `command_injection_scan`, `waf_bypass_scan`, `race_condition_scan`, `oauth_scan`, `payment_security_test`, `idor_scan`, `jwt_analyze`, `api_enumerate`, `host_header_scan`, `path_traversal_scan`, `crlf_scan`, `subdomain_takeover_scan`, `cache_poisoning_scan`, `http_smuggling_scan`, `websocket_scan`

#### Auditor (suggest when: audit, compliance, forensic)
All `mcp__mcp-auditor__*` tools

### LAYER_2: Adaptive

#### Development (suggest when: develop, code, implement)
| Tool | Description |
|------|-------------|
| `llm_route` | Route to best LLM |
| `prompt_generate` | Generate bot prompts |
| `fabric_*` | 235 Fabric AI patterns |
| `aitmpl_*` | 100 agent + 64 MCP templates |
| `reason_*` | 13-block cognitive reasoning |

#### AI/ML (suggest when: ai, ml, training, model)
`qstar_*`, `hypertune_*`, `task_*`, `memory_*`, `graph_*`, `lora_*`, `autogen_*`

#### SEO (suggest when: seo, ranking, keyword, traffic)
`serp_*`, `keyword_*`, `pagespeed_*`, `backlinks_*`, `gsc_*`, `geo_*`

#### Workflow (suggest when: workflow, orchestrate, pipeline)
`action_graph_*`, `hybrid_plan_*`, `agent_*`

#### Vision (suggest when: image, video, detect, segment)
`telekinesis_*`

### LAYER_3: Interface

#### Deployment (requires: tests_passed + review_complete)
`vercel_*`, `netlify_*`

#### Browser
`mcp__playwright__*`, `mcp__hyperbrowser__*`

#### Google
`mcp__google__*` (gmail, drive, calendar, youtube, sheets, docs)

#### GitHub
`mcp__github__*`

#### Voice
`mcp__elevenlabs__*`

#### Knowledge
`mcp__memory__*`, `mcp__qdrant__*`

#### Docs
`mcp__lovely-docs__*`, `mcp__context7__*`

---

## Agents by Layer

### LAYER_0: Safety
| Agent | Purpose |
|-------|---------|
| `safety-monitor` | Monitors all operations (CANNOT BE DISABLED) |

### LAYER_1: Deterministic (Workflow Core)
| Agent | Workflow Position | Suggest When |
|-------|-------------------|--------------|
| `spec-orchestrator` | 0 | coordinate, orchestrate, agent-workflow |
| `spec-analyst` | 1 | requirements, user story, scope |
| `spec-architect` | 2 | architecture, design, data model |
| `spec-planner` | 3 | plan, task breakdown, timeline |
| `spec-validator` | 5 | validate, quality check (95% gate) |

### LAYER_2: Adaptive
| Agent | Suggest When |
|-------|--------------|
| `spec-developer` | implement, code, build |
| `spec-tester` | test, coverage, qa |
| `spec-reviewer` | review, best practices |
| `senior-backend-architect` | api, backend, database, microservice |
| `senior-frontend-architect` | ui, frontend, react, vue |
| `ui-ux-master` | ux, design system, wireframe |
| `refactor-agent` | refactor, clean up, technical debt |

---

## Workflows

### Development (95% quality gate)
```
analyze → design → plan → implement → validate(≥95%?) → test → review
                                          ↓ No
                                     iterate back
```

### Security Assessment
```
recon → scan → test → report
```

### SEO Audit
```
technical → keywords → backlinks → geo
```

---

## State Flags

| Flag | Layer | Trigger | Effect |
|------|-------|---------|--------|
| `emergency_mode` | L0 | safety violation | disable all non-safety |
| `security_mode` | L1 | pentest, security audit | enable security tools |
| `audit_mode` | L1 | compliance, sox, forensic | enable auditor tools |
| `workflow_mode` | L1 | agent-workflow | full pipeline |
| `ready_to_deploy` | L2 | tests_passed + review_approved | enable deployment |
| `knowledge_mode` | L2 | remember, knowledge graph | enable memory tools |
| `google_mode` | L3 | gmail, drive, calendar | enable google tools |
| `github_mode` | L3 | pr, issue, repo | enable github tools |
| `voice_mode` | L3 | tts, audio, voice | enable elevenlabs |

---

## Quick Reference

### Slash Commands
```bash
/agent-workflow <description>   # Full multi-agent pipeline
```

### Rules Engine
```bash
rules_evaluate message="<task>"   # Get active agents, tools, defaults
rules_set_flag name="security_mode"   # Enable state flag
rules_workflow_status workflow="development"   # Check progress
```

### Common Patterns
```bash
# Security scan
nuclei_scan target="https://example.com" severity=["high","critical"]

# LLM red team
llm_redteam_scan targetUrl="https://api.example.com/chat" strategies=["direct","multi_turn"]

# Fabric pattern
fabric_generate pattern="create_stride_threat_model" input="[description]"

# Agent template
aitmpl_get_agent name="penetration-tester"

# Memory
mcp__memory__create_entities entities=[{name:"X",type:"concept"}]
```

---

## Governance Policies

### Layer Assignment
- **Authority**: DeadManOfficial (human approval required)
- **Source**: `rules/rules.yaml` (static definitions)
- **Constraint**: Claude cannot modify layers without approval
- **L0 Frozen**: LAYER_0 assignments cannot be changed

### Component Integration
- **ALL** new components require full FOUNDATION.md Section 11 compliance
- Safety analysis (FMEA/FTA), 95% test coverage, failure injection required
- No exceptions by layer

### Failure Handling
- BlackHat operations trigger full state degradation
- Single failure → DEGRADED, Multiple → MINIMAL, Critical → SAFE
- Graduated recovery required (no direct jump to OPERATIONAL)

### Safety Context
- System designed for physical safety contexts (current/future)
- Security operations treated as capable of serious harm
- Build as if lives depend on it

*Full policy details: `rules/README.md`*

---

## Directory Structure

```
~/.claude-home/.claude-home\
├── CLAUDE.md              # This file (quick reference)
├── FOUNDATION.md          # Full specification
├── .claude.json           # MCP server config
├── keyring\               # API keys (load-keyring.sh)
├── rules\                 # Rules engine (rules.yaml)
├── mcp\                   # All MCP servers (local)
│   ├── mcp-registry.json  # Registry of all 18 MCPs
│   ├── mcp-deadman\       # DeadMan Toolkit (116 tools)
│   ├── mcp-google\        # Google services
│   ├── mcp-seo\           # SEO tools
│   └── mcp-qdrant\        # Vector database
├── agents\                # Sub-agent definitions
├── security-scanner\      # 36 security tools
├── bot-generator\         # Fabric + AITMPL templates
└── [other modules]        # See FOUNDATION.md
```

---

## Startup

```powershell
# Load keys and start Claude
~/.claude-home/.claude-home\keyring\start-claude.sh
```

---

*DeadMan Toolkit v5.3 - ALL FREE FOREVER*
*Full spec: FOUNDATION.md | Config: rules.yaml*
