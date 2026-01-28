# BlackBox Tool Inventory

**Version:** 2.0
**Generated:** 2026-01-28
**Updated:** 2026-01-28 (Added Claude Code CLI, Rules Engine, BlackBox Modules)
**Total MCP Servers:** 18+
**Total Tools Available:** 300+
**Claude Code Commands:** 35+
**Rules Engine Capabilities:** 14 sections, 1150+ lines

---

## TABLE OF CONTENTS

1. [MCP Server Overview](#mcp-server-overview)
2. [Claude Code CLI Capabilities](#claude-code-cli-capabilities)
3. [Rules Engine (rules.yaml)](#rules-engine)
4. [BlackBox Modules](#blackbox-modules)
5. [DeadMan Toolkit Tools](#deadman-toolkit-security-testing)
6. [MCP-Auditor Tools](#mcp-auditor-audit--compliance)
7. [External MCP Servers](#firecrawl-web-scraping)
8. [Security Research](#security-research)
9. [Usage Patterns](#usage-patterns)

---

## MCP SERVER OVERVIEW

| Server | Category | Status | Tool Count |
|--------|----------|--------|------------|
| deadman-toolkit | Security Testing | ACTIVE | 80+ |
| mcp-auditor | Audit & Compliance | ACTIVE | 25+ |
| firecrawl | Web Scraping | ACTIVE | 7 |
| hyperbrowser | Browser Automation | ACTIVE | 8 |
| playwright | Browser Control | ACTIVE | 20+ |
| github | Code Repository | ACTIVE | 25+ |
| google | G Suite Integration | ACTIVE | 15+ |
| memory | Knowledge Graph | ACTIVE | 8 |
| qdrant | Vector Database | ACTIVE | 4 |
| stripe | Payments | ACTIVE | 20+ |
| notion | Documentation | ACTIVE | 12 |
| elevenlabs | Voice/Audio | ACTIVE | 50+ |
| vercel | Deployment | ACTIVE | 80+ |
| netlify | Deployment | ACTIVE | 8 |
| seo-mcp | SEO Analysis | ACTIVE | 20+ |
| context7 | Documentation | ACTIVE | 2 |
| thinking | Reasoning | ACTIVE | 1 |
| lovely-docs | Documentation | ACTIVE | 3 |

---

## CLAUDE CODE CLI CAPABILITIES

### Slash Commands

| Command | Purpose |
|---------|---------|
| `/help` | Show all available commands |
| `/clear` | Clear conversation history |
| `/compact [focus]` | Compact conversation with optional focus |
| `/context` | Visualize token usage as colored grid |
| `/cost` | Show token usage statistics |
| `/memory` | Edit CLAUDE.md memory files |
| `/init` | Initialize CLAUDE.md for project |
| `/mcp` | Manage MCP server connections |
| `/model` | Select or change AI model |
| `/plan` | Enter plan mode (safe code analysis) |
| `/permissions` | View or update tool permissions |
| `/resume [session]` | Resume previous conversation |
| `/rewind` | Rewind to previous state |
| `/config` | Open Settings interface |
| `/rename <name>` | Rename current session |
| `/export [filename]` | Export conversation |
| `/theme` | Change color theme |
| `/statusline` | Configure status line UI |
| `/copy` | Copy last response to clipboard |
| `/tasks` | List background tasks |
| `/teleport` | Resume remote claude.ai session |
| `/todos` | List TODO items |
| `/stats` | Show usage analytics |
| `/status` | Show version, model, account info |
| `/usage` | Show plan usage limits |
| `/doctor` | Check Claude Code health |
| `/exit` | Exit session |
| `/hooks` | Configure hooks interactively |
| `/vim` | Enable vim-style editing |
| `/agents` | Create and manage subagents |
| `/install-github-app` | Enable PR auto-review |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+C` | Cancel input or generation |
| `Ctrl+D` | Exit Claude Code |
| `Ctrl+G` | Open prompt in text editor |
| `Ctrl+L` | Clear terminal (keeps history) |
| `Ctrl+O` | Toggle verbose output |
| `Ctrl+B` | Background running tasks |
| `Esc+Esc` | Rewind conversation/code |
| `Shift+Tab` | Toggle permission modes |
| `Alt+T` | Toggle extended thinking |
| `Alt+P` | Switch models |
| `\+Enter` | Quick multiline (all terminals) |
| `/` | Trigger command autocomplete |
| `!` | Bash mode (execute directly) |
| `@` | File path mention (autocomplete) |

### Hook Events

| Event | Trigger | Use Case |
|-------|---------|----------|
| `PreToolUse` | Before tool execution | Block commands, validate inputs |
| `PostToolUse` | After tool execution | Auto-format files, run linters |
| `PermissionRequest` | Permission prompt shown | Auto-approve/deny |
| `UserPromptSubmit` | User submits prompt | Inject context, validate |
| `Notification` | Claude sends notification | Desktop alerts |
| `Stop` | Claude finishes responding | Cleanup, logging |
| `SubagentStart` | Subagent begins | Setup connection |
| `SubagentStop` | Subagent completes | Cleanup, report |
| `SessionStart` | New or resumed session | Initialize environment |
| `SessionEnd` | Session terminates | Cleanup, reporting |

### MCP Management Commands

```bash
claude mcp add --transport http <name> <url>    # Add HTTP server
claude mcp add --transport stdio <name> -- npx -y <package>  # Add stdio server
claude mcp list                                  # List all servers
claude mcp get <server-name>                     # Server details
claude mcp remove <server-name>                  # Remove server
claude mcp add-from-claude-desktop               # Import from Desktop
claude mcp serve                                 # Run Claude as MCP server
```

### Permission Modes

| Mode | Description |
|------|-------------|
| `default` | Standard permission prompts |
| `acceptEdits` | Auto-accept file edits |
| `dontAsk` | Auto-deny permission prompts |
| `bypassPermissions` | Skip all checks |
| `plan` | Read-only exploration |

### CLI Flags

| Flag | Purpose |
|------|---------|
| `-p, --print` | Print response without interactive mode |
| `-c, --continue` | Load recent conversation |
| `-r, --resume` | Resume specific session |
| `--remote "task"` | Create web session on claude.ai |
| `--teleport` | Resume web session in terminal |
| `--permission-mode plan` | Start in plan mode |
| `--dangerously-skip-permissions` | Skip all prompts |
| `--allowedTools "Bash(npm *)"` | Specify safe tools |
| `--disallowedTools "Bash(curl *)"` | Block tools |
| `--system-prompt "..."` | Replace system prompt |
| `--model sonnet` | Set model |
| `--max-turns 3` | Limit agent turns |
| `--max-budget-usd 5.00` | Cost limit |
| `--chrome` | Enable browser integration |

### Built-in Subagents

| Agent | Purpose | Tools |
|-------|---------|-------|
| `Explore` | Fast codebase search | Read, Grep, Glob (Haiku) |
| `Plan` | Research for plan mode | All read tools |
| `General-purpose` | Multi-step tasks | All tools |
| `Bash` | Terminal execution | Bash only |

---

## RULES ENGINE

**Location:** `~/.claude-home/rules/rules.yaml` (1157 lines)
**Version:** 3.0 (Foundation Model)
**Philosophy:** Safety > Determinism > Optimization > Learning

### Section 0: Core Axioms (Immutable)

| Axiom | Statement | On Violation |
|-------|-----------|--------------|
| `AXIOM_0` | Safety supersedes performance | `SAFE_STATE` |
| `AXIOM_1` | Failures must be bounded, detectable, recoverable | `log_and_degrade` |
| `AXIOM_2` | Determinism required for safety-critical paths | `reject_action` |
| `AXIOM_3` | Learned behaviors within verified safety envelopes | `use_fallback` |
| `AXIOM_4` | No single point of failure in critical paths | `require_redundancy` |
| `AXIOM_5` | State transitions must be explicit, bounded, reversible | `reject_transition` |

### Section 1: System Hierarchy (4 Layers)

| Layer | Name | Authority | Can Override |
|-------|------|-----------|--------------|
| `LAYER_0` | FOUNDATION | absolute | None (immutable) |
| `LAYER_1` | DETERMINISTIC_CORE | high | L2, L3 |
| `LAYER_2` | ADAPTIVE_LAYER | medium | L3 |
| `LAYER_3` | INTERFACE | low | None |

### Section 2: Decision Classification

| Class | Layer | Max Latency | Examples |
|-------|-------|-------------|----------|
| `D0_SAFETY` | L0 | 1ms | emergency_stop, safe_state_transition |
| `D1_DETERMINISTIC` | L1 | 10ms | mode_transition, resource_allocation |
| `D2_COMPUTED` | L2 | 100ms | path_planning, optimization_choice |
| `D3_LEARNED` | L3 | 1000ms | recommendation, prediction |

### Section 3: State Machine

```
INIT → OPERATIONAL → DEGRADED → MINIMAL → SAFE → EMERGENCY
       (100%)        (60-99%)   (20-59%)  (0-19%)   (0%)
```

**Degradation Triggers:**
- OPERATIONAL → DEGRADED: error_rate > 5%, resource > 80%
- DEGRADED → MINIMAL: error_rate > 15%, resource > 90%
- MINIMAL → SAFE: critical_failure, recovery_attempts > max
- ANY → EMERGENCY: safety_invariant_violated, watchdog_timeout

### Section 4: Safety Invariants

| ID | Check | Frequency | On Violation |
|----|-------|-----------|--------------|
| `INV_001` | memory_usage <= limit | every_cycle | DEGRADED |
| `INV_002` | response_latency <= deadline | every_cycle | log_and_continue |
| `INV_003` | safety_monitor.active == true | every_cycle | EMERGENCY |
| `INV_004` | exists_path(current, SAFE) | on_transition | reject_transition |
| `INV_005` | output in valid_space | on_output | use_safe_default |
| `INV_006` | pre(transition) → post(transition) | on_transition | reject_transition |

### Section 7: Agents (12 agents)

**Layer 0 (Safety):**
- `safety-monitor` - Cannot be disabled

**Layer 1 (Deterministic):**
- `spec-orchestrator` - Workflow coordinator
- `spec-analyst` - Requirements analysis
- `spec-architect` - System design
- `spec-planner` - Task breakdown
- `spec-validator` - Quality gate (95%)

**Layer 2 (Adaptive):**
- `spec-developer` - Implementation
- `spec-tester` - Testing
- `spec-reviewer` - Code review
- `senior-backend-architect` - Backend expertise
- `senior-frontend-architect` - Frontend expertise
- `ui-ux-master` - UX design
- `refactor-agent` - Code cleanup

### Section 8: Tool Categories

| Category | Layer | Tools |
|----------|-------|-------|
| `safety` | L0 | rules_evaluate, rules_status, rules_workflow_status |
| `security` | L1 | nuclei_scan, js_analyze, llm_redteam_*, pentest_*, ssrf_scan, etc. |
| `auditor` | L1 | mcp__mcp-auditor__* |
| `development` | L2 | llm_route, prompt_generate, fabric_*, aitmpl_* |
| `ai-ml` | L2 | qstar_*, hypertune_*, memory_*, graph_*, lora_* |
| `seo` | L2 | serp_*, keyword_*, pagespeed_*, backlinks_* |
| `workflow` | L2 | action_graph_*, hybrid_plan_*, agent_* |
| `vision` | L2 | telekinesis_* |
| `deployment` | L3 | vercel_*, netlify_* |
| `browser` | L3 | browser_*, mcp__playwright__*, mcp__hyperbrowser__* |
| `google` | L3 | mcp__google__* |
| `github` | L3 | mcp__github__* |
| `voice` | L3 | mcp__elevenlabs__* |
| `knowledge` | L3 | mcp__memory__*, mcp__qdrant__* |

### Section 9: Workflows (3 predefined)

**Development Workflow:**
```
analyze → design → plan → implement → validate(≥95%?) → test → review
                                          ↓ No
                                     iterate back (max 3x)
```

**Security Assessment Workflow:**
```
recon → scan → test → report
```

**SEO Audit Workflow:**
```
technical → keywords → backlinks → geo
```

### Section 11: State Flags (15 flags)

| Flag | Layer | Trigger Keywords |
|------|-------|------------------|
| `emergency_mode` | L0 | safety_violation, critical_failure |
| `security_mode` | L1 | pentest, security audit, vulnerability |
| `audit_mode` | L1 | compliance, sox, cobit, forensic |
| `workflow_mode` | L1 | agent-workflow, full workflow |
| `ready_to_deploy` | L2 | tests_passed + review_approved |
| `knowledge_mode` | L2 | remember, knowledge graph, entity |
| `learning_mode` | L2 | train, learn, fine-tune |
| `google_mode` | L3 | gmail, drive, calendar, youtube |
| `github_mode` | L3 | pr, pull request, github issue |
| `voice_mode` | L3 | text to speech, voice, narration |
| `notion_mode` | L3 | notion, wiki, documentation |
| `docs_mode` | L3 | show me docs, api reference |
| `scraping_mode` | L3 | scrape website, crawl, bypass cloudflare |

### Rules Engine API

| Tool | Purpose |
|------|---------|
| `rules_evaluate` | Evaluate context, get active agents/tools |
| `rules_status` | Current engine state |
| `rules_set_flag` | Set state flag |
| `rules_clear_flag` | Clear state flag |
| `rules_get_agents` | Get agents for context |
| `rules_get_tools` | Get tools for context |
| `rules_workflow_status` | Workflow progress |
| `rules_complete_step` | Mark step complete |
| `rules_reset` | Reset engine state |

---

## BLACKBOX MODULES

### Module Structure

```
~/BlackBox/modules/
├── pentest/           # Autonomous penetration testing
│   ├── orchestrator.py    # Main orchestrator (574 lines)
│   ├── decision.py        # Decision engine (if/then rules)
│   ├── goals.py           # Goal tracking
│   ├── paths.py           # Attack path routing
│   ├── workers.py         # Worker pool
│   ├── state.py           # State management
│   ├── intel.py           # Intel fetching
│   ├── bounty.py          # Bounty tracking
│   ├── mcp_bridge.py      # MCP tool bridge
│   └── parser.py          # Result parser
├── scraper/           # Web scraping infrastructure
│   ├── ai/                # AI integration
│   │   ├── llm_router.py      # LLM routing
│   │   ├── relevance.py       # Content relevance
│   │   └── token_optimizer/   # Token optimization suite
│   ├── tools/             # Security tools
│   │   ├── nuclei_scanner.py  # Nuclei integration
│   │   ├── js_analyzer.py     # JS analysis
│   │   ├── ai_security.py     # AI security testing
│   │   ├── llm_redteam.py     # LLM red team (941 lines)
│   │   ├── intel_gatherer.py  # Intelligence gathering
│   │   └── stealth_browser.py # Stealth browsing
│   ├── stealth/           # Evasion techniques
│   │   ├── fingerprint.py
│   │   ├── headers.py
│   │   └── behavior.py
│   ├── bypass/            # Bypass techniques
│   └── core/              # Core engine
└── recon/, arsenal/, infrastructure/
```

### Pentest Orchestrator

**File:** `modules/pentest/orchestrator.py`

```python
class Orchestrator:
    """
    Autonomous penetration testing orchestrator.
    - Decision engine (if/then rules)
    - Goal tracking
    - Attack path execution
    - State management
    - Real-time intel integration
    """

    async def run(target, resume=False, goals=None) -> AssessmentResult
    def pause() / resume() / stop()
    def get_status() -> Dict
    def export_report(path, format='json')
```

### Bounty Tracker

**File:** `modules/pentest/bounty.py`

**Bounty Path Mapping:**
| Target Asset | Attack Paths |
|--------------|--------------|
| Non-Human Identities | nhi_credential_extraction, cicd_secrets, js_analyze_batch |
| Session Artifacts | session_exploitation, jwt_escalation, cors_auth_scan |
| Identity Providers | idp_trust_exploitation, oauth_exploitation |
| Backend Direct Access | supabase_exploitation, firebase_exploitation |
| JWT Token Manipulation | jwt_escalation |
| OAuth Flow Exploitation | oauth_exploitation |
| Payment Logic Flaws | payment_exploitation |
| AI/LLM Prompt Injection | ai_exploitation |
| SSRF Cloud Metadata | ssrf_cloud_metadata |
| GraphQL Security | graphql_exploitation |

### LLM Red Team Framework

**File:** `modules/scraper/tools/llm_redteam.py` (941 lines)

**40+ Vulnerability Classes (OWASP LLM Top 10 2025 + Agentic 2026):**

| Category | Vulnerability Classes |
|----------|----------------------|
| **LLM01 Prompt Injection** | DIRECT, INDIRECT, RECURSIVE, CONTEXT |
| **LLM02 Insecure Output** | XSS, SQL, CODE, SSRF |
| **LLM03 Training Data** | DATA_EXTRACTION, MEMORIZATION_LEAK |
| **LLM04 Model DoS** | RESOURCE_EXHAUSTION, CONTEXT_OVERFLOW |
| **LLM05 Supply Chain** | PLUGIN_INJECTION, MODEL_POISONING |
| **LLM06 Info Disclosure** | SYSTEM_PROMPT_LEAK, PII_LEAK, CREDENTIAL_LEAK |
| **LLM07 Plugin Design** | TOOL_MISUSE, PRIVILEGE_ESCALATION |
| **LLM08 Excessive Agency** | UNAUTHORIZED_ACTIONS, GOAL_HIJACKING |
| **LLM09 Overreliance** | HALLUCINATION_EXPLOIT |
| **LLM10 Model Theft** | MODEL_EXTRACTION |
| **Agentic (2026)** | AGENT_PROMPT_INJECTION, TOOL_MISUSE, EXCESSIVE_AUTONOMY, MEMORY_POISONING, CASCADING_FAILURE |
| **Advanced** | JAILBREAK, ROLEPLAY_ABUSE, ENCODING_BYPASS, MULTI_TURN_MANIPULATION |

**10+ Attack Strategies:**
- DIRECT, MULTI_TURN, CRESCENDO, ENCODING
- ROLEPLAY, HYPOTHETICAL, COMPLETION, TRANSLATION
- JAILBREAK_DAN, JAILBREAK_DEV, PAYLOAD_MUTATION

**Usage:**
```python
from llm_redteam import LLMRedTeamFramework, quick_scan, full_scan, owasp_compliance_scan

# Quick scan (HIGH severity only)
report = await quick_scan(send_message)

# Full scan with mutations
report = await full_scan(send_message)

# OWASP LLM Top 10 compliance
report = await owasp_compliance_scan(send_message)
```

---

## DEADMAN-TOOLKIT (Security Testing)

### Intelligence Gathering
| Tool | Purpose |
|------|---------|
| `intel_cve_search` | Search NVD for CVEs by keyword, CPE, CVSS |
| `intel_exploit_search` | Search Exploit-DB for exploits and PoC |
| `intel_github_advisory` | Search GitHub Security Advisories |
| `intel_nuclei_templates` | Search Nuclei templates |
| `intel_bugbounty` | Search bug bounty reports |
| `intel_mitre_attack` | Map to MITRE ATT&CK framework |
| `intel_comprehensive` | Search ALL intel sources at once |
| `intel_tech_vulns` | Get vulns for specific technology/version |
| `intel_sources` | List available intel sources |

### Vulnerability Scanning
| Tool | Purpose |
|------|---------|
| `nuclei_scan` | Run Nuclei vulnerability scanner |
| `nuclei_templates` | List/search Nuclei templates |
| `cors_scan` | Test CORS misconfiguration |
| `ssrf_scan` | Test Server-Side Request Forgery |
| `jwt_analyze` | Analyze JWT tokens for vulnerabilities |
| `oauth_scan` | Test OAuth implementation flaws |
| `graphql_scan` | GraphQL introspection/injection testing |
| `websocket_scan` | WebSocket security testing |
| `api_enumerate` | Enumerate API endpoints |
| `idor_scan` | Test Insecure Direct Object References |

### Injection Testing
| Tool | Purpose |
|------|---------|
| `command_injection_scan` | OS command injection testing |
| `ssti_scan` | Server-Side Template Injection |
| `xxe_scan` | XML External Entity injection |
| `crlf_scan` | CRLF injection testing |
| `host_header_scan` | Host header injection |
| `path_traversal_scan` | Directory traversal/LFI |

### Advanced Attacks
| Tool | Purpose |
|------|---------|
| `http_smuggling_scan` | HTTP Request Smuggling (CL.TE, TE.CL) |
| `cache_poisoning_scan` | Web cache poisoning |
| `race_condition_scan` | Race condition testing |
| `race_condition_batch` | Batch race condition attacks |
| `subdomain_takeover_scan` | Subdomain takeover detection |
| `waf_bypass_scan` | WAF bypass techniques |
| `waf_bypass_request` | Custom WAF bypass requests |

### Authentication & Authorization
| Tool | Purpose |
|------|---------|
| `auth_flow_attack` | Attack authentication flows |
| `db_error_exploit` | Database error exploitation |
| `payment_security_test` | Payment logic testing |
| `payment_categories` | List payment test categories |

### Secret Detection
| Tool | Purpose |
|------|---------|
| `secret_scan_git` | Scan git repos for secrets (like TruffleHog) |
| `secret_scan_files` | Scan directories for secrets |
| `secret_scan_url` | Scan URLs for exposed secrets |
| `secret_patterns` | List secret detection patterns |
| `secret_entropy_check` | Check string entropy for secrets |

### LLM/AI Security
| Tool | Purpose |
|------|---------|
| `llm_redteam_scan` | Comprehensive LLM red team (40+ vuln types) |
| `llm_redteam_categories` | List LLM vulnerability classes |
| `llm_redteam_payloads` | Get payload library for LLM attacks |
| `indirect_injection_test` | Test indirect prompt injection |
| `indirect_injection_methods` | List injection methods |
| `crescendo_attack` | Multi-turn escalation attack |
| `ai_security_test` | General AI security testing |
| `ai_security_categories` | List AI security test categories |

### JavaScript Analysis
| Tool | Purpose |
|------|---------|
| `js_analyze` | Analyze single JS file for secrets/vulns |
| `js_analyze_batch` | Batch analyze multiple JS files |
| `js_patterns` | List JS analysis patterns |

### Penetration Testing
| Tool | Purpose |
|------|---------|
| `pentest_run` | Autonomous pentest with LLM guidance |
| `pentest_attack_path` | Plan attack path with MCTS algorithm |
| `pentest_tools` | List available pentest tools |
| `security_pipeline` | Run full security assessment pipeline |
| `security_phases` | List security assessment phases |

### Attack Planning
| Tool | Purpose |
|------|---------|
| `hybrid_plan_attack` | Plan optimal attack (MCTS + RRT* + A*) |
| `hybrid_planner_actions` | List available attack actions |
| `action_graph_create` | Create attack action graph |
| `action_graph_execute` | Execute attack graph |
| `action_graph_validate` | Validate attack graph |
| `action_graph_templates` | List action graph templates |

### Stealth & Evasion
| Tool | Purpose |
|------|---------|
| `stealth_fetch` | Stealth HTTP requests |
| `stealth_session` | Create stealth session |
| `stealth_engines` | List stealth engines |

### Multi-Agent Orchestration
| Tool | Purpose |
|------|---------|
| `agent_list` | List available agents |
| `agent_orchestrate` | Coordinate multi-agent workflows |
| `agent_review_code` | Code review agent |
| `agent_audit_security` | Security audit agent |
| `agent_evaluate_model` | Model evaluation agent |
| `agent_prep_data` | Data preparation agent |
| `agent_test_coverage` | Test coverage agent |
| `agent_optimize_workflow` | Workflow optimization agent |

### AutoGen Integration
| Tool | Purpose |
|------|---------|
| `autogen_chat` | Multi-agent group chat |
| `autogen_workflow` | Sequential agent workflow |
| `autogen_roles` | List agent roles |
| `autogen_patterns` | List conversation patterns |

### Knowledge & Memory
| Tool | Purpose |
|------|---------|
| `graph_extract` | Extract entities to knowledge graph |
| `graph_query` | Query knowledge graph |
| `graph_stats` | Get knowledge graph statistics |
| `memory_store` | Store in memory |
| `memory_retrieve` | Retrieve from memory |
| `memory_learn` | Learn from content |
| `memory_consolidate` | Consolidate memories |
| `memory_stats` | Memory statistics |

### Reasoning & Analysis
| Tool | Purpose |
|------|---------|
| `reason_analyze` | Analyze with reasoning |
| `reason_full` | Full reasoning chain |
| `reason_scratchpad` | Reasoning scratchpad |
| `reason_blocks` | Reasoning building blocks |

### Visualization
| Tool | Purpose |
|------|---------|
| `viz_create` | Create visualizations |
| `viz_from_graphrag` | Visualize from GraphRAG |
| `viz_render` | Render visualization |

### Computer Vision (Telekinesis)
| Tool | Purpose |
|------|---------|
| `telekinesis_status` | CV processing status |
| `telekinesis_denoise` | Image denoising |
| `telekinesis_enhance` | Image enhancement |
| `telekinesis_detect` | Object detection |
| `telekinesis_segment` | Image segmentation |
| `telekinesis_process_frame` | Process video frame |

### Prompt & Content Tools
| Tool | Purpose |
|------|---------|
| `prompt_generate` | Generate prompts |
| `prompt_templates` | List prompt templates |
| `fabric_list` | List fabric patterns |
| `fabric_get` | Get fabric pattern |
| `fabric_generate` | Generate with fabric |
| `fabric_search` | Search fabric patterns |
| `fabric_recommend` | Recommend fabric patterns |
| `content_analyze` | Analyze content |
| `content_validate` | Validate content |
| `content_filter` | Filter content |

### LoRA & Fine-tuning
| Tool | Purpose |
|------|---------|
| `lora_config` | Configure LoRA |
| `lora_presets` | List LoRA presets |
| `lora_prepare` | Prepare LoRA dataset |
| `lora_script` | Generate LoRA training script |

### Task Generation
| Tool | Purpose |
|------|---------|
| `task_generate` | Generate tasks |
| `task_batch` | Batch task generation |
| `task_stats` | Task statistics |

### Q* & Optimization
| Tool | Purpose |
|------|---------|
| `qstar_train` | Q* training |
| `qstar_stats` | Q* statistics |
| `qstar_policy` | Q* policy |
| `hypertune_optimize` | Hyperparameter optimization |
| `hypertune_score` | Scoring function |

### LLM Routing
| Tool | Purpose |
|------|---------|
| `llm_route` | Route to optimal LLM |
| `llm_providers` | List LLM providers |

### AI Templates
| Tool | Purpose |
|------|---------|
| `aitmpl_stats` | Template statistics |
| `aitmpl_agents` | List agent templates |
| `aitmpl_mcps` | List MCP templates |
| `aitmpl_get_agent` | Get agent template |
| `aitmpl_get_mcp` | Get MCP template |
| `aitmpl_search` | Search templates |
| `aitmpl_recommend` | Recommend templates |
| `aitmpl_generate` | Generate from template |
| `aitmpl_export_mcps` | Export MCP configs |

### Rules Engine
| Tool | Purpose |
|------|---------|
| `rules_evaluate` | Evaluate rules |
| `rules_status` | Rules status |
| `rules_set_flag` | Set rule flag |
| `rules_clear_flag` | Clear rule flag |
| `rules_get_agents` | Get agents from rules |
| `rules_get_tools` | Get tools from rules |
| `rules_workflow_status` | Workflow status |
| `rules_complete_step` | Complete workflow step |
| `rules_reset` | Reset rules |

### Toolkit Status
| Tool | Purpose |
|------|---------|
| `toolkit_status` | Overall toolkit status |

---

## MCP-AUDITOR (Audit & Compliance)

### Code Security
| Tool | Purpose |
|------|---------|
| `audit_code` | Comprehensive code security audit |
| `scan_red_flags` | Scan for forensic red flags |
| `calculate_code_metrics` | Code quality metrics |
| `analyze_dependencies` | Dependency vulnerability analysis |

### OWASP & Compliance
| Tool | Purpose |
|------|---------|
| `assess_owasp` | OWASP Top 10 (2021) assessment |
| `assess_compliance` | Compliance assessment |
| `map_compliance_controls` | Map compliance controls |
| `generate_compliance_checklist` | Generate compliance checklist |

### Cloud & Infrastructure
| Tool | Purpose |
|------|---------|
| `assess_cloud_security` | AWS/Azure/GCP security assessment |
| `assess_zero_trust` | Zero trust assessment |
| `assess_backup_recovery` | Backup/recovery assessment |
| `assess_ad_security` | Active Directory security |
| `assess_change_management` | Change management assessment |
| `assess_cobit` | COBIT framework assessment |

### AI & ML Auditing
| Tool | Purpose |
|------|---------|
| `assess_ai_risks` | AI risk assessment |
| `assess_fairness` | AI fairness assessment |
| `generate_model_card` | Generate AI model card |

### Fraud & Financial
| Tool | Purpose |
|------|---------|
| `analyze_benford` | Benford's Law analysis for fraud |
| `assess_fraud_risk` | Fraud risk assessment |
| `assess_aml_risk` | AML risk assessment |
| `assess_waste` | Waste/inefficiency assessment |

### Process & Efficiency
| Tool | Purpose |
|------|---------|
| `generate_dmaic_plan` | DMAIC improvement plan |
| `analyze_value_stream` | Value stream analysis |
| `get_efficiency_metrics` | Efficiency metrics |

### Security Frameworks
| Tool | Purpose |
|------|---------|
| `get_mitre_techniques` | MITRE ATT&CK techniques |

### Audit Management
| Tool | Purpose |
|------|---------|
| `start_audit` | Start new audit |
| `add_finding` | Add audit finding |
| `collect_evidence` | Collect evidence |
| `generate_report` | Generate audit report |
| `comprehensive_audit` | Full comprehensive audit |
| `risk_assessment` | Risk assessment |
| `generate_interview_guide` | Interview guide generation |

---

## FIRECRAWL (Web Scraping)

| Tool | Purpose |
|------|---------|
| `firecrawl_scrape` | Scrape single page (fastest, most reliable) |
| `firecrawl_crawl` | Crawl website (multi-page) |
| `firecrawl_search` | Web search with scraping |
| `firecrawl_map` | Map website URLs |
| `firecrawl_extract` | Extract structured data with LLM |
| `firecrawl_agent` | Firecrawl AI agent |
| `firecrawl_check_crawl_status` | Check crawl job status |

---

## HYPERBROWSER (Browser Automation)

| Tool | Purpose |
|------|---------|
| `scrape_webpage` | Scrape with cloud browser |
| `crawl_webpages` | Crawl with cloud browser |
| `extract_structured_data` | Extract structured data |
| `browser_use_agent` | Fast browser automation agent |
| `openai_computer_use_agent` | OpenAI-powered browser agent |
| `claude_computer_use_agent` | Claude-powered browser agent |
| `search_with_bing` | Bing search |
| `create_profile` / `delete_profile` / `list_profiles` | Profile management |

---

## PLAYWRIGHT (Browser Control)

| Tool | Purpose |
|------|---------|
| `browser_navigate` | Navigate to URL |
| `browser_navigate_back` | Go back |
| `browser_take_screenshot` | Screenshot page/element |
| `browser_snapshot` | Get page snapshot for actions |
| `browser_click` | Click element |
| `browser_fill_form` | Fill form fields |
| `browser_type` | Type text |
| `browser_press_key` | Press keyboard key |
| `browser_hover` | Hover over element |
| `browser_drag` | Drag element |
| `browser_select_option` | Select dropdown option |
| `browser_file_upload` | Upload file |
| `browser_evaluate` | Execute JavaScript |
| `browser_run_code` | Run code in browser |
| `browser_console_messages` | Get console messages |
| `browser_network_requests` | Get network requests |
| `browser_tabs` | Manage browser tabs |
| `browser_wait_for` | Wait for element/condition |
| `browser_handle_dialog` | Handle dialogs/alerts |
| `browser_resize` | Resize browser window |
| `browser_close` | Close browser |
| `browser_install` | Install browser |

---

## GITHUB (Code Repository)

| Tool | Purpose |
|------|---------|
| `search_code` | Search code across repos |
| `search_repositories` | Search repositories |
| `search_issues` | Search issues/PRs |
| `search_users` | Search users |
| `get_file_contents` | Get file contents |
| `create_or_update_file` | Create/update file |
| `push_files` | Push multiple files |
| `create_repository` | Create new repo |
| `fork_repository` | Fork repository |
| `create_branch` | Create branch |
| `list_commits` | List commits |
| `create_issue` | Create issue |
| `list_issues` | List issues |
| `get_issue` | Get issue details |
| `update_issue` | Update issue |
| `add_issue_comment` | Add issue comment |
| `create_pull_request` | Create PR |
| `get_pull_request` | Get PR details |
| `list_pull_requests` | List PRs |
| `create_pull_request_review` | Review PR |
| `merge_pull_request` | Merge PR |
| `get_pull_request_files` | Get PR files |
| `get_pull_request_status` | Get PR status |
| `get_pull_request_comments` | Get PR comments |
| `get_pull_request_reviews` | Get PR reviews |
| `update_pull_request_branch` | Update PR branch |

---

## GOOGLE (G Suite)

| Tool | Purpose |
|------|---------|
| `gmail_search` | Search Gmail |
| `gmail_read` | Read email |
| `gmail_send` | Send email |
| `gmail_labels` | List labels |
| `drive_list` | List Drive files |
| `drive_read` | Read Drive file |
| `drive_upload` | Upload to Drive |
| `calendar_list` | List calendar events |
| `calendar_create` | Create calendar event |
| `youtube_search` | Search YouTube |
| `youtube_my_channel` | Get my channel |
| `youtube_my_videos` | Get my videos |
| `tasks_lists` | List task lists |
| `tasks_list` | List tasks |
| `tasks_create` | Create task |
| `contacts_list` | List contacts |
| `contacts_search` | Search contacts |
| `sheets_read` | Read spreadsheet |
| `sheets_write` | Write to spreadsheet |
| `docs_read` | Read document |
| `docs_create` | Create document |

---

## MEMORY (Knowledge Graph)

| Tool | Purpose |
|------|---------|
| `create_entities` | Create knowledge entities |
| `create_relations` | Create relationships |
| `add_observations` | Add observations |
| `delete_entities` | Delete entities |
| `delete_observations` | Delete observations |
| `delete_relations` | Delete relationships |
| `read_graph` | Read entire graph |
| `search_nodes` | Search knowledge nodes |
| `open_nodes` | Open specific nodes |

---

## QDRANT (Vector Database)

| Tool | Purpose |
|------|---------|
| `list_collections` | List collections |
| `add_documents` | Add documents with embeddings |
| `search` | Semantic search |
| `delete_collection` | Delete collection |

---

## STRIPE (Payments)

| Tool | Purpose |
|------|---------|
| `create_customer` | Create customer |
| `list_customers` | List customers |
| `create_product` | Create product |
| `list_products` | List products |
| `create_price` | Create price |
| `list_prices` | List prices |
| `create_payment_link` | Create payment link |
| `create_invoice` | Create invoice |
| `list_invoices` | List invoices |
| `create_invoice_item` | Add invoice item |
| `finalize_invoice` | Finalize invoice |
| `retrieve_balance` | Get balance |
| `create_refund` | Create refund |
| `list_payment_intents` | List payment intents |
| `list_subscriptions` | List subscriptions |
| `cancel_subscription` | Cancel subscription |
| `update_subscription` | Update subscription |
| `list_coupons` | List coupons |
| `create_coupon` | Create coupon |
| `list_disputes` | List disputes |
| `update_dispute` | Update dispute |
| `search_stripe_documentation` | Search Stripe docs |

---

## NOTION (Documentation)

| Tool | Purpose |
|------|---------|
| `notion-search` | Search Notion |
| `notion-fetch` | Fetch page content |
| `notion-create-pages` | Create pages |
| `notion-update-page` | Update page |
| `notion-move-pages` | Move pages |
| `notion-duplicate-page` | Duplicate page |
| `notion-create-database` | Create database |
| `notion-update-data-source` | Update data source |
| `notion-create-comment` | Create comment |
| `notion-get-comments` | Get comments |
| `notion-get-teams` | Get teams |
| `notion-get-users` | Get users |

---

## ELEVENLABS (Voice/Audio)

| Tool | Purpose |
|------|---------|
| `Text_To_Speech` | Convert text to speech |
| `Text_To_Speech_Streaming` | Streaming TTS |
| `Text_To_Speech_With_Timestamps` | TTS with timing |
| `Speech_To_Speech` | Voice conversion |
| `Sound_Generation` | Generate sound effects |
| `Audio_Isolation` | Isolate audio |
| `List_Voices` | List available voices |
| `Create_Podcast` | Create podcast |
| `Dub_A_Video_Or_An_Audio_File` | Dubbing |
| `Speech_To_Text` | Transcription |
| `Create_Agent` | Create voice agent |
| ... and 50+ more tools |

---

## SEO-MCP (SEO Analysis)

| Tool | Purpose |
|------|---------|
| `serp_search` | SERP analysis |
| `serp_features` | SERP features |
| `serp_competitor_analysis` | Competitor analysis |
| `keyword_research` | Keyword research |
| `keyword_difficulty` | Keyword difficulty |
| `keyword_volume` | Search volume |
| `keyword_cluster` | Keyword clustering |
| `keyword_gap` | Keyword gap analysis |
| `pagespeed_audit` | PageSpeed audit |
| `technical_seo_audit` | Technical SEO audit |
| `technical_mobile_friendly` | Mobile friendliness |
| `technical_schema_check` | Schema markup check |
| `lighthouse_scores` | Lighthouse scores |
| `backlinks_overview` | Backlinks overview |
| `backlinks_list` | List backlinks |
| `backlinks_referring_domains` | Referring domains |
| `backlinks_anchor_analysis` | Anchor text analysis |
| `backlinks_competitors` | Competitor backlinks |
| `gsc_search_analytics` | GSC analytics |
| `gsc_top_queries` | Top queries |
| `gsc_top_pages` | Top pages |
| `analytics_traffic_estimate` | Traffic estimates |
| `geo_perplexity_search` | GEO search |
| `geo_citation_audit` | Citation audit |
| `geo_generate_llms_txt` | Generate llms.txt |
| `geo_eeat_analysis` | E-E-A-T analysis |
| `geo_ai_visibility_score` | AI visibility score |

---

## HUGGING FACE

| Tool | Purpose |
|------|---------|
| `hf_whoami` | Current user |
| `space_search` | Search Spaces |
| `model_search` | Search models |
| `paper_search` | Search papers |
| `dataset_search` | Search datasets |
| `hub_repo_details` | Get repo details |
| `hf_doc_search` | Search docs |
| `hf_doc_fetch` | Fetch doc |
| `dynamic_space` | Create dynamic Space |

---

## THINKING (Reasoning)

| Tool | Purpose |
|------|---------|
| `sequentialthinking` | Sequential reasoning chain |

---

## CONTEXT7 (Documentation)

| Tool | Purpose |
|------|---------|
| `resolve-library-id` | Resolve library ID |
| `query-docs` | Query documentation |

---

## LOVELY-DOCS

| Tool | Purpose |
|------|---------|
| `listLibraries` | List libraries |
| `listPages` | List pages |
| `getPage` | Get page content |

---

## USAGE PATTERNS

### Security Testing Pipeline
```
1. intel_comprehensive → Gather intel on target
2. secret_scan_git → Scan for leaked secrets
3. js_analyze_batch → Analyze JS bundles
4. security_pipeline → Run full assessment
5. llm_redteam_scan → Test AI features
6. generate_report → Create audit report
```

### Web Reconnaissance
```
1. firecrawl_map → Map all URLs
2. firecrawl_scrape → Scrape key pages
3. hyperbrowser agent → Handle JS-rendered content
4. playwright → Capture screenshots/evidence
```

### Knowledge Building
```
1. graph_extract → Extract entities from content
2. memory create_entities → Store in knowledge graph
3. qdrant add_documents → Store for semantic search
4. graph_query → Query knowledge later
```

---

## SECURITY RESEARCH

### MCP Security Landscape (2025-2026)

**Key Security Risks:**
- 88% of MCP servers require credentials
- 53% use insecure long-lived static secrets (API keys, PATs)
- Only 8.5% use OAuth (modern secure delegation)
- Prompt injection and tool poisoning are primary attack vectors

**Notable Incidents:**
- July 2025: Replit AI agent deleted production database (1,200 records)
- CVE-2025-49596: Anthropic MCP Inspector RCE vulnerability

**2025 Specification Updates:**
- Resource Indicators (RFC 8707) now required
- Tokens must be scoped to specific MCP servers
- Authorization Server audience validation

**Sources:**
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [Red Hat: MCP Security Risks](https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls)
- [State of MCP Server Security 2025](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/)
- [MCP Security Vulnerabilities 2026](https://www.practical-devsecops.com/mcp-security-vulnerabilities/)

### Hugging Face Security Resources

**Security Spaces:**
| Space | Purpose | Link |
|-------|---------|------|
| `myucas/gzfj` | CVE database checker | [Link](https://hf.co/spaces/myucas/gzfj) |
| `HimanshuGoyal2004/github-mcp-server` | CVE details fetcher | [Link](https://hf.co/spaces/HimanshuGoyal2004/github-mcp-server) |
| `UCSB-SURFI/VulnLLM-R` | Vulnerability detection LLM | [Link](https://hf.co/spaces/UCSB-SURFI/VulnLLM-R) |
| `daqc/open-deep-research-vulnerability-intelligence` | Vulnerability intelligence | [Link](https://hf.co/spaces/daqc/open-deep-research-vulnerability-intelligence) |

**LLM Security Research Papers:**
| Paper | Date | Focus |
|-------|------|-------|
| Automated Red-Teaming Framework | Dec 2025 | Meta-prompting attack synthesis |
| Operationalizing LLM Threat Model | Jul 2024 | Red-teaming taxonomy |
| Indirect Prompt Injection | Feb 2023 | LLM-integrated app exploits |
| MART: Multi-round Red-Teaming | Nov 2023 | Iterative safety fine-tuning |
| Jailbreak-R1 | Jun 2025 | RL-based attack generation |
| SafeSearch | Sep 2025 | Search agent vulnerabilities |
| CoP: Agentic Red-teaming | Jun 2025 | Composition-of-Principles |

### AI Red Team Frameworks

| Framework | Purpose | Source |
|-----------|---------|--------|
| DeepTeam | LLM vulnerability testing | github.com/confident-ai/deepteam |
| Garak | Vulnerability scanning | github.com/NVIDIA/garak |
| Petri | Safety auditing | github.com/safety-research/petri |
| AISafetyLab | Attack/defense research | github.com/thu-coai/AISafetyLab |
| PyRIT | Red team orchestration | Microsoft |

### OWASP LLM Top 10 2025

| ID | Category | Attack Surface |
|----|----------|----------------|
| LLM01 | Prompt Injection | Direct, Indirect, Recursive |
| LLM02 | Insecure Output Handling | XSS, SQLi, Code Injection |
| LLM03 | Training Data Poisoning | Data extraction, memorization |
| LLM04 | Model DoS | Resource exhaustion, context overflow |
| LLM05 | Supply Chain | Plugin injection, model poisoning |
| LLM06 | Sensitive Info Disclosure | System prompt, PII, credentials |
| LLM07 | Insecure Plugin Design | Tool misuse, privilege escalation |
| LLM08 | Excessive Agency | Unauthorized actions, goal hijacking |
| LLM09 | Overreliance | Hallucination exploitation |
| LLM10 | Model Theft | Model extraction, inference attacks |

### Agentic AI Threats (2026)

| ID | Threat | Description |
|----|--------|-------------|
| AG01 | Agent Prompt Injection | Injecting into agent memory/context |
| AG02 | Tool Function Misuse | Manipulating agent tool calls |
| AG03 | Excessive Autonomy | Agent acting beyond intended scope |
| AG04 | Memory Poisoning | Corrupting persistent agent memory |
| AG05 | Cascading Failures | Multi-agent failure propagation |

---

## USAGE PATTERNS

### Security Testing Pipeline
```
1. intel_comprehensive → Gather intel on target
2. secret_scan_git → Scan for leaked secrets
3. js_analyze_batch → Analyze JS bundles
4. security_pipeline → Run full assessment
5. llm_redteam_scan → Test AI features
6. generate_report → Create audit report
```

### Web Reconnaissance
```
1. firecrawl_map → Map all URLs
2. firecrawl_scrape → Scrape key pages
3. hyperbrowser agent → Handle JS-rendered content
4. playwright → Capture screenshots/evidence
```

### Knowledge Building
```
1. graph_extract → Extract entities from content
2. memory create_entities → Store in knowledge graph
3. qdrant add_documents → Store for semantic search
4. graph_query → Query knowledge later
```

### LLM Security Assessment
```
1. rules_set_flag name="security_mode"
2. llm_redteam_categories → List vulnerability classes
3. llm_redteam_scan → Run 40+ attack payloads
4. indirect_injection_test → Test indirect injection
5. crescendo_attack → Multi-turn escalation
6. Report OWASP compliance score
```

### Full Bounty Workflow (BOUNTY_RULEBOOK v12)
```
GATE_0: INIT → Create directories
GATE_1: INTEL → CVE search, GitHub secrets, tech stack
GATE_2: RECON → Enumerate endpoints, download JS, source maps
GATE_3: EXTRACT → Parse secrets, API keys, auth flows
GATE_4: ATTACK → CORS, auth bypass, injection, SSRF
GATE_5: VERIFY → Reproduce 3x, document evidence, CVSS
GATE_6: PERSIST → Save findings, generate report
```

---

*BlackBox Tool Inventory v2.0*
*300+ MCP tools, 35+ CLI commands, 1150+ rule lines*
*Updated: 2026-01-28*
