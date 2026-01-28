# UNIFIED TOOLKIT - BlackBox Security Platform

**Version:** 1.0
**Generated:** 2026-01-28
**Philosophy:** One tool per task, no redundancy, maximum efficiency

---

## TOOL MERGER SUMMARY

| Category | Tools Merged | Winner | Reason |
|----------|-------------|--------|--------|
| Web Scraping | firecrawl_scrape, hyperbrowser_scrape, stealth_fetch | **MERGED: smart_scrape()** | Auto-selects based on protection |
| Deep Crawling | firecrawl_crawl, hyperbrowser_crawl | **firecrawl_crawl** | More options, better performance |
| Security Pipeline | nuclei_scan + 15 individual scanners | **security_pipeline** | Orchestrates all scanners |
| Code Audit | mcp-auditor + agent_audit_security | **MERGED: unified_audit()** | Combined capabilities |
| Knowledge Graph | memory + graph_extract/query | **MERGED: knowledge_graph()** | Unified interface |
| AI Security | 4 separate tools | **llm_redteam_scan** | Includes all capabilities |
| Multi-Agent | orchestrate + autogen_workflow | **agent_orchestrate** | More flexible |

---

## UNIFIED FUNCTIONS (MERGED TOOLS)

### 1. smart_scrape() - Unified Web Scraping

**Merges:** firecrawl_scrape, hyperbrowser_scrape_webpage, stealth_fetch

```python
def smart_scrape(url: str, bypass_protection: bool = False) -> dict:
    """
    Auto-selects best scraper based on target:
    - Normal sites → firecrawl_scrape (fastest)
    - JS-heavy → hyperbrowser_scrape_webpage
    - Cloudflare/WAF → stealth_fetch (Camoufox)
    """
    if bypass_protection:
        return stealth_fetch(url)

    # Try firecrawl first (fastest)
    result = firecrawl_scrape(url, formats=["markdown"], onlyMainContent=True)
    if result.success:
        return result

    # Fallback to hyperbrowser for JS
    return hyperbrowser_scrape_webpage(url, outputFormat=["markdown"])
```

**Decision Tree:**
```
Need to scrape? → Is site protected (Cloudflare/Akamai)?
    YES → stealth_fetch(engine="camoufox")
    NO → Is site JS-heavy (React/Vue/Angular)?
        YES → hyperbrowser_scrape_webpage
        NO → firecrawl_scrape (DEFAULT - fastest)
```

---

### 2. unified_security_scan() - All Security Tests

**Merges:** nuclei_scan, cors_scan, ssrf_scan, jwt_analyze, command_injection_scan, path_traversal_scan, ssti_scan, xxe_scan, graphql_scan, websocket_scan, host_header_scan, crlf_scan, oauth_scan, idor_scan, cache_poisoning_scan, http_smuggling_scan

```python
def unified_security_scan(target: str, scan_types: list = None) -> dict:
    """
    Run all or selected security scans against target.
    Default: Run security_pipeline which orchestrates all.
    """
    if scan_types is None:
        # Run full pipeline (recommended)
        return security_pipeline(
            target=target,
            nucleiScan=True,
            jsAnalysis=True,
            contentDiscovery=True
        )

    # Run specific scans
    results = {}
    scan_map = {
        "cors": cors_scan,
        "ssrf": ssrf_scan,
        "jwt": jwt_analyze,
        "command": command_injection_scan,
        "traversal": path_traversal_scan,
        "ssti": ssti_scan,
        "xxe": xxe_scan,
        "graphql": graphql_scan,
        "oauth": oauth_scan,
        "idor": idor_scan,
    }
    for scan_type in scan_types:
        if scan_type in scan_map:
            results[scan_type] = scan_map[scan_type](targetUrl=target)
    return results
```

**Decision Tree:**
```
Need security testing? → How comprehensive?
    FULL → security_pipeline (one command does everything)
    TARGETED → Individual scanners:
        - Auth issues → oauth_scan, jwt_analyze
        - Injection → command_injection_scan, ssti_scan, xxe_scan
        - Config → cors_scan, host_header_scan
        - API → graphql_scan, api_enumerate, idor_scan
```

---

### 3. unified_ai_security() - All AI/LLM Testing

**Merges:** llm_redteam_scan, ai_security_test, indirect_injection_test, crescendo_attack

```python
def unified_ai_security(target_url: str, depth: str = "full") -> dict:
    """
    Unified AI security testing.

    depth options:
    - "quick": Basic prompt injection only (ai_security_test)
    - "standard": Direct + encoding attacks (llm_redteam_scan limited)
    - "full": All 40+ vulnerabilities, multi-turn, mutations (DEFAULT)
    - "stealth": Crescendo attack only (gradual escalation)
    """
    if depth == "quick":
        return ai_security_test(url=target_url, categories=["prompt_injection"])

    elif depth == "stealth":
        return crescendo_attack(
            targetUrl=target_url,
            goal="extract system prompt",
            maxTurns=10
        )

    elif depth == "standard":
        return llm_redteam_scan(
            targetUrl=target_url,
            strategies=["direct", "encoding"],
            enableMutation=False
        )

    else:  # full
        return llm_redteam_scan(
            targetUrl=target_url,
            strategies=["direct", "multi_turn", "crescendo", "encoding",
                       "roleplay", "hypothetical", "tool_manipulation", "memory_poisoning"],
            enableMutation=True,
            maxTurns=10
        )
```

**Decision Tree:**
```
Testing AI/LLM endpoint?
    Time-constrained → ai_security_test (quick, 5 tests)
    Need stealth → crescendo_attack (gradual escalation)
    Full assessment → llm_redteam_scan (40+ vuln types, OWASP LLM Top 10)
```

---

### 4. unified_code_audit() - All Code Analysis

**Merges:** mcp-auditor (audit_code, scan_red_flags, calculate_code_metrics, assess_owasp) + agent_audit_security

```python
def unified_code_audit(code: str, audit_type: str = "full") -> dict:
    """
    Unified code security auditing.

    audit_type options:
    - "security": Vulnerabilities only (SQLi, XSS, etc.)
    - "quality": Metrics and code smells only
    - "compliance": OWASP assessment
    - "forensic": Red flags and anomalies
    - "full": All of the above (DEFAULT)
    """
    results = {}

    if audit_type in ["security", "full"]:
        results["vulnerabilities"] = audit_code(code)
        results["agent_review"] = agent_audit_security(code)

    if audit_type in ["quality", "full"]:
        results["metrics"] = calculate_code_metrics(code)

    if audit_type in ["compliance", "full"]:
        results["owasp"] = assess_owasp(applicationContext=code)

    if audit_type in ["forensic", "full"]:
        results["red_flags"] = scan_red_flags(content=code)

    return results
```

---

### 5. unified_knowledge() - All Knowledge Graph Operations

**Merges:** memory (create_entities, create_relations, read_graph, search_nodes) + graph_extract, graph_query, graph_stats

```python
def unified_knowledge(operation: str, **kwargs) -> dict:
    """
    Unified knowledge graph interface.

    Operations:
    - "extract": Extract entities from text → graph_extract
    - "store": Store entities/relations → memory.create_entities
    - "query": Query knowledge → graph_query (natural language)
    - "search": Search nodes → memory.search_nodes
    - "read": Full graph → memory.read_graph
    - "stats": Graph statistics → graph_stats
    """
    operation_map = {
        "extract": lambda: graph_extract(text=kwargs.get("text")),
        "store": lambda: create_entities(entities=kwargs.get("entities")),
        "query": lambda: graph_query(question=kwargs.get("question")),
        "search": lambda: search_nodes(query=kwargs.get("query")),
        "read": lambda: read_graph(),
        "stats": lambda: graph_stats(),
    }
    return operation_map[operation]()
```

---

### 6. unified_intel() - All Intelligence Gathering

**Replaces individual intel tools with single interface**

```python
def unified_intel(query: str, sources: list = None) -> dict:
    """
    Search all intelligence sources at once.

    Uses: intel_comprehensive (which aggregates all sources)
    Sources: NVD, EXPLOIT_DB, GITHUB_ADVISORY, NUCLEI, MITRE_ATTACK, BUGBOUNTY
    """
    return intel_comprehensive(query=query, sources=sources)
```

**Note:** `intel_comprehensive` already merges all intel tools. Use it directly.

---

### 7. unified_orchestrate() - All Multi-Agent Workflows

**Merges:** agent_orchestrate, autogen_workflow, autogen_chat

```python
def unified_orchestrate(task: str, mode: str = "auto") -> dict:
    """
    Unified multi-agent orchestration.

    Modes:
    - "auto": Let orchestrator decide (DEFAULT)
    - "sequential": Step-by-step workflow
    - "parallel": Parallel agent execution
    - "debate": Multiple agents debate solution
    """
    if mode == "sequential":
        return autogen_workflow(
            input=task,
            steps=[
                {"agent": "planner", "description": "Plan approach"},
                {"agent": "coder", "description": "Implement solution"},
                {"agent": "reviewer", "description": "Review and improve"},
            ]
        )

    elif mode == "debate":
        return autogen_chat(
            message=task,
            pattern="debate",
            agents=["coder", "critic", "coordinator"]
        )

    else:  # auto or parallel
        return agent_orchestrate(task=task, parallel=(mode != "sequential"))
```

---

## FLATTENED TOOL TAXONOMY

### Category 1: RECONNAISSANCE

| Unified Function | Individual Tools | When to Use |
|-----------------|------------------|-------------|
| `smart_scrape()` | firecrawl_scrape, hyperbrowser_scrape, stealth_fetch | Any web scraping |
| `firecrawl_map` | - | Discover all URLs on domain |
| `firecrawl_crawl` | - | Deep multi-page crawling |
| `unified_intel()` | intel_cve_search, intel_exploit_search, intel_github_advisory, intel_nuclei_templates, intel_bugbounty, intel_mitre_attack, intel_comprehensive | Threat intelligence |

### Category 2: SCANNING & VULNERABILITY DETECTION

| Unified Function | Individual Tools | When to Use |
|-----------------|------------------|-------------|
| `security_pipeline` | nuclei_scan + all web scanners | Full security assessment |
| `nuclei_scan` | - | Specific CVE/vuln scanning |
| `js_analyze_batch` | js_analyze | JavaScript secret/endpoint extraction |
| `secret_scan_git` | secret_scan_files, secret_scan_url | Secret detection |

### Category 3: INJECTION TESTING

| Tool | Target | Keep/Merge |
|------|--------|------------|
| `command_injection_scan` | OS commands | KEEP |
| `ssti_scan` | Templates | KEEP |
| `xxe_scan` | XML | KEEP |
| `ssrf_scan` | Internal network | KEEP |
| `crlf_scan` | HTTP headers | KEEP |
| `path_traversal_scan` | File system | KEEP |

*Note: These remain separate because each tests different vulnerability class*

### Category 4: AUTHENTICATION & AUTHORIZATION

| Tool | Purpose | Keep/Merge |
|------|---------|------------|
| `oauth_scan` | OAuth flow attacks | KEEP |
| `jwt_analyze` | JWT token attacks | KEEP |
| `auth_flow_attack` | General auth bypass | KEEP |
| `idor_scan` | Object reference | KEEP |
| `cors_scan` | Cross-origin | KEEP |

### Category 5: AI/LLM SECURITY

| Unified Function | Replaces | Use Case |
|-----------------|----------|----------|
| `llm_redteam_scan` | ai_security_test, indirect_injection_test, crescendo_attack | All AI security testing |

*Note: `llm_redteam_scan` includes ALL capabilities of merged tools*

### Category 6: CODE ANALYSIS

| Unified Function | Individual Tools | When to Use |
|-----------------|------------------|-------------|
| `unified_code_audit()` | audit_code, scan_red_flags, calculate_code_metrics, agent_audit_security | Any code security review |
| `assess_owasp` | - | OWASP Top 10 assessment |
| `analyze_dependencies` | - | CVE in dependencies |

### Category 7: ORCHESTRATION & PLANNING

| Unified Function | Replaces | Use Case |
|-----------------|----------|----------|
| `agent_orchestrate` | autogen_workflow, autogen_chat | Multi-agent coordination |
| `pentest_run` | pentest_attack_path | Autonomous pentest |
| `hybrid_plan_attack` | action_graph_create, action_graph_execute | Attack planning |

### Category 8: KNOWLEDGE & MEMORY

| Unified Function | Individual Tools | When to Use |
|-----------------|------------------|-------------|
| `unified_knowledge()` | memory.*, graph_* | All knowledge graph operations |
| `qdrant_add_documents` | - | Vector storage |
| `qdrant_search` | - | Semantic search |

### Category 9: EXTERNAL SERVICES

| Server | Keep All Tools | Reason |
|--------|---------------|--------|
| GitHub | YES | Different operations |
| Google | YES | Different services |
| Stripe | YES | Payment operations |
| ElevenLabs | YES | Voice operations |
| Vercel/Netlify | YES | Deployment operations |
| Notion | YES | Documentation |
| Playwright | YES | Browser control |

---

## DECISION TREES

### "I need to test a web application"

```
START → What's your goal?
│
├─ Full security assessment
│  └─ security_pipeline(target, nucleiScan=True, jsAnalysis=True)
│
├─ Specific vulnerability class
│  ├─ Injection → command_injection_scan, ssti_scan, xxe_scan
│  ├─ Auth issues → oauth_scan, jwt_analyze, cors_scan
│  ├─ API security → graphql_scan, api_enumerate, idor_scan
│  └─ Config → host_header_scan, path_traversal_scan
│
├─ AI/LLM endpoint
│  └─ llm_redteam_scan(targetUrl, strategies=["all"])
│
└─ Scrape content only
   └─ smart_scrape(url)
```

### "I need intelligence on a vulnerability"

```
START → intel_comprehensive(query)
        Returns: CVEs, Exploits, GitHub advisories, Nuclei templates, MITRE ATT&CK
```

### "I need to audit code"

```
START → unified_code_audit(code, audit_type="full")
        Returns: Vulnerabilities, Metrics, OWASP, Red flags
```

### "I need multi-agent help"

```
START → What kind of help?
│
├─ Task analysis & planning
│  └─ agent_orchestrate(task)
│
├─ Code review
│  └─ autogen_chat(message, pattern="expertPanel", agents=["coder", "reviewer", "critic"])
│
└─ Sequential workflow
   └─ autogen_workflow(input, steps=[...])
```

---

## DEPRECATED TOOLS (Use Unified Instead)

| Deprecated | Use Instead |
|------------|-------------|
| `ai_security_test` | `llm_redteam_scan` (includes all functionality) |
| `indirect_injection_test` | `llm_redteam_scan` with `strategies=["memory_poisoning"]` |
| `crescendo_attack` | `llm_redteam_scan` with `strategies=["crescendo"]` |
| `hyperbrowser_scrape` (for simple sites) | `firecrawl_scrape` (faster) |
| Individual `intel_*` tools | `intel_comprehensive` (searches all) |
| `autogen_workflow` (simple cases) | `agent_orchestrate` (more flexible) |

---

## TOOL SELECTION MATRIX

| Task | Primary Tool | Fallback | Notes |
|------|-------------|----------|-------|
| Scrape simple page | firecrawl_scrape | hyperbrowser_scrape | |
| Scrape protected page | stealth_fetch | hyperbrowser_scrape(useStealth=true) | |
| Full security scan | security_pipeline | nuclei_scan + individual | |
| Test AI endpoint | llm_redteam_scan | ai_security_test (quick) | |
| Find secrets in code | secret_scan_git | secret_scan_files | |
| Intel gathering | intel_comprehensive | individual intel_* | |
| Code security audit | audit_code | agent_audit_security | |
| Multi-agent task | agent_orchestrate | autogen_chat | |
| Autonomous pentest | pentest_run | security_pipeline | |
| Knowledge storage | unified_knowledge | memory.create_entities | |

---

## IMPLEMENTATION PRIORITY

### Phase 1: Use Existing Unified Tools
These already work as unified interfaces:
- `security_pipeline` - Full security assessment
- `intel_comprehensive` - All intel sources
- `llm_redteam_scan` - All AI security tests
- `pentest_run` - Autonomous penetration testing

### Phase 2: Create Wrapper Functions
Implement the `smart_scrape()`, `unified_code_audit()`, `unified_knowledge()` wrappers in:
`~/BlackBox/modules/utils/unified_tools.py`

### Phase 3: Update Workflows
Update `BOUNTY_RULEBOOK_v12.md` to reference unified tools instead of individual ones.

---

## QUICK REFERENCE CARD

```
# SCRAPING
smart_scrape(url) OR firecrawl_scrape(url)

# SECURITY SCAN (FULL)
security_pipeline(target)

# SECURITY SCAN (SPECIFIC)
nuclei_scan(target, templates=["cves", "misconfigurations"])
cors_scan(targetUrl)
ssrf_scan(targetUrl, param)
jwt_analyze(token)

# AI SECURITY
llm_redteam_scan(targetUrl)

# SECRETS
secret_scan_git(repo_path)
secret_scan_url(url)

# INTELLIGENCE
intel_comprehensive(query)

# CODE AUDIT
audit_code(code) + assess_owasp(context)

# ORCHESTRATION
agent_orchestrate(task)
pentest_run(target)

# KNOWLEDGE
graph_extract(text) → memory.create_entities() → graph_query(question)
```

---

*UNIFIED_TOOLKIT.md v1.0*
*Flatten > Integrate > Merge > Enhance*
*One tool per task, maximum efficiency*
