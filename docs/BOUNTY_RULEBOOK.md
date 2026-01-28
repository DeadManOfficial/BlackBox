# BOUNTY RULEBOOK - NATIVE ONLY

```yaml
target: "{opusclip}"
output: ~/BlackBox/targets/{target}/
```

## SCOPE

**IN:** API endpoints, Workflows, Tools, Software, Banking/Financial, Code, API/Keys/OAuth/Login/Email, Data, Auth flows, User data, Third-party integrations, Infrastructure

**OUT:** Physical, Social engineering, DoS

---

## GATES

```
G0 INIT     → dirs → G1
G1 INTEL    → cves, exploits, github, techstack → G2
G2 RECON    → endpoints, js, sourcemaps, cookies, headers → G3
G3 EXTRACT  → ALL 12 scope items → G4
G4 ATTACK   → ALL 20 vectors → G5
G5 VERIFY   → 3x repro, evidence, cvss → G6
G6 PERSIST  → Analyze findings → G7
G7 LOOP     → Breakthrough Exploits, save, report → DONE
```

---

## NATIVE TOOLS (60+ classes)

### VULNERABILITY SCANNERS
```python
from modules.scraper.tools import (
    # Core Scanners
    NucleiScanner,          # CVE/misconfig scanning (10k+ templates)
    CORSScanner,            # CORS misconfiguration
    IDORScanner,            # Insecure direct object reference
    XXEScanner,             # XML external entity
    CRLFScanner,            # CRLF injection / response splitting
    RCEScanner,             # Remote code execution
    UnifiedVulnScanner,     # All-in-one scanner
)
```

### JAVASCRIPT ANALYSIS
```python
from modules.scraper.tools import (
    JSSecurityAnalyzer,     # 700+ secret patterns
    JSDeepAnalyzer,         # Source maps, AST, bundle unpacking
)
```

### ATTACK TOOLS
```python
from modules.scraper.tools import (
    # Advanced Attacks
    WAFBypassEngine,        # WAF bypass, origin discovery
    RaceConditionTester,    # Race condition detection
    OAuthAttacker,          # OAuth flow exploitation
    PaymentSecurityTester,  # Payment manipulation
    HTTPSmugglingDetector,  # CL.TE, TE.CL, TE.TE

    # Deep Pentesting
    JWTAnalyzer,            # JWT none/weak/confusion
    FileUploadTester,       # Upload bypass, polyglot
    WebSocketTester,        # CSWSH, origin bypass
    RateLimitBypass,        # Rate limit circumvention
    BusinessLogicTester,    # Logic flaw testing
    APIFuzzer,              # Parameter discovery
    SourceMapHunter,        # Sensitive code paths
)
```

### RECON TOOLS
```python
from modules.scraper.tools import (
    SubdomainEnumerator,    # DNS + passive sources
    GraphQLSecurityTester,  # Introspection, batching
    AuthTester,             # Session/permission testing
    CloudAssetDiscovery,    # AWS/GCP/Azure
)
```

### AI/LLM SECURITY
```python
from modules.scraper.tools import (
    AISecurityTester,       # 10 vulnerability types
    LLMRedTeamFramework,    # 40+ classes, OWASP LLM Top 10
    PayloadLibrary,         # Prompt injection payloads
)
```

### STEALTH & EVASION
```python
from modules.scraper.tools import (
    StealthBrowserFactory,  # Camoufox/Nodriver/Playwright
    TLSClient,              # curl_cffi fingerprinting
    BrowserPool,            # Context pooling
)
```

### AUTONOMOUS PENTEST
```python
from modules.pentest.orchestrator import Orchestrator
from modules.scraper.tools import (
    AutonomousPentestAgent, # MCTS attack planning
    AttackPathPlanner,      # Path optimization
)
```

### INTEL & PERSISTENCE
```python
from modules.pentest.intel import IntelFetcher
from modules.pentest.bounty import BountyTracker
from modules.pentest.state import StateManager
from modules.bugbounty.module import BugBountyModule
```

---

## EXTRACT (12 items)

| # | Target | Tool | Output |
|---|--------|------|--------|
| 1 | API endpoints | JSSecurityAnalyzer, APIFuzzer | api_endpoints.json |
| 2 | Workflows | BusinessLogicTester | workflows.json |
| 3 | Tools | JSDeepAnalyzer | tools.json |
| 4 | Software | NucleiScanner | software.json |
| 5 | Financial | PaymentSecurityTester | financial.json |
| 6 | Code | JSDeepAnalyzer, SourceMapHunter | code/ |
| 7 | Auth | JWTAnalyzer, OAuthAttacker | auth.json |
| 8 | Data | IDORScanner | data_models.json |
| 9 | Auth flows | AuthTester | auth_flows.json |
| 10 | User data | IDORScanner | user_data.json |
| 11 | Integrations | JSSecurityAnalyzer | integrations.json |
| 12 | Infrastructure | SubdomainEnumerator, CloudAssetDiscovery | infrastructure.json |

---

## ATTACK (20 vectors)

| # | Vector | Native Tool |
|---|--------|-------------|
| 1 | Auth | AuthTester, JWTAnalyzer |
| 2 | IDOR | IDORScanner |
| 3 | Injection | RCEScanner, XXEScanner, APIFuzzer |
| 4 | SSRF | SSRFPayloadGenerator |
| 5 | CORS | CORSScanner |
| 6 | CSRF | BusinessLogicTester |
| 7 | JWT | JWTAnalyzer |
| 8 | OAuth | OAuthAttacker |
| 9 | File | FileUploadTester |
| 10 | Logic | BusinessLogicTester, RaceConditionTester |
| 11 | Rate | RateLimitBypass |
| 12 | Info | JSDeepAnalyzer, SourceMapHunter |
| 13 | Crypto | JWTAnalyzer |
| 14 | API | APIFuzzer, IDORScanner |
| 15 | GraphQL | GraphQLSecurityTester |
| 16 | WebSocket | WebSocketTester |
| 17 | Cache | HTTPSmugglingDetector |
| 18 | Smuggling | HTTPSmugglingDetector |
| 19 | Subdomain | SubdomainEnumerator |
| 20 | Cloud | CloudAssetDiscovery, GCSAttacker |

---

## USAGE EXAMPLE

```python
import asyncio
from modules.scraper.tools import (
    UnifiedVulnScanner,
    JSSecurityAnalyzer,
    LLMRedTeamFramework,
    StealthBrowserFactory,
)

async def run_assessment(target: str):
    # Initialize scanners
    vuln_scanner = UnifiedVulnScanner(timeout=15)
    js_analyzer = JSSecurityAnalyzer()

    # Run vulnerability scan
    results = await vuln_scanner.scan_all(f"https://{target}")

    # Analyze JavaScript
    js_report = await js_analyzer.analyze_url(f"https://{target}")

    # Get all findings
    findings = vuln_scanner.get_all_findings()
    findings.extend(js_report.findings)

    return findings

# Run
findings = asyncio.run(run_assessment("opusclip.com"))
```

---

## CLI

```bash
# Full pipeline
python -m modules.pentest.orchestrator opusclip.com

# Individual tools
python -c "
from modules.scraper.tools import CORSScanner
import asyncio
scanner = CORSScanner()
results = asyncio.run(scanner.scan('https://opusclip.com'))
print(results)
"
```

---

## IF/THEN

```
cors_reflects        → CORSScanner → HIGH
idor_found           → IDORScanner → HIGH
xxe_possible         → XXEScanner → CRITICAL
rce_confirmed        → RCEScanner → CRITICAL
jwt_none_accepted    → JWTAnalyzer → CRITICAL
sourcemaps_exposed   → SourceMapHunter → scan secrets
graphql_introspect   → GraphQLSecurityTester → dump schema
payment_no_verify    → PaymentSecurityTester → CRITICAL
race_condition       → RaceConditionTester → logic bypass
```

---

## EVIDENCE

```
targets/{target}/findings/{ID}.json
targets/{target}/findings/{ID}_request
targets/{target}/findings/{ID}_response
targets/{target}/findings/{ID}_poc.py
```

```json
{
  "id": "VULN-001",
  "type": "cors",
  "severity": "HIGH",
  "cvss": 6.5,
  "endpoint": "https://api.opusclip.com/v1/user",
  "evidence": "Origin reflection with credentials",
  "verified": true,
  "attempts": 3,
  "tool": "CORSScanner"
}
```

---

## RUN

```
FOR tool IN NATIVE_TOOLS:
    result = tool.scan(target)
    IF result.findings:
        save(result)

NEVER skip gate
NEVER skip attack vector
ALL findings 3x verification
ALL evidence documented
```

---

## TOOL COUNT

| Category | Count |
|----------|-------|
| Vulnerability Scanners | 7 |
| JavaScript Analysis | 2 |
| Attack Tools | 12 |
| Recon Tools | 4 |
| AI/LLM Security | 3 |
| Stealth/Evasion | 3 |
| Autonomous | 2 |
| Intel/Persistence | 4 |
| **TOTAL** | **37 native classes** |

All tools are Python native. No MCP dependencies. No external APIs required for core functionality.
