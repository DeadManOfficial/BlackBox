# BlackBox Security Platform

> **Philosophy**: Safety > Determinism > Optimization > Learning
> **Spec**: FOUNDATION.md v1.0 | rules.yaml v3.0
> **Author**: DeadManOfficial

---

## Purpose

Security operations platform providing penetration testing, vulnerability assessment, and security research capabilities. Operates under the rules engine with NASA-inspired safety architecture.

---

## Layer Assignment (per FOUNDATION.md)

| Component | Layer | Justification |
|-----------|-------|---------------|
| rules/ | LAYER_0/1 | Safety-critical rules engine |
| standards/ | LAYER_1 | Deterministic data standards |
| external-tools/ | LAYER_2 | 175 integrated security tools |
| modules/ | LAYER_2 | Tool integration modules |
| templates/ | LAYER_3 | Agent/MCP templates |

---

## Structure

```
BlackBox/
├── agents/              # Agent definitions & security prompts
├── cli/                 # BlackBox CLI commands
├── config/              # Configuration files
├── docs/                # Documentation & methodologies
├── engines/             # Pentest engine
├── examples/            # Usage examples
├── external-tools/      # 175 integrated security tools (7.2GB)
├── mcp/                 # MCP servers (deadman, kali)
├── modules/             # Integration modules
│   ├── osint/           # 7 OSINT tools
│   ├── web_security/    # 7 web security tools
│   ├── defense/         # 11 defensive tools
│   ├── cloud/           # 9 cloud security tools
│   ├── wireless/        # 10 wireless tools
│   ├── darkweb/         # 13 dark web tools
│   ├── injection/       # 3 injection tools
│   ├── payloads/        # 3 payload collections
│   └── ai_security/     # 6 AI security tools
├── reports/             # Generated reports
├── rules/               # Rules engine v3.0
├── scripts/             # Utility scripts
├── standards/           # NASA PDS4-inspired data standards
├── targets/             # Target workspaces
├── templates/           # 100+ agent & 64+ MCP templates
├── tests/               # Test suites
├── tools/               # Core tool implementations
└── workflows/           # Debug & pentest workflows
```

---

## MCP Tools (via deadman-toolkit)

```
nuclei_scan, js_analyze, ai_security_test, security_pipeline
llm_redteam_scan, pentest_run, stealth_fetch
waf_bypass_scan, race_condition_scan, oauth_scan
intel_cve_search, intel_comprehensive
```

---

## Failure Boundaries (per AXIOM_1)

Security operations trigger state degradation per FOUNDATION.md state machine:

| Failure Type | System Response | Recovery Path |
|--------------|-----------------|---------------|
| Single operation failure | → DEGRADED | Fix issue → OPERATIONAL |
| Multiple failures | → MINIMAL | Stabilize → DEGRADED → OPERATIONAL |
| Critical failure | → SAFE | Investigate → MINIMAL → DEGRADED → OPERATIONAL |
| Safety violation | → EMERGENCY | Two-action confirmation required |

### Degradation Triggers

```
OPERATIONAL → DEGRADED:
  - Scan timeout > threshold
  - Target unreachable (network error)
  - Rate limited / blocked
  - error_rate > 0.05

DEGRADED → MINIMAL:
  - Multiple consecutive failures
  - Resource exhaustion
  - error_rate > 0.15

MINIMAL → SAFE:
  - Critical component failure
  - Legal/ethical boundary concern
  - recovery_attempts > max_attempts

ANY → EMERGENCY:
  - Safety invariant violated
  - Unintended target impact detected
  - Unauthorized scope expansion
```

### Recovery Protocol

Recovery requires **graduated steps** (no direct jump to OPERATIONAL):
```
SAFE → MINIMAL → DEGRADED → OPERATIONAL
```

---

## Workflows

### Security Assessment
```
recon → scan → test → report
```

### Pentest Pipeline
```
1. RECON       → intel_comprehensive, amass, subfinder
2. SCAN        → nuclei_scan, js_analyze
3. TEST        → llm_redteam_scan, waf_bypass_scan, oauth_scan
4. EXPLOIT     → pentest_run (safe_mode unless authorized)
5. REPORT      → Generate findings
```

---

## Quick Reference

```python
from modules.external_tools import ExternalTools

tools = ExternalTools()
tools.osint.spiderfoot_scan("example.com")
tools.web.test_xss("http://example.com/page?p=test")
tools.defense.scan_for_backdoors("/path/to/code")
tools.cloud.audit_aws()
tools.injection.test_sqli("http://example.com?id=1")
```

---

*BlackBox Security Platform - 175 Tools Integrated*
*Governed by: rules/rules.yaml & standards/DATA_STANDARDS.md*
