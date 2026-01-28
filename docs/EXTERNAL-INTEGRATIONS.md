# External Integrations
## Third-Party Tools & Resources

---

## 1. Claude Scientific Skills (K-Dense-AI)

**Source:** https://github.com/K-Dense-AI/claude-scientific-skills
**Purpose:** 140 scientific skills for research workflows

### Relevant Skills for Security Research

| Category | Application |
|----------|-------------|
| Bioinformatics | Malware DNA analysis |
| Cheminformatics | Cryptographic analysis |
| Data Analysis | Log analysis, pattern detection |
| Machine Learning | Anomaly detection |
| Visualization | Attack path mapping |

### Integration

**MCP Server:**
```json
{
  "mcpServers": {
    "claude-scientific-skills": {
      "url": "https://mcp.k-dense.ai/claude-scientific-skills/mcp"
    }
  }
}
```

### Security Research Applications

- **Pattern Analysis:** Use statistical tools for log analysis
- **Data Processing:** Process large vulnerability datasets
- **Visualization:** Generate attack surface graphs
- **ML Integration:** Train anomaly detection models

---

## 2. Claude Code Setup (centminmod)

**Source:** https://github.com/centminmod/my-claude-code-setup
**Purpose:** Memory bank system for persistent context

### Memory Bank Pattern

**File Structure:**
```
project/
├── CLAUDE.md                    # Main instructions
├── CLAUDE-activeContext.md      # Current session context
├── CLAUDE-patterns.md           # Learned patterns
├── CLAUDE-decisions.md          # Architectural decisions
└── CLAUDE-troubleshooting.md    # Solutions log
```

### Integration for Bounty Framework

**Adapted Structure:**
```
bounty-framework/
├── CLAUDE.md                    # Framework instructions
├── soul/
│   ├── CONTEXT.md              # Active research context
│   ├── PATTERNS.md             # Attack patterns learned
│   ├── DECISIONS.md            # Research decisions
│   └── FINDINGS.md             # Vulnerability log
└── projects/[target]/
    └── CLAUDE.md               # Target-specific context
```

### Key Features to Adopt

1. **Memory Bank Updates:** Auto-update context after each session
2. **Git Worktree Parallelization:** Run multiple research sessions
3. **Status Line Monitoring:** Track research metrics
4. **Safety Net Plugin:** Prevent destructive commands

### Git Worktree Setup

```bash
# Create isolated research sessions
git worktree add ../tiktok-session-2 -b research-session-2

# Run parallel Claude Code sessions
cx() {
    cd "$1" && claude
}

# Switch between sessions
clx tiktok-session-1
clx tiktok-session-2
```

---

## 3. DeadMan Toolkit Integration

**Already Available:** 116 security tools via MCP

### Security-Relevant Tools

| Tool | Purpose |
|------|---------|
| `nuclei_scan` | Vulnerability scanning |
| `js_analyze` | JavaScript secrets/endpoints |
| `ai_security_test` | AI endpoint testing |
| `llm_redteam_scan` | LLM red team |
| `pentest_run` | Autonomous pentest |
| `security_pipeline` | Full assessment |
| `intel_comprehensive` | Threat intelligence |

### Advanced Scanners
- `ssrf_scan` - SSRF detection
- `graphql_scan` - GraphQL vulnerabilities
- `jwt_analyze` - JWT weaknesses
- `oauth_scan` - OAuth flaws
- `idor_scan` - IDOR testing
- `race_condition_scan` - Race conditions

---

## 4. MCP Auditor Integration

**Available:** 35 audit tools

### Security Audit Tools

| Tool | Purpose |
|------|---------|
| `audit_code` | Code security analysis |
| `assess_owasp` | OWASP compliance |
| `assess_zero_trust` | Zero trust assessment |
| `get_mitre_techniques` | MITRE ATT&CK mapping |
| `comprehensive_audit` | Full security audit |
| `risk_assessment` | Risk scoring |

---

## Integration Priority

| Priority | Integration | Benefit |
|----------|-------------|---------|
| P0 | Memory Bank (centminmod) | Persistent research context |
| P0 | DeadMan Toolkit | Core security tools |
| P1 | Scientific Skills | Advanced analysis |
| P1 | MCP Auditor | Compliance checking |
| P2 | Git Worktrees | Parallel research |

---

## Setup Instructions

### 1. Memory Bank Setup

```bash
# Copy memory bank structure
mkdir -p soul
cat > CLAUDE.md << 'EOF'
# Bug Bounty Framework

## Memory Bank Files
- soul/CONTEXT.md - Active research context
- soul/PATTERNS.md - Attack patterns learned
- soul/DECISIONS.md - Research decisions
- soul/FINDINGS.md - Vulnerability log

## Instructions
- Update memory bank after each session
- Reference patterns before starting new research
- Log all architectural decisions
EOF
```

### 2. Scientific Skills MCP

```bash
# Add to .claude/settings.json
{
  "mcpServers": {
    "scientific": {
      "url": "https://mcp.k-dense.ai/claude-scientific-skills/mcp"
    }
  }
}
```

### 3. Git Worktree Functions

```bash
# Add to ~/.bashrc
cx() {
    local session_dir="$1"
    cd "$session_dir" && claude
}

new_research_session() {
    local target="$1"
    local session="$2"
    git worktree add "../${target}-${session}" -b "research-${target}-${session}"
    cx "../${target}-${session}"
}
```

---

*External Integrations - DeadMan Security Research*
