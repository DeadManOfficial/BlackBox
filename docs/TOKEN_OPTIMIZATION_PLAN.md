# Token Optimization Plan

**Issue**: "Exceeds maximum allowed tokens" errors during bounty operations
**Date**: 2026-01-27
**Status**: PLANNING

---

## Problem Analysis

### Root Causes Identified

1. **MCP Tool Bloat** - All 300+ MCP tool definitions loaded at startup
   - DeadMan toolkit alone has 116+ tools
   - Each tool definition consumes tokens before any work begins
   - Solution already exists: `ToolSearch` deferred loading

2. **Large Scrape Results** - Firecrawl returns full page content
   - Example: viewcreator.ai scrape returned 166KB
   - Entire response loaded into context

3. **Conversation History Accumulation** - Long bounty runs accumulate context
   - Multiple gate executions
   - Tool call results stack up
   - No automatic summarization between gates

4. **Verbose Tool Outputs** - Full JSON/HTML responses
   - GitHub file contents include metadata
   - Sitemap XML fully expanded

---

## Solutions

### TIER 1: Immediate (No Code Changes)

#### 1.1 Use ToolSearch for Deferred Loading
```
RULE: Never call MCP tools directly without first loading via ToolSearch
BEFORE: mcp__firecrawl__firecrawl_scrape(...)  ← FAILS, tool not loaded
AFTER:  ToolSearch("firecrawl scrape") → then call tool
```

**Impact**: 46.9% reduction in startup tokens (51K → 8.5K documented)

#### 1.2 Request Concise Outputs
```
RULE: Always specify output format constraints
- "Return only: [specific fields]"
- "Summarize in 100 words"
- "List top 5 only"
- "JSON with keys: url, status, finding"
```

#### 1.3 Gate-Based Context Resets
```
RULE: After completing a gate, summarize and checkpoint
- Write findings to file (already doing this)
- Start fresh context for next gate
- Reference files instead of inline data
```

### TIER 2: Configuration Changes

#### 2.1 Claude Code Settings
```bash
# Check current settings
claude config list

# Reduce tool definitions loaded
# Use ToolSearch for deferred tools (already configured)
```

#### 2.2 Firecrawl Optimizations
```python
# Use targeted scraping
mcp__firecrawl__firecrawl_scrape(
    url="...",
    formats=["markdown"],  # Not rawHtml
    onlyMainContent=True,  # Skip headers/footers
    excludeTags=["script", "style", "nav", "footer"]
)
```

#### 2.3 Response Truncation
```yaml
# In bounty rulebook - add output limits
scrape_rules:
  max_response_chars: 10000
  summarize_if_larger: true
  extract_only: ["title", "forms", "links", "meta"]
```

### TIER 3: BlackBox Module Enhancement

#### 3.1 Enhance Existing Token Optimizer

The existing modules at `/home/deadman/BlackBox/modules/scraper/ai/token_optimizer/` provide:
- `PromptOptimizer` - Compress prompts (20-30% reduction)
- `ContextManager` - Manage conversation history
- `RequestConsolidator` - Batch requests (50-70% savings)
- `ResponseCache` - Cache responses
- `OutputController` - Enforce concise output

**Enhancement needed**: Integration with Claude Code workflows

#### 3.2 Create Response Truncator
```python
# New module: response_truncator.py
class ResponseTruncator:
    """Truncate large tool responses before context injection"""

    MAX_CHARS = 10000

    @staticmethod
    def truncate(response: str, max_chars: int = MAX_CHARS) -> str:
        if len(response) <= max_chars:
            return response

        # Keep first and last portions (avoid "lost in middle")
        head = response[:max_chars // 2]
        tail = response[-(max_chars // 2):]

        return f"{head}\n\n[...{len(response) - max_chars} chars truncated...]\n\n{tail}"

    @staticmethod
    def summarize_json(data: dict, max_items: int = 10) -> dict:
        """Reduce JSON arrays to top N items"""
        if isinstance(data, list):
            return data[:max_items]
        if isinstance(data, dict):
            return {k: ResponseTruncator.summarize_json(v, max_items)
                    for k, v in data.items()}
        return data
```

#### 3.3 Create Gate Context Manager
```python
# New module: gate_context.py
class GateContext:
    """Manages context between bounty gates"""

    def __init__(self, target: str):
        self.target = target
        self.base_path = f"~/BlackBox/targets/{target}"

    def checkpoint(self, gate: str, findings: dict):
        """Save gate results and return summary for next gate"""
        # Write full findings to file
        self.save_findings(gate, findings)

        # Return compact summary for context
        return self.create_summary(gate, findings)

    def create_summary(self, gate: str, findings: dict) -> str:
        """Create token-efficient summary"""
        return f"""
## {gate} Complete
- Findings: {len(findings.get('findings', []))}
- URLs mapped: {findings.get('urls_mapped', 0)}
- Next: {findings.get('next_steps', ['Continue'])[0]}
- Full data: {self.base_path}/intel/findings.json
"""
```

### TIER 4: Workflow Changes

#### 4.1 Bounty Rulebook Updates

Add to `hackerone_bounty.md`:

```markdown
## TOKEN MANAGEMENT RULES

### Before Each Gate
- [ ] Check context usage (mental estimate)
- [ ] If heavy, checkpoint current findings
- [ ] Start fresh if > 50% context used

### Tool Usage
- [ ] Use ToolSearch before calling MCP tools
- [ ] Request minimal output formats
- [ ] Write large results to files, reference paths

### Response Handling
- [ ] Truncate responses > 10KB
- [ ] Extract only needed fields from JSON
- [ ] Summarize HTML to key elements
```

#### 4.2 Chunked Processing Pattern
```
For large targets:
1. Map all URLs → save to file
2. Process in batches of 10
3. Checkpoint after each batch
4. Aggregate findings at end
```

---

## Implementation Priority

| Priority | Task | Impact | Effort |
|----------|------|--------|--------|
| **P0** | Use ToolSearch consistently | 47% reduction | Low |
| **P0** | Add output limits to scrape calls | 30% reduction | Low |
| **P1** | Gate checkpointing in bounty runs | 40% reduction | Medium |
| **P1** | Response truncation module | 25% reduction | Medium |
| **P2** | Integrate TokenOptimizer with workflows | 20% reduction | High |
| **P2** | Chunked processing for large targets | 35% reduction | High |

---

## Immediate Actions

### 1. Update Bounty Rulebook
Add token management section with IF/THEN rules

### 2. Create Response Handler
Simple truncation utility for large responses

### 3. Implement Gate Checkpointing
Save to file + return summary pattern

### 4. Test on Next Target
Apply rules to next bounty run, measure improvement

---

## Metrics to Track

```yaml
token_metrics:
  startup_tokens: "Measure before first tool call"
  per_gate_tokens: "Estimate per gate completion"
  large_response_count: "Track responses > 10KB"
  checkpoint_frequency: "Gates between resets"
```

---

## Sources

- [Claude Code Cut MCP Bloat by 46.9%](https://medium.com/@joe.njenga/claude-code-just-cut-mcp-context-bloat-by-46-9-51k-tokens-down-to-8-5k-with-new-tool-search-ddf9e905f734)
- [Claude Context Window Practical Guide](https://www.eesel.ai/blog/claude-code-context-window-size)
- [Fixing Maximum Length Errors](https://limitededitionjonathan.substack.com/p/ultimate-guide-fixing-claude-hit)
- [Claude Context Windows - Official Docs](https://platform.claude.com/docs/en/build-with-claude/context-windows)

---

*BlackBox Token Optimization Plan v1.0*
