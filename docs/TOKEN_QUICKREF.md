# Token Optimization Quick Reference

```
╔══════════════════════════════════════════════════════════════════════╗
║                     TOKEN AXIOMS (T0-T4)                             ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  T0: ToolSearch BEFORE MCP calls                                     ║
║      ToolSearch("firecrawl scrape") → then call tool                 ║
║                                                                      ║
║  T1: Truncate responses > 10KB                                       ║
║      Head (60%) + Tail (40%) = preserve context, drop middle         ║
║                                                                      ║
║  T2: Checkpoint after each gate                                      ║
║      Write: ~/BlackBox/targets/{target}/checkpoints/{gate}.json      ║
║      Return: summary (3-5 lines) + path reference                    ║
║                                                                      ║
║  T3: Files for data, context for summary                             ║
║      WRONG: return full_data                                         ║
║      RIGHT: save(data) → return f"Saved to {path}: {summary}"        ║
║                                                                      ║
║  T4: Batch operations in chunks of 10                                ║
║      for batch in chunks(urls, 10): process(batch)                   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

## Tool Loading (T0)

```python
# CORRECT
ToolSearch("firecrawl scrape")    # 1. Load
mcp__firecrawl__firecrawl_scrape(url="...")  # 2. Call

# WRONG - bloats context or fails
mcp__firecrawl__firecrawl_scrape(url="...")  # Direct call
```

## Scraping Parameters (T1)

```python
mcp__firecrawl__firecrawl_scrape(
    url="https://example.com",
    formats=["markdown"],          # NOT rawHtml
    onlyMainContent=True,          # Skip chrome
    excludeTags=["script", "style", "nav", "footer"]
)
```

## Checkpoint Pattern (T2)

```python
from modules.utils import checkpoint, get_summary

# After completing gate
summary = checkpoint("viewcreator.ai", "GATE_1", {
    "findings": findings,
    "urls_mapped": 120
})
# Returns: "GATE_1 COMPLETE\n- Findings: 5\n- Path: ..."

# Loading in next gate
prev = get_summary("viewcreator.ai", "GATE_1")
```

## File vs Context (T3)

```python
from modules.utils import truncate, summarize

# Large response handling
if len(response) > 10000:
    # Save full data
    path = save_to_file(response, "scraped_data.json")
    # Return summary for context
    return f"Saved to {path}\nSummary: {summarize(response)}"
```

## Batch Processing (T4)

```python
from modules.utils import BatchProcessor

processor = BatchProcessor("viewcreator.ai", batch_size=10)

for batch in processor.process(all_urls):
    results = scrape_batch(batch)
    processor.save_batch_results(results)

final = processor.get_all_results()
```

## Context Reset Triggers

- After completing a gate
- After processing 50+ items
- When `should_checkpoint()` returns True
- Before starting unrelated task

## Expected Savings

| Technique | Reduction |
|-----------|-----------|
| ToolSearch (T0) | 46% |
| Response truncation (T1) | 30% |
| Checkpointing (T2) | 40% |
| File storage (T3) | 50% |
| Batching (T4) | 35% |
| **Combined** | **60-70%** |

## Module Locations

```
~/BlackBox/modules/utils/
├── __init__.py           # All exports
├── response_handler.py   # truncate, compact, summarize
├── gate_checkpoint.py    # checkpoint, load, get_summary
└── token_rules.py        # TokenRules, BatchProcessor

~/.claude/
├── CLAUDE.md             # Token axioms T0-T4
└── TOKEN_OPTIMIZATION_UNIFIED.md  # Full documentation

~/Downloads/hackerone_bounty.md    # Bounty rulebook with token rules
```

---
*BlackBox Token Optimization v1.0*
