# Audit Protocol v1.0

**Double Gate Verification with Final Test**

```
GATE_1 (DETECT) → GATE_2 (VERIFY) → FINAL (TEST)
```

---

## Philosophy

```
TRUST NOTHING. VERIFY EVERYTHING. TEST TO CONFIRM.
```

No ruling without double verification. No fix without test confirmation.

---

## Gate 1: Detection

**Purpose:** Find potential issues via pattern search.

```bash
# Broken imports
grep -r "from.*deleted_module" --include="*.py"

# Dead references
grep -r "deleted_file\.py" --include="*.md"

# Orphaned dependencies
grep -r "import.*removed_package"
```

**Output:** List of POTENTIAL issues (not confirmed yet).

---

## Gate 2: Verification

**Purpose:** Confirm each potential issue is actually broken.

| Check Type | Method |
|------------|--------|
| File exists? | `ls -la <path>` |
| Module exists? | Check `__init__.py` exports |
| Class exists? | `grep "^class "` |
| Function exists? | `grep "^def "` |
| Is it imported? | `grep -r "from.*import\|import.*"` |

**Output:** CONFIRMED broken references only.

**Double Gate Rule:**
```
Detection alone ≠ Ruling
Detection + Verification = Ruling
```

---

## Final Verification: Test

**Purpose:** Confirm fixes work via actual execution.

```python
#!/usr/bin/env python3
"""BlackBox Import Verification Test"""

import sys
sys.path.insert(0, '.')

CRITICAL_IMPORTS = [
    ("blackbox", None),
    ("workflows.pipeline", "PipelineOrchestrator"),
    ("modules.command", "MissionCommander"),
    ("modules.pentest.mcp_bridge", "MCPToolBridge"),
    ("modules.pentest.bounty", "BountyTracker"),
    ("modules.command.intel_cli", "cli"),
    ("cli.main", "app"),
]

def verify_imports():
    errors = []
    for module, attr in CRITICAL_IMPORTS:
        try:
            m = __import__(module, fromlist=[attr] if attr else [])
            if attr and not hasattr(m, attr):
                errors.append(f"{module}.{attr}: attribute not found")
            else:
                name = f"{module}.{attr}" if attr else module
                print(f"[OK] {name}")
        except Exception as e:
            errors.append(f"{module}: {e}")

    if errors:
        print("\nERRORS:")
        for e in errors:
            print(f"  [FAIL] {e}")
        return False

    print("\nALL IMPORTS VERIFIED")
    return True

if __name__ == "__main__":
    sys.exit(0 if verify_imports() else 1)
```

---

## Audit Checklist

### Before Making Changes

- [ ] Gate 1: Pattern search for issues
- [ ] Gate 2: Verify each finding individually
- [ ] Document findings in table format

### After Making Changes

- [ ] Run import verification test
- [ ] Grep for any remaining references
- [ ] Confirm zero broken references

---

## Audit Table Format

| File | Issue | Gate 1 | Gate 2 | Verdict |
|------|-------|--------|--------|---------|
| path/file.py | Description | Evidence | Confirmation | DELETE/FIX/OK |

---

## Common Patterns

### Deleted File References

```bash
# Files that were deleted
DELETED="blackbox_mcp|blackbox_server|mission_control_app|module_integration|launcher"

# Find references
grep -rE "$DELETED" --include="*.py" --include="*.md"
```

### Import Verification

```bash
# Check if module path matches import
# import: from .mission_control import X
# actual: modules/command/mission_commander.py
# verdict: BROKEN (control ≠ commander)
```

### Orphan Detection

```bash
# File exists but nothing imports it
grep -r "from.*suspect_module" --include="*.py"
# Returns: nothing
# Verdict: ORPHANED - safe to delete
```

---

## Integration

This protocol is referenced by:
- `docs/BOUNTY_RULEBOOK.md` - Gate verification
- `workflows/pipeline.py` - Checkpoint validation
- `modules/pentest/bounty.py` - Finding verification

---

*Audit Protocol v1.0 - Double Gate Verification*
*TRUST NOTHING. VERIFY EVERYTHING. TEST TO CONFIRM.*
