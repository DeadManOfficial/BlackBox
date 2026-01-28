#!/usr/bin/env python3
"""
BlackBox Import Verification Test
==================================

Double Gate Final Verification - Tests all critical imports.

Usage:
    python scripts/verify_imports.py

Exit Codes:
    0 - All imports verified
    1 - Import failures detected
"""

import sys
from pathlib import Path

# Add BlackBox root to path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Critical imports that MUST work
CRITICAL_IMPORTS = [
    # Core entry points
    ("blackbox", None),
    ("cli.main", "app"),

    # Workflows
    ("workflows.pipeline", "PipelineOrchestrator"),
    ("workflows.pipeline", "PipelinePhase"),

    # Command modules
    ("modules.command", "MissionCommander"),
    ("modules.command.intel_cli", "cli"),
    ("modules.command.mission_commander", "MissionCommander"),

    # Pentest modules
    ("modules.pentest.mcp_bridge", "MCPToolBridge"),
    ("modules.pentest.mcp_bridge", "SyncMCPToolBridge"),
    ("modules.pentest.bounty", "BountyTracker"),
    ("modules.pentest.bounty", "BountyTarget"),
]

# Optional imports (warn but don't fail)
OPTIONAL_IMPORTS = [
    ("modules.h1_bridge", "H1Bridge"),
    ("modules.scraper.ai.token_optimizer", "TokenOptimizer"),
]


def verify_import(module: str, attr: str = None) -> tuple[bool, str]:
    """Verify a single import. Returns (success, message)."""
    try:
        m = __import__(module, fromlist=[attr] if attr else [])
        if attr and not hasattr(m, attr):
            return False, f"{module}.{attr}: attribute not found"
        name = f"{module}.{attr}" if attr else module
        return True, f"[OK] {name}"
    except Exception as e:
        return False, f"{module}: {e}"


def main():
    print("=" * 60)
    print("BLACKBOX IMPORT VERIFICATION")
    print("Double Gate Final Test")
    print("=" * 60)
    print()

    errors = []
    warnings = []

    # Test critical imports
    print("[CRITICAL IMPORTS]")
    for module, attr in CRITICAL_IMPORTS:
        success, msg = verify_import(module, attr)
        if success:
            print(f"  {msg}")
        else:
            errors.append(msg)
            print(f"  [FAIL] {msg}")

    print()

    # Test optional imports
    print("[OPTIONAL IMPORTS]")
    for module, attr in OPTIONAL_IMPORTS:
        success, msg = verify_import(module, attr)
        if success:
            print(f"  {msg}")
        else:
            warnings.append(msg)
            print(f"  [WARN] {msg}")

    print()
    print("=" * 60)

    # Summary
    if errors:
        print(f"[FAIL] {len(errors)} critical import(s) failed")
        for e in errors:
            print(f"  - {e}")
        print()
        print("VERIFICATION FAILED")
        return 1

    if warnings:
        print(f"[WARN] {len(warnings)} optional import(s) missing")

    print("[OK] All critical imports verified")
    print()
    print("VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
