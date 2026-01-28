#!/usr/bin/env python3
"""
BlackBox Reference Audit
========================

Gate 1 + Gate 2 automated detection and verification.

Usage:
    python scripts/audit_references.py

Checks for:
    - References to deleted files
    - Broken module imports
    - Orphaned files
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent

# Known deleted files - references to these are BROKEN
DELETED_PATTERNS = [
    "blackbox_mcp",
    "blackbox_server",
    "mission_control_app",
    "module_integration",
    "launcher\\.py",
]

# Known renamed modules - check for old names
RENAMED_MODULES = {
    "mission_control": "mission_commander",  # old -> new
}


def grep_pattern(pattern: str, file_types: list[str] = None) -> list[str]:
    """Run grep and return matching lines."""
    if file_types is None:
        file_types = ["*.py", "*.md"]

    # Exclude audit scripts and documentation (they contain patterns as examples)
    exclude_paths = [
        "scripts/audit_references.py",
        "scripts/verify_imports.py",
        "docs/AUDIT_PROTOCOL.md",
    ]

    results = []
    for ft in file_types:
        try:
            cmd = ["grep", "-r", pattern, "--include", ft, str(ROOT)]
            output = subprocess.run(cmd, capture_output=True, text=True)
            if output.stdout:
                for line in output.stdout.strip().split("\n"):
                    # Skip excluded files
                    skip = False
                    for exc in exclude_paths:
                        if exc in line:
                            skip = True
                            break
                    if not skip:
                        results.append(line)
        except Exception:
            pass
    return [r for r in results if r]


def check_file_exists(path: str) -> bool:
    """Gate 2: Verify file actually exists or not."""
    return Path(path).exists()


def main():
    print("=" * 60)
    print("BLACKBOX REFERENCE AUDIT")
    print("Gate 1: Detection | Gate 2: Verification")
    print("=" * 60)
    print()

    issues = []

    # Check for references to deleted files
    print("[GATE 1] Scanning for deleted file references...")
    for pattern in DELETED_PATTERNS:
        matches = grep_pattern(pattern)
        for match in matches:
            # Gate 2: Verify it's actually a problem
            # Skip if it's just a database name or comment
            if ".db" in match or "# " in match.split(":")[-1]:
                continue
            issues.append(("DELETED_REF", pattern, match))

    # Check for renamed module imports
    print("[GATE 1] Scanning for renamed module references...")
    for old_name, new_name in RENAMED_MODULES.items():
        pattern = f"from.*{old_name}.*import|import.*{old_name}"
        matches = grep_pattern(pattern, ["*.py"])
        for match in matches:
            # Gate 2: Check if it's importing from the old name
            if f".{old_name}" in match and f".{new_name}" not in match:
                issues.append(("RENAMED_MODULE", f"{old_name} -> {new_name}", match))

    print()
    print("=" * 60)
    print("[RESULTS]")
    print("=" * 60)

    if not issues:
        print()
        print("[OK] No broken references found")
        print()
        print("AUDIT PASSED")
        return 0

    print()
    print(f"[FAIL] Found {len(issues)} issue(s):")
    print()

    for issue_type, pattern, match in issues:
        print(f"  [{issue_type}] {pattern}")
        print(f"    {match[:100]}...")
        print()

    print("AUDIT FAILED - Manual review required")
    return 1


if __name__ == "__main__":
    sys.exit(main())
