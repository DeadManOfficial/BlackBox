#!/usr/bin/env python3
"""
Pre-commit Checks
Custom validation hooks for bug bounty framework

Usage:
    Called by pre-commit hooks
    Or manually: python pre-commit-checks.py --authorization
"""

import argparse
import re
import sys
from pathlib import Path

FRAMEWORK_DIR = Path(__file__).parent.parent
PROJECTS_DIR = FRAMEWORK_DIR / "projects"


def check_authorization():
    """Verify all projects have valid authorization"""
    errors = []

    for project_dir in PROJECTS_DIR.iterdir():
        if not project_dir.is_dir():
            continue

        # Check scope.yaml exists
        scope_file = project_dir / "config" / "scope.yaml"
        if not scope_file.exists():
            errors.append(f"{project_dir.name}: Missing config/scope.yaml")
            continue

        # Check scope.yaml has required fields
        content = scope_file.read_text()
        required = ["in_scope:", "authorization:", "target:"]
        for req in required:
            if req not in content:
                errors.append(f"{project_dir.name}: scope.yaml missing '{req}'")

    if errors:
        print("[!] Authorization check FAILED:")
        for error in errors:
            print(f"    - {error}")
        return False

    print("[+] Authorization check PASSED")
    return True


def check_evidence(files):
    """Verify findings have associated evidence"""
    errors = []

    for file_path in files:
        path = Path(file_path)
        if not path.exists():
            continue

        if "findings" in str(path) or "FINDINGS" in path.name:
            content = path.read_text()

            # Check for evidence markers
            if "## Evidence" not in content and "### Evidence" not in content:
                # Check for inline evidence
                if not re.search(r'```(http|curl|request|response)', content, re.I):
                    errors.append(f"{path.name}: No evidence section found")

    if errors:
        print("[!] Evidence check FAILED:")
        for error in errors:
            print(f"    - {error}")
        return False

    print("[+] Evidence check PASSED")
    return True


def check_no_secrets(files):
    """Check for potential secrets in files"""
    secret_patterns = [
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\'"][^\'"]+[\'"]', "AWS Secret Key"),
        (r'(?i)api[_-]?key\s*[:=]\s*[\'"][a-zA-Z0-9]{20,}[\'"]', "API Key"),
        (r'(?i)password\s*[:=]\s*[\'"][^\'"]+[\'"]', "Password"),
        (r'(?i)secret\s*[:=]\s*[\'"][^\'"]+[\'"]', "Secret"),
        (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', "JWT Token"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub PAT"),
        (r'sk-[a-zA-Z0-9]{48}', "OpenAI Key"),
    ]

    errors = []

    for file_path in files:
        path = Path(file_path)
        if not path.exists():
            continue

        # Skip certain directories
        skip_dirs = [".git", "node_modules", "__pycache__", "evidence"]
        if any(skip in str(path) for skip in skip_dirs):
            continue

        try:
            content = path.read_text()
        except:
            continue

        for pattern, name in secret_patterns:
            if re.search(pattern, content):
                # Allow in evidence directories
                if "evidence" in str(path).lower():
                    continue
                # Allow in documentation with [REDACTED]
                if "[REDACTED]" in content or "XXXX" in content:
                    continue

                errors.append(f"{path.name}: Potential {name} found")

    if errors:
        print("[!] Secrets check FAILED:")
        for error in errors:
            print(f"    - {error}")
        print("\nTip: Use [REDACTED] or remove secrets before committing")
        return False

    print("[+] Secrets check PASSED")
    return True


def check_documentation():
    """Verify documentation is complete"""
    required_docs = [
        "README.md",
        "MASTER-AUTHORIZATION.md",
        "METHODOLOGY.md",
        "DEBUG_RULES.md",
    ]

    errors = []

    for doc in required_docs:
        doc_path = FRAMEWORK_DIR / doc
        if not doc_path.exists():
            errors.append(f"Missing: {doc}")
            continue

        # Check not empty
        if doc_path.stat().st_size < 100:
            errors.append(f"Too small: {doc} ({doc_path.stat().st_size} bytes)")

    if errors:
        print("[!] Documentation check FAILED:")
        for error in errors:
            print(f"    - {error}")
        return False

    print("[+] Documentation check PASSED")
    return True


def main():
    parser = argparse.ArgumentParser(description="Pre-commit Checks")
    parser.add_argument("--authorization", action="store_true", help="Check authorization")
    parser.add_argument("--evidence", action="store_true", help="Check evidence")
    parser.add_argument("--no-secrets", action="store_true", help="Check for secrets")
    parser.add_argument("--documentation", action="store_true", help="Check documentation")
    parser.add_argument("--all", action="store_true", help="Run all checks")
    parser.add_argument("files", nargs="*", help="Files to check")

    args = parser.parse_args()

    all_pass = True

    if args.authorization or args.all:
        if not check_authorization():
            all_pass = False

    if args.evidence or args.all:
        if not check_evidence(args.files or []):
            all_pass = False

    if args.no_secrets or args.all:
        if not check_no_secrets(args.files or list(FRAMEWORK_DIR.rglob("*"))):
            all_pass = False

    if args.documentation or args.all:
        if not check_documentation():
            all_pass = False

    sys.exit(0 if all_pass else 1)


if __name__ == "__main__":
    main()
