#!/usr/bin/env python3
"""
Integrity Check Tool
Verifies SOUL file integrity using SHA-256 hashes

Usage:
    ./integrity-check.py --create-baseline
    ./integrity-check.py --verify
    ./integrity-check.py --status
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
SOUL_DIR = FRAMEWORK_DIR / "soul"
BASELINE_FILE = SOUL_DIR / ".baseline.sha256"
INTEGRITY_LOG = FRAMEWORK_DIR / ".integrity-log.json"


def compute_hash(file_path):
    """Compute SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_soul_files():
    """Get all SOUL markdown files"""
    return sorted(SOUL_DIR.glob("*.md"))


def create_baseline():
    """Create baseline hashes for all SOUL files"""
    hashes = {}

    for file_path in get_soul_files():
        file_hash = compute_hash(file_path)
        hashes[file_path.name] = {
            "hash": file_hash,
            "size": file_path.stat().st_size,
            "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
        }
        print(f"[+] {file_path.name}: {file_hash[:16]}...")

    # Save baseline
    baseline = {
        "created": datetime.now().isoformat(),
        "files": hashes
    }
    BASELINE_FILE.write_text(json.dumps(baseline, indent=2))

    print(f"\n[+] Baseline saved to: {BASELINE_FILE}")
    print(f"[+] {len(hashes)} files hashed")

    return True


def verify_integrity():
    """Verify current files against baseline"""
    if not BASELINE_FILE.exists():
        print("[!] No baseline found. Run with --create-baseline first.")
        return False

    baseline = json.loads(BASELINE_FILE.read_text())
    baseline_files = baseline.get("files", {})

    results = {
        "verified": datetime.now().isoformat(),
        "status": "PASS",
        "files": {}
    }

    all_pass = True

    for file_path in get_soul_files():
        name = file_path.name
        current_hash = compute_hash(file_path)

        if name not in baseline_files:
            print(f"[!] NEW FILE: {name}")
            results["files"][name] = {"status": "NEW", "hash": current_hash}
            all_pass = False
            continue

        expected_hash = baseline_files[name]["hash"]

        if current_hash == expected_hash:
            print(f"[✓] {name}: VERIFIED")
            results["files"][name] = {"status": "VERIFIED", "hash": current_hash}
        else:
            print(f"[✗] {name}: TAMPERED!")
            print(f"    Expected: {expected_hash[:32]}...")
            print(f"    Found:    {current_hash[:32]}...")
            results["files"][name] = {
                "status": "TAMPERED",
                "expected": expected_hash,
                "actual": current_hash
            }
            all_pass = False

    # Check for missing files
    for name in baseline_files:
        if not (SOUL_DIR / name).exists():
            print(f"[!] MISSING: {name}")
            results["files"][name] = {"status": "MISSING"}
            all_pass = False

    # Update status
    if all_pass:
        results["status"] = "PASS"
        print(f"\n[+] Integrity check PASSED")
    else:
        results["status"] = "FAIL"
        print(f"\n[!] Integrity check FAILED")

    # Log results
    log_integrity_check(results)

    return all_pass


def log_integrity_check(results):
    """Log integrity check results"""
    log = []
    if INTEGRITY_LOG.exists():
        try:
            log = json.loads(INTEGRITY_LOG.read_text())
        except:
            log = []

    log.append(results)

    # Keep last 100 entries
    log = log[-100:]

    INTEGRITY_LOG.write_text(json.dumps(log, indent=2))


def show_status():
    """Show current integrity status"""
    print("\n" + "="*60)
    print("INTEGRITY STATUS")
    print("="*60)

    # Baseline info
    if BASELINE_FILE.exists():
        baseline = json.loads(BASELINE_FILE.read_text())
        print(f"\nBaseline created: {baseline.get('created', 'Unknown')}")
        print(f"Files tracked: {len(baseline.get('files', {}))}")
    else:
        print("\n[!] No baseline exists")

    # Current files
    print("\nSOUL Files:")
    for file_path in get_soul_files():
        size = file_path.stat().st_size
        print(f"  - {file_path.name} ({size} bytes)")

    # Last check
    if INTEGRITY_LOG.exists():
        try:
            log = json.loads(INTEGRITY_LOG.read_text())
            if log:
                last = log[-1]
                print(f"\nLast check: {last.get('verified', 'Unknown')}")
                print(f"Status: {last.get('status', 'Unknown')}")
        except:
            pass

    print("")


def recover_from_backup():
    """Attempt to recover from backup (placeholder)"""
    print("[!] Recovery not implemented")
    print("[!] Manual recovery required:")
    print("    1. Check git history: git log soul/")
    print("    2. Restore from backup: git checkout HEAD~1 -- soul/")
    return False


def main():
    parser = argparse.ArgumentParser(description="SOUL Integrity Checker")
    parser.add_argument("--create-baseline", "-c", action="store_true",
                       help="Create baseline hashes")
    parser.add_argument("--verify", "-v", action="store_true",
                       help="Verify against baseline")
    parser.add_argument("--status", "-s", action="store_true",
                       help="Show status")
    parser.add_argument("--recover", "-r", action="store_true",
                       help="Attempt recovery from backup")

    args = parser.parse_args()

    if args.create_baseline:
        create_baseline()
    elif args.verify:
        success = verify_integrity()
        sys.exit(0 if success else 1)
    elif args.recover:
        recover_from_backup()
    else:
        show_status()


if __name__ == "__main__":
    main()
