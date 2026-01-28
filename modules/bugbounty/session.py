#!/usr/bin/env python3
"""
Session Hooks
Pre/post execution hooks for session management

Usage:
    Called automatically by Claude Code hooks system
    Or manually: python hooks/session.py --on-start
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
SOUL_DIR = FRAMEWORK_DIR / "soul"
HOOKS_LOG = FRAMEWORK_DIR / ".hooks-log.json"

sys.path.insert(0, str(FRAMEWORK_DIR / "tools"))
from pathlib import Path


def log_hook(hook_name, status, details=None):
    """Log hook execution"""
    log = []
    if HOOKS_LOG.exists():
        try:
            log = json.loads(HOOKS_LOG.read_text())
        except:
            log = []

    log.append({
        "timestamp": datetime.now().isoformat(),
        "hook": hook_name,
        "status": status,
        "details": details
    })

    # Keep last 500 entries
    log = log[-500:]
    HOOKS_LOG.write_text(json.dumps(log, indent=2))


def on_session_start():
    """Called when a new session starts"""
    print("[HOOK] on_session_start triggered")

    # 1. Verify SOUL integrity
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, str(FRAMEWORK_DIR / "tools" / "integrity-check.py"), "--verify"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print("[!] INTEGRITY CHECK FAILED")
            log_hook("on_session_start", "FAILED", "Integrity check failed")
            return False
    except Exception as e:
        print(f"[!] Integrity check error: {e}")

    # 2. Load context
    context_file = SOUL_DIR / "CONTEXT.md"
    if context_file.exists():
        print(f"[+] Context loaded from: {context_file}")

    # 3. Log start
    log_hook("on_session_start", "SUCCESS", "Session initialized")
    print("[+] Session started successfully")
    return True


def on_tool_call(tool_name, params=None):
    """Called before any tool execution"""
    print(f"[HOOK] on_tool_call: {tool_name}")

    # Authorization check for security tools
    security_tools = ["nuclei_scan", "ssrf_scan", "jwt_analyze", "pentest_run",
                      "command_injection_scan", "ssti_scan", "idor_scan"]

    if tool_name in security_tools:
        # Verify scope exists for current project
        scope_files = list(FRAMEWORK_DIR.glob("projects/*/config/scope.yaml"))
        if not scope_files:
            print(f"[!] WARNING: No scope.yaml found - verify authorization")
            log_hook("on_tool_call", "WARNING", {"tool": tool_name, "reason": "no_scope"})
        else:
            print(f"[+] Security tool authorized: {tool_name}")

    # Track tool usage
    log_hook("on_tool_call", "ALLOWED", {"tool": tool_name, "params": str(params)[:100] if params else None})
    return True


def on_output(output, output_type="text"):
    """Called before returning output to user"""
    print(f"[HOOK] on_output: {output_type}")

    # Sanitize sensitive data patterns
    sensitive_patterns = [
        (r'AKIA[0-9A-Z]{16}', '[AWS_KEY_REDACTED]'),
        (r'(?i)password["\']?\s*[:=]\s*["\'][^"\']+["\']', 'password=[REDACTED]'),
        (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', '[JWT_REDACTED]'),
    ]

    sanitized = str(output)
    import re
    for pattern, replacement in sensitive_patterns:
        sanitized = re.sub(pattern, replacement, sanitized)

    log_hook("on_output", "PROCESSED", {"type": output_type, "length": len(str(output))})
    return sanitized


def on_error(error, context=None):
    """Called when an error occurs"""
    print(f"[HOOK] on_error: {error}")

    error_info = {
        "error": str(error),
        "type": type(error).__name__ if hasattr(error, '__class__') else "unknown",
        "context": context
    }

    log_hook("on_error", "ERROR", error_info)

    # Categorize error severity
    critical_patterns = ["permission denied", "authentication", "rate limit"]
    for pattern in critical_patterns:
        if pattern in str(error).lower():
            print(f"[!] CRITICAL ERROR: {pattern} detected")
            return False  # Signal to stop

    return True  # Continue despite error


def on_session_end():
    """Called when session ends"""
    print("[HOOK] on_session_end triggered")

    # 1. Update CONTEXT.md
    context_file = SOUL_DIR / "CONTEXT.md"
    if context_file.exists():
        content = context_file.read_text()
        # Update last modified
        now = datetime.now().strftime("%Y-%m-%d")
        if "**Last Updated:**" in content:
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if line.startswith("**Last Updated:**"):
                    lines[i] = f"**Last Updated:** {now}"
                    break
            content = "\n".join(lines)
            context_file.write_text(content)
            print(f"[+] Context updated: {now}")

    # 2. Log end
    log_hook("on_session_end", "SUCCESS", "Session ended cleanly")
    print("[+] Session ended successfully")
    return True


def main():
    parser = argparse.ArgumentParser(description="Session Hooks")
    parser.add_argument("--on-start", action="store_true", help="Trigger session start")
    parser.add_argument("--on-end", action="store_true", help="Trigger session end")
    parser.add_argument("--on-tool", help="Trigger tool call hook")
    parser.add_argument("--on-error", help="Trigger error hook")
    parser.add_argument("--status", action="store_true", help="Show hook log")

    args = parser.parse_args()

    if args.on_start:
        on_session_start()
    elif args.on_end:
        on_session_end()
    elif args.on_tool:
        on_tool_call(args.on_tool)
    elif args.on_error:
        on_error(args.on_error)
    elif args.status:
        if HOOKS_LOG.exists():
            log = json.loads(HOOKS_LOG.read_text())
            print(f"Hook log entries: {len(log)}")
            for entry in log[-10:]:
                print(f"  {entry['timestamp']}: {entry['hook']} - {entry['status']}")
        else:
            print("No hook log found")
    else:
        print("Usage: session.py --on-start | --on-end | --on-tool TOOL | --status")


if __name__ == "__main__":
    main()
