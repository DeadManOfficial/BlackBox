#!/usr/bin/env python3
"""
Rules Engine
Programmatic enforcement of DEBUG_RULES.md

Usage:
    ./rules-engine.py --check authorization
    ./rules-engine.py --validate finding.json
    ./rules-engine.py --status
"""

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
RULES_FILE = FRAMEWORK_DIR / "DEBUG_RULES.md"
STATE_FILE = FRAMEWORK_DIR / ".rules-state.json"
AUDIT_LOG = FRAMEWORK_DIR / ".rules-audit.json"


class RulesEngine:
    """IF-THEN rules engine from DEBUG_RULES.md"""

    def __init__(self):
        self.rules = self.parse_rules()
        self.state = self.load_state()

    def parse_rules(self):
        """Parse rules from DEBUG_RULES.md"""
        rules = {}

        if not RULES_FILE.exists():
            return rules

        content = RULES_FILE.read_text()

        # Extract rules using pattern matching
        rule_pattern = r'### RULE (\d+) — ([^\n]+)\n((?:IF|THEN|AND|ELSE|NOT)[^\n#]+(?:\n(?:IF|THEN|AND|ELSE|NOT|-)[^\n#]+)*)'
        matches = re.findall(rule_pattern, content, re.MULTILINE)

        for num, name, body in matches:
            rules[int(num)] = {
                "name": name.strip(),
                "body": body.strip(),
                "conditions": self.extract_conditions(body),
                "actions": self.extract_actions(body)
            }

        return rules

    def extract_conditions(self, body):
        """Extract IF conditions from rule body"""
        conditions = []
        for line in body.split('\n'):
            if line.strip().startswith('IF '):
                conditions.append(line.strip()[3:])
        return conditions

    def extract_actions(self, body):
        """Extract THEN actions from rule body"""
        actions = []
        for line in body.split('\n'):
            if line.strip().startswith('THEN '):
                actions.append(line.strip()[5:])
        return actions

    def load_state(self):
        """Load current rules state"""
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        return {
            "gates_passed": [],
            "gates_failed": [],
            "current_phase": 0,
            "last_check": None
        }

    def save_state(self):
        """Save current rules state"""
        self.state["last_check"] = datetime.now().isoformat()
        STATE_FILE.write_text(json.dumps(self.state, indent=2))

    def audit(self, rule_num, result, details=None):
        """Log rule evaluation to audit log"""
        log = []
        if AUDIT_LOG.exists():
            try:
                log = json.loads(AUDIT_LOG.read_text())
            except:
                log = []

        log.append({
            "timestamp": datetime.now().isoformat(),
            "rule": rule_num,
            "result": result,
            "details": details
        })

        # Keep last 1000 entries
        log = log[-1000:]
        AUDIT_LOG.write_text(json.dumps(log, indent=2))

    def check_rule(self, rule_num, context=None):
        """Check if a specific rule passes"""
        if rule_num not in self.rules:
            return {"passed": False, "error": f"Rule {rule_num} not found"}

        rule = self.rules[rule_num]
        result = {"passed": True, "rule": rule["name"], "checks": []}

        # Rule-specific checks
        if rule_num == 0:  # Authorization
            result = self.check_authorization(context)
        elif rule_num == 1:  # Failure Definition
            result = self.check_failure_definition(context)
        elif rule_num == 4:  # Golden State
            result = self.check_golden_state(context)
        elif rule_num == 6:  # Deterministic Repro
            result = self.check_deterministic_repro(context)
        elif rule_num == 8:  # Multiple Hypotheses
            result = self.check_multiple_hypotheses(context)
        else:
            result["checks"].append(f"Rule {rule_num} requires manual verification")

        # Audit the check
        self.audit(rule_num, "PASS" if result["passed"] else "FAIL", result.get("checks"))

        return result

    def check_authorization(self, context=None):
        """Rule 0: Check authorization is documented"""
        result = {"passed": True, "rule": "Authorization", "checks": []}

        # Check master authorization exists
        master_auth = FRAMEWORK_DIR / "MASTER-AUTHORIZATION.md"
        if not master_auth.exists():
            result["passed"] = False
            result["checks"].append("FAIL: MASTER-AUTHORIZATION.md missing")
        else:
            result["checks"].append("PASS: Master authorization exists")

        # Check project scope exists
        scope_files = list(FRAMEWORK_DIR.glob("projects/*/config/scope.yaml"))
        if scope_files:
            result["checks"].append(f"PASS: {len(scope_files)} project scope(s) found")
        else:
            result["checks"].append("WARN: No project scopes defined")

        return result

    def check_failure_definition(self, context=None):
        """Rule 1: Check failure is observable and measurable"""
        result = {"passed": True, "rule": "Failure Definition", "checks": []}

        if context and "finding" in context:
            finding = context["finding"]

            # Check for observable condition
            if "description" in finding or "summary" in finding:
                result["checks"].append("PASS: Failure description exists")
            else:
                result["passed"] = False
                result["checks"].append("FAIL: No failure description")

            # Check for success criteria
            if "impact" in finding or "expected" in finding:
                result["checks"].append("PASS: Success criteria implied")
            else:
                result["checks"].append("WARN: Explicit success criteria recommended")
        else:
            result["checks"].append("INFO: No finding context provided")

        return result

    def check_golden_state(self, context=None):
        """Rule 4: Check golden state is captured"""
        result = {"passed": True, "rule": "Golden State", "checks": []}

        required = ["inputs", "environment", "timestamp"]

        if context and "golden_state" in context:
            state = context["golden_state"]
            for req in required:
                if req in state:
                    result["checks"].append(f"PASS: {req} captured")
                else:
                    result["passed"] = False
                    result["checks"].append(f"FAIL: {req} missing")
        else:
            result["checks"].append("INFO: Capture golden state before debugging")

        return result

    def check_deterministic_repro(self, context=None):
        """Rule 6: Check deterministic reproduction exists"""
        result = {"passed": True, "rule": "Deterministic Repro", "checks": []}

        if context and "reproduction" in context:
            repro = context["reproduction"]

            if "steps" in repro and len(repro["steps"]) > 0:
                result["checks"].append(f"PASS: {len(repro['steps'])} reproduction steps")
            else:
                result["passed"] = False
                result["checks"].append("FAIL: No reproduction steps")

            if repro.get("reproducibility", 0) >= 100:
                result["checks"].append("PASS: 100% reproducible")
            else:
                result["passed"] = False
                result["checks"].append("FAIL: Not deterministically reproducible")
        else:
            result["checks"].append("INFO: Document reproduction steps")

        return result

    def check_multiple_hypotheses(self, context=None):
        """Rule 8: Check ≥3 hypotheses generated"""
        result = {"passed": True, "rule": "Multiple Hypotheses", "checks": []}

        if context and "hypotheses" in context:
            count = len(context["hypotheses"])
            if count >= 3:
                result["checks"].append(f"PASS: {count} hypotheses generated")
            else:
                result["passed"] = False
                result["checks"].append(f"FAIL: Only {count} hypotheses (need ≥3)")
        else:
            result["checks"].append("INFO: Generate ≥3 competing hypotheses")

        return result

    def validate_finding(self, finding_path):
        """Validate a finding against all applicable rules"""
        results = {"valid": True, "rules": []}

        try:
            with open(finding_path) as f:
                finding = json.load(f)
        except:
            return {"valid": False, "error": "Cannot parse finding file"}

        context = {"finding": finding}

        # Check applicable rules
        for rule_num in [0, 1, 6]:
            result = self.check_rule(rule_num, context)
            results["rules"].append(result)
            if not result["passed"]:
                results["valid"] = False

        return results

    def get_status(self):
        """Get current rules engine status"""
        return {
            "rules_loaded": len(self.rules),
            "state": self.state,
            "rules": {num: rule["name"] for num, rule in self.rules.items()}
        }


def main():
    parser = argparse.ArgumentParser(description="Rules Engine")
    parser.add_argument("--check", "-c", type=int, help="Check specific rule")
    parser.add_argument("--validate", "-v", help="Validate finding file")
    parser.add_argument("--status", "-s", action="store_true", help="Show status")
    parser.add_argument("--list", "-l", action="store_true", help="List all rules")

    args = parser.parse_args()
    engine = RulesEngine()

    if args.check is not None:
        result = engine.check_rule(args.check)
        print(f"\nRule {args.check}: {result['rule']}")
        print("-" * 40)
        for check in result["checks"]:
            print(f"  {check}")
        print(f"\nResult: {'PASS' if result['passed'] else 'FAIL'}")
        sys.exit(0 if result["passed"] else 1)

    elif args.validate:
        results = engine.validate_finding(args.validate)
        print(f"\nValidating: {args.validate}")
        print("=" * 40)
        for rule_result in results["rules"]:
            status = "✓" if rule_result["passed"] else "✗"
            print(f"\n[{status}] {rule_result['rule']}")
            for check in rule_result["checks"]:
                print(f"    {check}")
        print(f"\nOverall: {'VALID' if results['valid'] else 'INVALID'}")
        sys.exit(0 if results["valid"] else 1)

    elif args.list:
        print("\nDEBUG_RULES.md - Rule Index")
        print("=" * 40)
        for num, rule in sorted(engine.rules.items()):
            print(f"Rule {num}: {rule['name']}")

    else:
        status = engine.get_status()
        print(f"\nRules Engine Status")
        print("=" * 40)
        print(f"Rules loaded: {status['rules_loaded']}")
        print(f"Last check: {status['state'].get('last_check', 'Never')}")
        print(f"Gates passed: {len(status['state'].get('gates_passed', []))}")
        print(f"Gates failed: {len(status['state'].get('gates_failed', []))}")


if __name__ == "__main__":
    main()
