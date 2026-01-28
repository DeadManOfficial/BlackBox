#!/usr/bin/env python3
"""
BlackBox Methodology Module
============================

DEBUG_RULES.md as a programmatic rules engine.
DEADMAN Debugging Methodology.

9 Phases, 22 Rules, Absolute Stop Conditions.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

# Try to import base module
try:
    from modules.base import BaseModule, ModuleCategory
    HAS_BASE = True
except ImportError:
    HAS_BASE = False
    class BaseModule:
        def __init__(self, config=None): self.config = config or {}
        def on_load(self): return True
        def on_unload(self): pass
        def register_tools(self, mcp, client): return []
        def register_routes(self, app): return []
    class ModuleCategory:
        METHODOLOGY = "methodology"


class Phase(Enum):
    """9 Debugging Phases"""
    P1_DETECTION = "failure_detection"
    P2_STATE = "state_freeze"
    P3_REPRO = "reproduction"
    P4_HYPOTHESIS = "hypothesis"
    P5_VALIDATION = "validation"
    P6_FIX = "fix_design"
    P7_DEPLOY = "deployment"
    P8_REVIEW = "independent_review"
    P9_CLOSURE = "closure"


class RuleStatus(Enum):
    """Rule evaluation status"""
    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"  # STOP condition
    PENDING = "pending"
    SKIPPED = "skipped"


@dataclass
class RuleResult:
    """Result of a rule evaluation"""
    rule_id: str
    rule_name: str
    phase: str
    status: RuleStatus
    message: str
    evidence: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        d = asdict(self)
        d['status'] = self.status.value
        return d


@dataclass
class DebugSession:
    """Active debugging session state"""
    session_id: str
    target: str
    current_phase: Phase
    started: str
    authorization: Optional[Dict] = None
    golden_state: Optional[Dict] = None
    hypotheses: List[str] = field(default_factory=list)
    rule_results: List[RuleResult] = field(default_factory=list)
    stop_reason: Optional[str] = None

    def to_dict(self):
        d = asdict(self)
        d['current_phase'] = self.current_phase.value
        d['rule_results'] = [r.to_dict() for r in self.rule_results]
        return d


class RulesEngine:
    """
    The non-negotiable IF-THEN rules engine.

    Global Invariants:
    - Evidence > opinion
    - Reproducibility > speed
    - System > symptom
    - Spec > implementation
    - Correctness > performance
    - Minimal change > broad change
    - Lowest Responsible Layer > masking
    - Documentation is part of the fix
    """

    INVARIANTS = [
        "Evidence > opinion",
        "Reproducibility > speed",
        "System > symptom",
        "Spec > implementation",
        "Correctness > performance",
        "Minimal change > broad change",
        "Lowest Responsible Layer > masking",
        "Documentation is part of the fix",
    ]

    STOP_CONDITIONS = [
        "reproduction is lost",
        "evidence contradicts hypothesis",
        "telemetry is missing",
        "spec interpretation unclear",
        "fix hides a lower-layer defect",
        "rollback is impossible",
    ]

    FAILURE_TYPES = ["crash", "incorrect_output", "performance_regression", "hang_deadlock"]

    LAYERS = ["hardware", "firmware", "driver", "runtime", "framework", "application"]

    def __init__(self):
        self.sessions: Dict[str, DebugSession] = {}
        self.rules = self._define_rules()

    def _define_rules(self) -> Dict[str, Dict]:
        """Define all 22 rules"""
        return {
            # Phase 1: Failure Detection
            "R0": {
                "name": "Authorization",
                "phase": Phase.P1_DETECTION,
                "check": "scope, authorization, and asset ownership documented",
                "stop_on_fail": True,
            },
            "R1": {
                "name": "Failure Definition",
                "phase": Phase.P1_DETECTION,
                "check": "failure defined as observable, measurable condition with success criteria",
                "stop_on_fail": True,
            },
            "R2": {
                "name": "System Boundary",
                "phase": Phase.P1_DETECTION,
                "check": "system boundaries defined (inputs -> transforms -> outputs) with dependencies",
                "stop_on_fail": True,
            },
            "R3": {
                "name": "Failure Type",
                "phase": Phase.P1_DETECTION,
                "check": f"classified as exactly ONE type: {', '.join(self.FAILURE_TYPES)}",
                "stop_on_fail": True,
            },

            # Phase 2: State Freeze
            "R4": {
                "name": "Golden State",
                "phase": Phase.P2_STATE,
                "check": "captured inputs, configs, versions, environment, timestamp",
                "stop_on_fail": True,
            },
            "R5": {
                "name": "Telemetry Validation",
                "phase": Phase.P2_STATE,
                "check": "timestamps aligned, >=2 independent signals per symptom",
                "stop_on_fail": False,
            },

            # Phase 3: Reproduction
            "R6": {
                "name": "Deterministic Repro",
                "phase": Phase.P3_REPRO,
                "check": "deterministic reproduction exists",
                "stop_on_fail": True,
            },
            "R7": {
                "name": "Minimal Failing Unit",
                "phase": Phase.P3_REPRO,
                "check": "reduced to smallest failing unit (function, kernel, state)",
                "stop_on_fail": False,
            },

            # Phase 4: Hypothesis
            "R8": {
                "name": "Multiple Hypotheses",
                "phase": Phase.P4_HYPOTHESIS,
                "check": ">=3 competing hypotheses generated",
                "stop_on_fail": True,
            },
            "R9": {
                "name": "Falsification Only",
                "phase": Phase.P4_HYPOTHESIS,
                "check": "tests designed to falsify hypotheses, not confirm",
                "stop_on_fail": False,
            },
            "R10": {
                "name": "Layer Isolation",
                "phase": Phase.P4_HYPOTHESIS,
                "check": f"isolated to layer: {', '.join(self.LAYERS)}",
                "stop_on_fail": True,
            },
            "R11": {
                "name": "Memory First",
                "phase": Phase.P4_HYPOTHESIS,
                "check": "if nondeterministic, assume memory/coherency bug until proven otherwise",
                "stop_on_fail": False,
            },
            "R12": {
                "name": "Spec Check",
                "phase": Phase.P4_HYPOTHESIS,
                "check": "if behavior contradicts spec, code is wrong (not hardware/runtime)",
                "stop_on_fail": True,
            },

            # Phase 5: Validation
            "R13": {
                "name": "Golden Reference",
                "phase": Phase.P5_VALIDATION,
                "check": "outputs compared against golden reference (CPU ref, known-good, spec)",
                "stop_on_fail": True,
            },
            "R14": {
                "name": "Fleet Patterns",
                "phase": Phase.P5_VALIDATION,
                "check": "if multiple instances affected, patterns analyzed across population",
                "stop_on_fail": False,
            },

            # Phase 6: Fix Design
            "R15": {
                "name": "Lowest Responsible Layer",
                "phase": Phase.P6_FIX,
                "check": "fix at lowest responsible layer, not masking lower defect",
                "stop_on_fail": True,
            },
            "R16": {
                "name": "Minimal & Reversible",
                "phase": Phase.P6_FIX,
                "check": "fix is minimal, scoped, reversible with rollback plan",
                "stop_on_fail": True,
            },
            "R17": {
                "name": "Shadow Mode",
                "phase": Phase.P6_FIX,
                "check": "if possible, deploy in shadow mode first",
                "stop_on_fail": False,
            },

            # Phase 7: Deployment
            "R18": {
                "name": "Canary Only",
                "phase": Phase.P7_DEPLOY,
                "check": "deploy to smallest cohort first, rollback on anomaly",
                "stop_on_fail": False,
            },
            "R19": {
                "name": "Performance Safety",
                "phase": Phase.P7_DEPLOY,
                "check": "if performance impacted, correctness already proven",
                "stop_on_fail": False,
            },

            # Phase 8: Review
            "R20": {
                "name": "Tiger Team",
                "phase": Phase.P8_REVIEW,
                "check": "independent reviewer validated evidence, repro, hypothesis, fix logic",
                "stop_on_fail": True,
            },

            # Phase 9: Closure
            "R21": {
                "name": "Documentation",
                "phase": Phase.P9_CLOSURE,
                "check": "documentation includes timeline, root cause, evidence, prevention",
                "stop_on_fail": False,
            },
            "R22": {
                "name": "Regression Prevention",
                "phase": Phase.P9_CLOSURE,
                "check": "regression test added",
                "stop_on_fail": False,
            },
        }

    def start_session(self, target: str, authorization: Dict = None) -> DebugSession:
        """Start a new debugging session"""
        session_id = f"debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session = DebugSession(
            session_id=session_id,
            target=target,
            current_phase=Phase.P1_DETECTION,
            started=datetime.now().isoformat(),
            authorization=authorization,
        )
        self.sessions[session_id] = session
        return session

    def evaluate_rule(self, session_id: str, rule_id: str, passed: bool,
                      evidence: List[str] = None, message: str = None) -> RuleResult:
        """Evaluate a specific rule"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]
        rule = self.rules.get(rule_id)

        if not rule:
            raise ValueError(f"Rule not found: {rule_id}")

        if passed:
            status = RuleStatus.PASSED
        elif rule["stop_on_fail"]:
            status = RuleStatus.BLOCKED
            session.stop_reason = f"{rule_id}: {rule['name']} - STOP"
        else:
            status = RuleStatus.FAILED

        result = RuleResult(
            rule_id=rule_id,
            rule_name=rule["name"],
            phase=rule["phase"].value,
            status=status,
            message=message or rule["check"],
            evidence=evidence or [],
        )

        session.rule_results.append(result)
        return result

    def check_phase(self, session_id: str, phase: Phase) -> Dict:
        """Check all rules for a phase"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]
        phase_rules = {k: v for k, v in self.rules.items() if v["phase"] == phase}

        results = []
        for rule_id, rule in phase_rules.items():
            # Check if already evaluated
            existing = [r for r in session.rule_results if r.rule_id == rule_id]
            if existing:
                results.append(existing[-1].to_dict())
            else:
                results.append({
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "status": "pending",
                    "check": rule["check"],
                    "stop_on_fail": rule["stop_on_fail"],
                })

        return {
            "phase": phase.value,
            "rules": results,
            "blocked": session.stop_reason is not None,
            "stop_reason": session.stop_reason,
        }

    def advance_phase(self, session_id: str) -> Dict:
        """Advance to next phase if current phase rules pass"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]

        if session.stop_reason:
            return {"error": f"Session blocked: {session.stop_reason}"}

        current = session.current_phase
        phases = list(Phase)
        current_idx = phases.index(current)

        # Check if all blocking rules in current phase passed
        phase_rules = {k: v for k, v in self.rules.items()
                       if v["phase"] == current and v["stop_on_fail"]}

        for rule_id in phase_rules:
            results = [r for r in session.rule_results if r.rule_id == rule_id]
            if not results or results[-1].status != RuleStatus.PASSED:
                return {
                    "error": f"Cannot advance: {rule_id} not passed",
                    "current_phase": current.value,
                }

        if current_idx < len(phases) - 1:
            session.current_phase = phases[current_idx + 1]
            return {
                "previous_phase": current.value,
                "current_phase": session.current_phase.value,
                "advanced": True,
            }

        return {
            "current_phase": current.value,
            "complete": True,
        }

    def set_golden_state(self, session_id: str, state: Dict) -> Dict:
        """Set the golden state for a session"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        required = ["inputs", "configs", "versions", "environment", "timestamp"]
        missing = [k for k in required if k not in state]

        if missing:
            return {"error": f"Missing required fields: {missing}"}

        self.sessions[session_id].golden_state = state
        return {"golden_state": "captured", "fields": list(state.keys())}

    def add_hypothesis(self, session_id: str, hypothesis: str) -> Dict:
        """Add a hypothesis to the session"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]
        session.hypotheses.append(hypothesis)

        return {
            "hypothesis_added": hypothesis,
            "total_hypotheses": len(session.hypotheses),
            "minimum_required": 3,
            "rule_8_satisfied": len(session.hypotheses) >= 3,
        }

    def get_session_status(self, session_id: str) -> Dict:
        """Get full session status"""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]

        passed = sum(1 for r in session.rule_results if r.status == RuleStatus.PASSED)
        failed = sum(1 for r in session.rule_results if r.status == RuleStatus.FAILED)
        blocked = sum(1 for r in session.rule_results if r.status == RuleStatus.BLOCKED)

        return {
            "session_id": session.session_id,
            "target": session.target,
            "current_phase": session.current_phase.value,
            "started": session.started,
            "has_authorization": session.authorization is not None,
            "has_golden_state": session.golden_state is not None,
            "hypotheses_count": len(session.hypotheses),
            "rules_passed": passed,
            "rules_failed": failed,
            "rules_blocked": blocked,
            "is_blocked": session.stop_reason is not None,
            "stop_reason": session.stop_reason,
        }

    def check_stop_conditions(self, conditions: List[str]) -> Dict:
        """Check if any absolute stop conditions are met"""
        matched = [c for c in conditions if c in self.STOP_CONDITIONS]

        return {
            "stop_required": len(matched) > 0,
            "matched_conditions": matched,
            "all_stop_conditions": self.STOP_CONDITIONS,
        }

    def get_invariants(self) -> List[str]:
        """Get global invariants"""
        return self.INVARIANTS


class MethodologyModule(BaseModule if HAS_BASE else object):
    """
    BlackBox Methodology Module

    Implements DEBUG_RULES.md as a programmatic rules engine.
    """

    name = "methodology"
    version = "1.0.0"
    description = "DEADMAN Debugging methodology - 22 rules, 9 phases"
    category = ModuleCategory.METHODOLOGY if HAS_BASE else "methodology"

    def __init__(self, config: Dict = None):
        if HAS_BASE:
            super().__init__(config)
        else:
            self.config = config or {}

        self.engine = RulesEngine()

    def on_load(self) -> bool:
        return True

    def on_unload(self):
        pass

    def register_tools(self, mcp, client) -> List[str]:
        """Register MCP tools"""
        tools = []

        @mcp.tool()
        async def methodology_start(target: str, authorization: str = None) -> str:
            """Start a debugging session with methodology tracking.

            Args:
                target: Target system/component being debugged
                authorization: Authorization documentation (optional)
            """
            auth = {"documented": authorization} if authorization else None
            session = self.engine.start_session(target, auth)
            return json.dumps(session.to_dict(), indent=2)
        tools.append("methodology_start")

        @mcp.tool()
        async def methodology_evaluate_rule(session_id: str, rule_id: str,
                                            passed: bool, evidence: str = None,
                                            message: str = None) -> str:
            """Evaluate a methodology rule for a session.

            Args:
                session_id: Active session ID
                rule_id: Rule ID (R0-R22)
                passed: Whether the rule passed
                evidence: Evidence supporting the evaluation
                message: Additional message
            """
            evidence_list = evidence.split(";") if evidence else []
            result = self.engine.evaluate_rule(session_id, rule_id, passed,
                                               evidence_list, message)
            return json.dumps(result.to_dict(), indent=2)
        tools.append("methodology_evaluate_rule")

        @mcp.tool()
        async def methodology_check_phase(session_id: str, phase: str) -> str:
            """Check all rules for a debugging phase.

            Args:
                session_id: Active session ID
                phase: Phase name (failure_detection, state_freeze, reproduction,
                       hypothesis, validation, fix_design, deployment,
                       independent_review, closure)
            """
            phase_enum = Phase(phase)
            result = self.engine.check_phase(session_id, phase_enum)
            return json.dumps(result, indent=2)
        tools.append("methodology_check_phase")

        @mcp.tool()
        async def methodology_advance_phase(session_id: str) -> str:
            """Advance to next debugging phase if current phase rules pass.

            Args:
                session_id: Active session ID
            """
            result = self.engine.advance_phase(session_id)
            return json.dumps(result, indent=2)
        tools.append("methodology_advance_phase")

        @mcp.tool()
        async def methodology_golden_state(session_id: str, inputs: str,
                                           configs: str, versions: str,
                                           environment: str) -> str:
            """Capture golden state for a debugging session (Rule 4).

            Args:
                session_id: Active session ID
                inputs: Input data description
                configs: Configuration state
                versions: Version information
                environment: Environment details
            """
            state = {
                "inputs": inputs,
                "configs": configs,
                "versions": versions,
                "environment": environment,
                "timestamp": datetime.now().isoformat(),
            }
            result = self.engine.set_golden_state(session_id, state)
            return json.dumps(result, indent=2)
        tools.append("methodology_golden_state")

        @mcp.tool()
        async def methodology_add_hypothesis(session_id: str, hypothesis: str) -> str:
            """Add a hypothesis to the session (Rule 8 requires >=3).

            Args:
                session_id: Active session ID
                hypothesis: Hypothesis statement
            """
            result = self.engine.add_hypothesis(session_id, hypothesis)
            return json.dumps(result, indent=2)
        tools.append("methodology_add_hypothesis")

        @mcp.tool()
        async def methodology_status(session_id: str) -> str:
            """Get full methodology session status.

            Args:
                session_id: Active session ID
            """
            result = self.engine.get_session_status(session_id)
            return json.dumps(result, indent=2)
        tools.append("methodology_status")

        @mcp.tool()
        async def methodology_check_stop(conditions: str) -> str:
            """Check if any absolute stop conditions are met.

            Args:
                conditions: Semicolon-separated list of conditions to check
            """
            cond_list = [c.strip() for c in conditions.split(";")]
            result = self.engine.check_stop_conditions(cond_list)
            return json.dumps(result, indent=2)
        tools.append("methodology_check_stop")

        @mcp.tool()
        async def methodology_invariants() -> str:
            """Get the global debugging invariants."""
            return json.dumps({
                "invariants": self.engine.get_invariants(),
                "description": "These must ALWAYS be true during debugging",
            }, indent=2)
        tools.append("methodology_invariants")

        @mcp.tool()
        async def methodology_rules() -> str:
            """Get all methodology rules."""
            rules = []
            for rule_id, rule in self.engine.rules.items():
                rules.append({
                    "id": rule_id,
                    "name": rule["name"],
                    "phase": rule["phase"].value,
                    "check": rule["check"],
                    "stop_on_fail": rule["stop_on_fail"],
                })
            return json.dumps({"rules": rules, "total": len(rules)}, indent=2)
        tools.append("methodology_rules")

        return tools

    def register_routes(self, app) -> List[str]:
        """Register Flask routes"""
        routes = []

        @app.route('/api/methodology/start', methods=['POST'])
        def api_methodology_start():
            from flask import request, jsonify
            data = request.get_json() or {}
            target = data.get('target', 'unknown')
            auth = data.get('authorization')
            session = self.engine.start_session(target, {"documented": auth} if auth else None)
            return jsonify(session.to_dict())
        routes.append('/api/methodology/start')

        @app.route('/api/methodology/status/<session_id>')
        def api_methodology_status(session_id):
            from flask import jsonify
            try:
                result = self.engine.get_session_status(session_id)
                return jsonify(result)
            except ValueError as e:
                return jsonify({"error": str(e)}), 404
        routes.append('/api/methodology/status/<session_id>')

        @app.route('/api/methodology/rules')
        def api_methodology_rules():
            from flask import jsonify
            rules = []
            for rule_id, rule in self.engine.rules.items():
                rules.append({
                    "id": rule_id,
                    "name": rule["name"],
                    "phase": rule["phase"].value,
                    "check": rule["check"],
                    "stop_on_fail": rule["stop_on_fail"],
                })
            return jsonify({"rules": rules})
        routes.append('/api/methodology/rules')

        @app.route('/api/methodology/invariants')
        def api_methodology_invariants():
            from flask import jsonify
            return jsonify({"invariants": self.engine.get_invariants()})
        routes.append('/api/methodology/invariants')

        return routes


# CLI interface
if __name__ == "__main__":
    import sys

    engine = RulesEngine()

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "rules":
            print("=== DEBUG_RULES.md - 22 Rules ===\n")
            for rule_id, rule in engine.rules.items():
                stop = "[STOP]" if rule["stop_on_fail"] else ""
                print(f"{rule_id}: {rule['name']} {stop}")
                print(f"    Phase: {rule['phase'].value}")
                print(f"    Check: {rule['check']}\n")

        elif cmd == "invariants":
            print("=== Global Invariants ===\n")
            for inv in engine.INVARIANTS:
                print(f"  - {inv}")

        elif cmd == "phases":
            print("=== 9 Debugging Phases ===\n")
            for phase in Phase:
                print(f"  {phase.value}")

        elif cmd == "stop":
            print("=== Absolute Stop Conditions ===\n")
            for cond in engine.STOP_CONDITIONS:
                print(f"  - {cond}")

        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python module.py [rules|invariants|phases|stop]")
    else:
        print("DEBUG_RULES Methodology Module")
        print("Usage: python module.py [rules|invariants|phases|stop]")
