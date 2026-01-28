#!/usr/bin/env python3
"""
Debug Standards Enforcement
Automatically applies NASA-inspired data standards during debugging

This module integrates with the DEADMAN Debugging Methodology to ensure
all debug activities follow standardized data practices:

- Every debug session gets a unique LID
- All evidence is captured with checksums and provenance
- State snapshots have integrity verification
- Hypotheses are tracked with processing levels
- Fixes are documented with full R16/R21 compliance

Usage:
    from workflows.debug_standards_enforcement import (
        StandardizedDebugger,
        enforce_standards
    )

    # Start standardized debug session
    debugger = StandardizedDebugger.start(
        name="Memory Leak Investigation",
        failure_type="crash",
        system_boundary="API -> Cache -> DB"
    )

    # All operations are automatically standardized
    debugger.capture_state(inputs={...}, configs={...})
    debugger.add_hypothesis("Memory not freed after request")
    debugger.capture_evidence("log", log_content, "Heap dump")

    # Get enforcement report
    report = debugger.get_enforcement_report()
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from functools import wraps

# Add BlackBox root to path
BLACKBOX_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BLACKBOX_ROOT))

from standards.lib.debug_integration import (
    DebugSession,
    DebugPhase,
    FailureType,
    StateSnapshot,
    DebugEvidence,
    DebugHypothesis,
    DebugFix,
    HypothesisStatus,
    FixStatus,
    EvidenceLevel,
)
from standards import (
    ProcessingLevel,
    generate_timestamp,
    generate_lid,
)


# =============================================================================
# ENFORCEMENT RULES
# =============================================================================

@dataclass
class EnforcementRule:
    """A standards enforcement rule."""
    rule_id: str
    name: str
    phase: str
    description: str
    check_fn: Optional[Callable] = None
    required: bool = True
    auto_enforce: bool = True


ENFORCEMENT_RULES = [
    # Phase 1: Detection
    EnforcementRule(
        rule_id="STD-R0",
        name="Session LID Required",
        phase="detection",
        description="Every debug session must have a unique Logical Identifier",
        required=True,
        auto_enforce=True
    ),
    EnforcementRule(
        rule_id="STD-R1",
        name="Failure Classification",
        phase="detection",
        description="Failure type must be classified from standard enumeration",
        required=True,
        auto_enforce=True
    ),

    # Phase 2: State
    EnforcementRule(
        rule_id="STD-R4",
        name="Golden State Checksum",
        phase="state",
        description="State snapshots must have integrity checksums",
        required=True,
        auto_enforce=True
    ),
    EnforcementRule(
        rule_id="STD-R5",
        name="State Versioning",
        phase="state",
        description="All states must include version information",
        required=False,
        auto_enforce=True
    ),

    # Phase 3: Reproduction
    EnforcementRule(
        rule_id="STD-R6",
        name="Repro Evidence",
        phase="reproduction",
        description="Reproduction must be documented with evidence",
        required=True,
        auto_enforce=True
    ),

    # Phase 4: Hypothesis
    EnforcementRule(
        rule_id="STD-R8",
        name="Hypothesis Tracking",
        phase="hypothesis",
        description="All hypotheses must have LIDs and processing levels",
        required=True,
        auto_enforce=True
    ),
    EnforcementRule(
        rule_id="STD-R9",
        name="Falsification Records",
        phase="hypothesis",
        description="Test results must be recorded with timestamps",
        required=True,
        auto_enforce=True
    ),

    # Phase 5: Validation
    EnforcementRule(
        rule_id="STD-R13",
        name="Evidence Chain",
        phase="validation",
        description="All evidence must have hashes and provenance",
        required=True,
        auto_enforce=True
    ),

    # Phase 6: Fix
    EnforcementRule(
        rule_id="STD-R16",
        name="Fix Compliance",
        phase="fix",
        description="Fixes must document R16 compliance (minimal, reversible)",
        required=True,
        auto_enforce=True
    ),

    # Phase 8: Review
    EnforcementRule(
        rule_id="STD-R20",
        name="Review Provenance",
        phase="review",
        description="Reviews must be recorded with reviewer and timestamp",
        required=True,
        auto_enforce=True
    ),

    # Phase 9: Closure
    EnforcementRule(
        rule_id="STD-R21",
        name="Documentation Labels",
        phase="closure",
        description="Final documentation must have standardized labels",
        required=True,
        auto_enforce=True
    ),
]


# =============================================================================
# STANDARDIZED DEBUGGER
# =============================================================================

class StandardizedDebugger:
    """
    Debugging interface with automatic standards enforcement.

    Wraps DebugSession to automatically apply NASA-inspired data standards
    to all debugging operations.
    """

    def __init__(self, session: DebugSession):
        self.session = session
        self.enforcement_log: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self._log_enforcement("STD-R0", "Session created with LID", session.lid)
        self._log_enforcement("STD-R1", "Failure classified", session.failure_type.value)

    @classmethod
    def start(
        cls,
        name: str,
        failure_type: Union[FailureType, str],
        failure_definition: str,
        success_criteria: str,
        system_boundary: str,
        scope: Optional[str] = None,
        authorization: Optional[str] = None,
        base_path: Optional[Union[str, Path]] = None
    ) -> "StandardizedDebugger":
        """
        Start a new standardized debug session.

        All methodology rules and data standards are automatically enforced.
        """
        # Use default base path if not provided
        if base_path is None:
            base_path = BLACKBOX_ROOT / "debug_sessions"

        session = DebugSession.create(
            name=name,
            failure_type=failure_type,
            failure_definition=failure_definition,
            success_criteria=success_criteria,
            system_boundary=system_boundary,
            scope=scope,
            authorization=authorization,
            base_path=base_path
        )

        debugger = cls(session)

        # Auto-save session
        if session.base_path:
            session.save()

        return debugger

    def _log_enforcement(self, rule_id: str, action: str, details: str = ""):
        """Log an enforcement action."""
        self.enforcement_log.append({
            "timestamp": generate_timestamp(),
            "rule_id": rule_id,
            "action": action,
            "details": details
        })

    def _add_warning(self, message: str):
        """Add a warning for non-critical issues."""
        self.warnings.append(f"[{generate_timestamp()}] {message}")

    # -------------------------------------------------------------------------
    # State Management (Auto-enforces STD-R4, STD-R5)
    # -------------------------------------------------------------------------

    def capture_state(
        self,
        name: str,
        inputs: Dict[str, Any],
        configs: Dict[str, Any],
        versions: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> StateSnapshot:
        """
        Capture state with automatic standards enforcement.

        Automatically:
        - Generates checksum (STD-R4)
        - Validates versioning (STD-R5)
        - Creates standardized label
        """
        # Warn if versions missing
        if not versions:
            self._add_warning("STD-R5: State captured without version information")

        snapshot = self.session.capture_state(
            name=name,
            inputs=inputs,
            configs=configs,
            versions=versions or {},
            environment=environment or {}
        )

        self._log_enforcement(
            "STD-R4",
            "State captured with checksum",
            f"LID: {snapshot.lid}, Checksum: {snapshot.checksum[:32]}..."
        )

        return snapshot

    # -------------------------------------------------------------------------
    # Evidence Management (Auto-enforces STD-R13)
    # -------------------------------------------------------------------------

    def capture_evidence(
        self,
        evidence_type: str,
        content: Union[str, bytes, Path],
        title: str,
        description: str = ""
    ) -> DebugEvidence:
        """
        Capture evidence with automatic standards enforcement.

        Automatically:
        - Generates content hash (STD-R13)
        - Creates evidence chain entry
        - Tracks provenance
        """
        evidence = self.session.capture_evidence(
            evidence_type=evidence_type,
            content=content,
            title=title,
            description=description
        )

        self._log_enforcement(
            "STD-R13",
            "Evidence captured with hash",
            f"LID: {evidence.lid}, Hash: {evidence.content_hash[:32]}..."
        )

        return evidence

    def promote_evidence(self, evidence: DebugEvidence, new_level: EvidenceLevel):
        """Promote evidence strength level."""
        evidence.promote_level(new_level)
        self._log_enforcement(
            "STD-R13",
            "Evidence level promoted",
            f"LID: {evidence.lid}, New level: {new_level.value}"
        )

    # -------------------------------------------------------------------------
    # Hypothesis Management (Auto-enforces STD-R8, STD-R9)
    # -------------------------------------------------------------------------

    def add_hypothesis(
        self,
        description: str,
        layer: str = "application",
        falsification_test: Optional[str] = None
    ) -> DebugHypothesis:
        """
        Add hypothesis with automatic standards enforcement.

        Automatically:
        - Generates LID (STD-R8)
        - Sets initial processing level
        - Warns if no falsification test (R9)
        """
        hypothesis = self.session.add_hypothesis(
            description=description,
            layer=layer,
            falsification_test=falsification_test
        )

        if not falsification_test:
            self._add_warning(f"STD-R9: Hypothesis {hypothesis.lid} has no falsification test")

        self._log_enforcement(
            "STD-R8",
            "Hypothesis added with LID",
            f"LID: {hypothesis.lid}, Layer: {layer}"
        )

        # Check R8 compliance
        r8 = self.session.validate_r8()
        if not r8["passed"]:
            self._add_warning(f"R8 Warning: Only {r8['hypothesis_count']}/3 hypotheses")

        return hypothesis

    def record_test_result(
        self,
        hypothesis: DebugHypothesis,
        result: str,
        falsified: bool
    ):
        """
        Record hypothesis test result with standards enforcement.

        Automatically:
        - Timestamps the test (STD-R9)
        - Updates processing level
        - Logs the outcome
        """
        hypothesis.record_test_result(result, falsified)

        self._log_enforcement(
            "STD-R9",
            f"Test recorded: {'FALSIFIED' if falsified else 'SUPPORTED'}",
            f"LID: {hypothesis.lid}, Result: {result[:50]}..."
        )

    def confirm_root_cause(self, hypothesis: DebugHypothesis):
        """Confirm hypothesis as root cause."""
        hypothesis.confirm_as_root_cause()

        self._log_enforcement(
            "STD-R8",
            "Root cause confirmed",
            f"LID: {hypothesis.lid}, Processing Level: L4"
        )

    # -------------------------------------------------------------------------
    # Fix Management (Auto-enforces STD-R16, STD-R20, STD-R21)
    # -------------------------------------------------------------------------

    def document_fix(
        self,
        description: str,
        root_cause: str,
        layer: str = "application"
    ) -> DebugFix:
        """
        Document fix with automatic standards enforcement.

        Automatically:
        - Links to root cause hypothesis
        - Creates standardized label
        - Initializes timeline
        """
        fix = self.session.document_fix(
            description=description,
            root_cause=root_cause,
            layer=layer
        )

        self._log_enforcement(
            "STD-R16",
            "Fix documented",
            f"LID: {fix.lid}, Layer: {layer}"
        )

        # Warn about R16 compliance
        self._add_warning("STD-R16: Remember to set R16 compliance (minimal, scoped, reversible)")

        return fix

    def set_fix_compliance(
        self,
        fix: DebugFix,
        minimal: bool,
        scoped: bool,
        reversible: bool,
        rollback_plan: str
    ):
        """
        Set R16 compliance for a fix.

        Validates and logs compliance status.
        """
        fix.set_r16_compliance(minimal, scoped, reversible, rollback_plan)

        compliance = fix.validate_r16()
        self._log_enforcement(
            "STD-R16",
            f"R16 compliance: {'PASS' if compliance['all_passed'] else 'FAIL'}",
            f"LID: {fix.lid}, Details: {compliance}"
        )

        if not compliance["all_passed"]:
            self._add_warning(f"STD-R16: Fix {fix.lid} not fully compliant: {compliance}")

    def record_review(
        self,
        fix: DebugFix,
        reviewer: str,
        result: str,
        approved: bool
    ):
        """
        Record fix review with standards enforcement.

        Automatically timestamps and tracks reviewer.
        """
        fix.record_review(reviewer, result, approved)

        self._log_enforcement(
            "STD-R20",
            f"Review recorded: {'APPROVED' if approved else 'REJECTED'}",
            f"LID: {fix.lid}, Reviewer: {reviewer}"
        )

    def close_fix(
        self,
        fix: DebugFix,
        prevention: str,
        regression_test: str
    ):
        """
        Close fix with documentation requirements.

        Enforces R21 documentation requirements.
        """
        fix.close(prevention, regression_test)

        self._log_enforcement(
            "STD-R21",
            "Fix closed with documentation",
            f"LID: {fix.lid}, Has prevention: True, Has regression test: True"
        )

    # -------------------------------------------------------------------------
    # Reporting
    # -------------------------------------------------------------------------

    def get_enforcement_report(self) -> Dict[str, Any]:
        """
        Get comprehensive standards enforcement report.

        Shows all enforcement actions, warnings, and compliance status.
        """
        methodology = self.session.validate_methodology()

        return {
            "session": {
                "lid": self.session.lid,
                "name": self.session.name,
                "current_phase": self.session.current_phase.value,
                "status": self.session.status
            },
            "standards_compliance": {
                "STD-R0_session_lid": True,  # Always true if session exists
                "STD-R1_failure_classified": True,
                "STD-R4_golden_state": methodology["r4_golden_state"]["passed"],
                "STD-R8_hypotheses": methodology["r8_hypotheses"]["passed"],
                "STD-R13_evidence_chain": methodology["evidence_count"] > 0,
                "STD-R16_fix_compliance": all(
                    f["compliance"]["all_passed"]
                    for f in methodology["r16_fix_compliance"]
                ) if methodology["r16_fix_compliance"] else None,
                "STD-R21_documentation": all(
                    f["has_root_cause"] and f["has_timeline"]
                    for f in methodology["r21_documentation"]
                ) if methodology["r21_documentation"] else None
            },
            "counts": {
                "state_snapshots": len(self.session.state_snapshots),
                "evidence": methodology["evidence_count"],
                "hypotheses": methodology["hypothesis_count"],
                "fixes": methodology["fix_count"]
            },
            "enforcement_log": self.enforcement_log,
            "warnings": self.warnings,
            "methodology_validation": methodology
        }

    def advance_phase(self, new_phase: DebugPhase):
        """Advance to next phase."""
        self.session.advance_phase(new_phase)
        self._log_enforcement(
            "PHASE",
            f"Advanced to {new_phase.value}",
            f"Session: {self.session.lid}"
        )

    def close(self):
        """Close the debug session."""
        self.session.close()
        if self.session.base_path:
            self.session.save()

        self._log_enforcement(
            "SESSION",
            "Debug session closed",
            f"LID: {self.session.lid}"
        )

    def save(self):
        """Save current session state."""
        if self.session.base_path:
            self.session.save()

            # Also save enforcement report
            report_path = self.session.base_path / "enforcement_report.yaml"
            import yaml
            with open(report_path, "w") as f:
                yaml.dump(self.get_enforcement_report(), f, default_flow_style=False)


# =============================================================================
# DECORATOR FOR AUTOMATIC ENFORCEMENT
# =============================================================================

def enforce_standards(func: Callable) -> Callable:
    """
    Decorator to enforce standards on debug functions.

    Usage:
        @enforce_standards
        def my_debug_function(debugger: StandardizedDebugger, ...):
            ...
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Find StandardizedDebugger in args
        debugger = None
        for arg in args:
            if isinstance(arg, StandardizedDebugger):
                debugger = arg
                break

        if debugger is None:
            debugger = kwargs.get("debugger")

        if debugger:
            debugger._log_enforcement(
                "AUTO",
                f"Function called: {func.__name__}",
                f"Args: {len(args)}, Kwargs: {len(kwargs)}"
            )

        result = func(*args, **kwargs)

        if debugger:
            debugger._log_enforcement(
                "AUTO",
                f"Function completed: {func.__name__}",
                ""
            )

        return result

    return wrapper


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "StandardizedDebugger",
    "enforce_standards",
    "ENFORCEMENT_RULES",
    "EnforcementRule",
]
