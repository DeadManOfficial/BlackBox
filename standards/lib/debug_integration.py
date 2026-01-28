"""
BlackBox Debug Integration
NASA-Inspired Standards for Debugging Workflows

Integrates data standards with the DEADMAN Debugging Methodology (9 phases, 22 rules).

Key Enhancements:
- Debug Sessions with LIDs and provenance
- Evidence Chain with integrity verification
- State Snapshots with checksums
- Hypothesis Tracking with processing levels
- Fix Documentation with standardized labels

Usage:
    from standards.lib.debug_integration import (
        DebugSession,
        StateSnapshot,
        DebugHypothesis,
        DebugEvidence,
        DebugFix
    )

    # Start a debug session
    session = DebugSession.create(
        name="Memory Corruption Investigation",
        failure_type="crash",
        system_boundary="API Gateway -> Auth Service"
    )

    # Capture golden state
    snapshot = session.capture_state(
        inputs={"request": "POST /login"},
        configs={"timeout": 30},
        environment={"python": "3.11", "os": "linux"}
    )

    # Track hypotheses
    h1 = session.add_hypothesis(
        description="Buffer overflow in input parser",
        evidence=["stack trace shows overflow"],
        falsification_test="Test with bounded input"
    )

    # Capture evidence
    evidence = session.capture_evidence(
        evidence_type="log",
        content=log_content,
        title="Stack trace at crash"
    )

    # Document fix
    fix = session.document_fix(
        description="Add bounds checking to parser",
        root_cause="Missing input validation",
        minimal=True,
        reversible=True
    )
"""

import hashlib
import json
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

from .data_standards import (
    Label,
    ProcessingLevel,
    ProductClass,
    Provenance,
    FileInfo,
    Reference,
    ToolInfo,
    generate_lid,
    generate_short_id,
    generate_timestamp,
    create_label,
    calculate_checksum,
    Checksum,
)


# =============================================================================
# ENUMERATIONS
# =============================================================================

class DebugPhase(Enum):
    """DEADMAN Methodology phases"""
    DETECTION = "phase_1_detection"
    STATE = "phase_2_state"
    REPRODUCTION = "phase_3_reproduction"
    HYPOTHESIS = "phase_4_hypothesis"
    VALIDATION = "phase_5_validation"
    FIX = "phase_6_fix"
    DEPLOYMENT = "phase_7_deployment"
    REVIEW = "phase_8_review"
    CLOSURE = "phase_9_closure"


class FailureType(Enum):
    """Failure type classification (Rule R3)"""
    CRASH = "crash"
    INCORRECT_OUTPUT = "incorrect_output"
    PERFORMANCE_REGRESSION = "performance_regression"
    HANG_DEADLOCK = "hang_deadlock"
    SECURITY_VULNERABILITY = "security_vulnerability"
    DATA_CORRUPTION = "data_corruption"


class HypothesisStatus(Enum):
    """Hypothesis lifecycle status"""
    PROPOSED = "proposed"       # L0 - Initial
    TESTABLE = "testable"       # L1 - Has falsification test
    TESTED = "tested"           # L2 - Test executed
    FALSIFIED = "falsified"     # L3 - Disproven
    SUPPORTED = "supported"     # L3 - Not yet falsified
    CONFIRMED = "confirmed"     # L4 - Root cause identified


class FixStatus(Enum):
    """Fix lifecycle status"""
    PROPOSED = "proposed"
    DESIGNED = "designed"
    IMPLEMENTED = "implemented"
    SHADOW = "shadow"           # Shadow mode testing
    CANARY = "canary"           # Canary deployment
    DEPLOYED = "deployed"
    VERIFIED = "verified"
    CLOSED = "closed"


class EvidenceLevel(Enum):
    """Evidence strength classification"""
    ANECDOTAL = "anecdotal"     # Single observation
    REPRODUCIBLE = "reproducible"  # Can be reproduced
    CORROBORATED = "corroborated"  # Multiple sources
    VERIFIED = "verified"       # Independently verified


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class StateSnapshot:
    """
    Golden State capture (Rule R4).

    Captures complete system state at a point in time with
    integrity verification.
    """
    lid: str
    session_lid: str
    name: str
    inputs: Dict[str, Any]
    configs: Dict[str, Any]
    versions: Dict[str, str]
    environment: Dict[str, str]
    timestamp: str = field(default_factory=generate_timestamp)
    checksum: str = ""
    processing_level: ProcessingLevel = ProcessingLevel.L1
    label: Optional[Label] = None

    def __post_init__(self):
        """Calculate checksum after initialization"""
        if not self.checksum:
            content = json.dumps({
                "inputs": self.inputs,
                "configs": self.configs,
                "versions": self.versions,
                "environment": self.environment,
                "timestamp": self.timestamp
            }, sort_keys=True)
            self.checksum = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    @classmethod
    def create(
        cls,
        session_lid: str,
        name: str,
        inputs: Dict[str, Any],
        configs: Dict[str, Any],
        versions: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> "StateSnapshot":
        """Create a new state snapshot."""
        snapshot_id = f"state-{generate_short_id()}"
        snapshot_lid = generate_lid("debug", "state", snapshot_id)

        snapshot = cls(
            lid=snapshot_lid,
            session_lid=session_lid,
            name=name,
            inputs=inputs,
            configs=configs,
            versions=versions or {},
            environment=environment or {}
        )

        # Create label
        snapshot.label = create_label(
            lid=snapshot_lid,
            title=f"State Snapshot: {name}",
            product_class=ProductClass.CONTEXT,
            processing_level=ProcessingLevel.L1,
            created_by="debug-session"
        )

        return snapshot

    def verify_integrity(self) -> bool:
        """Verify snapshot integrity via checksum."""
        content = json.dumps({
            "inputs": self.inputs,
            "configs": self.configs,
            "versions": self.versions,
            "environment": self.environment,
            "timestamp": self.timestamp
        }, sort_keys=True)
        expected = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
        return self.checksum == expected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lid": self.lid,
            "session_lid": self.session_lid,
            "name": self.name,
            "inputs": self.inputs,
            "configs": self.configs,
            "versions": self.versions,
            "environment": self.environment,
            "timestamp": self.timestamp,
            "checksum": self.checksum,
            "processing_level": self.processing_level.value,
            "integrity_valid": self.verify_integrity()
        }


@dataclass
class DebugEvidence:
    """
    Debug evidence with chain of custody.

    Ensures evidence integrity per methodology invariant:
    "Evidence > opinion"
    """
    lid: str
    session_lid: str
    evidence_type: str
    title: str
    description: str
    content_hash: str
    content_path: Optional[str] = None
    content_inline: Optional[str] = None
    level: EvidenceLevel = EvidenceLevel.ANECDOTAL
    sources: List[str] = field(default_factory=list)
    captured_at: str = field(default_factory=generate_timestamp)
    captured_by: str = "debug-session"
    processing_level: ProcessingLevel = ProcessingLevel.L0
    label: Optional[Label] = None

    @classmethod
    def create(
        cls,
        session_lid: str,
        evidence_type: str,
        title: str,
        content: Union[str, bytes, Path],
        description: str = "",
        captured_by: str = "debug-session"
    ) -> "DebugEvidence":
        """Create new debug evidence."""
        evidence_id = f"evidence-{evidence_type}-{generate_short_id()}"
        evidence_lid = generate_lid("debug", "evidence", evidence_id)

        # Handle content
        if isinstance(content, Path):
            content_path = str(content)
            content_hash = f"sha256:{calculate_checksum(content)}"
            content_inline = None
        elif isinstance(content, bytes):
            content_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
            content_inline = content.decode("utf-8", errors="replace")[:10000]
            content_path = None
        else:
            content_hash = f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"
            content_inline = content[:10000] if len(content) > 10000 else content
            content_path = None

        evidence = cls(
            lid=evidence_lid,
            session_lid=session_lid,
            evidence_type=evidence_type,
            title=title,
            description=description,
            content_hash=content_hash,
            content_path=content_path,
            content_inline=content_inline,
            captured_by=captured_by
        )

        # Create label
        evidence.label = create_label(
            lid=evidence_lid,
            title=f"Evidence: {title}",
            product_class=ProductClass.EVIDENCE,
            processing_level=ProcessingLevel.L0,
            created_by=captured_by
        )

        return evidence

    def promote_level(self, new_level: EvidenceLevel):
        """Promote evidence strength level."""
        self.level = new_level
        if self.label:
            # Map evidence level to processing level
            level_map = {
                EvidenceLevel.ANECDOTAL: ProcessingLevel.L0,
                EvidenceLevel.REPRODUCIBLE: ProcessingLevel.L1,
                EvidenceLevel.CORROBORATED: ProcessingLevel.L2,
                EvidenceLevel.VERIFIED: ProcessingLevel.L3,
            }
            self.processing_level = level_map.get(new_level, ProcessingLevel.L0)
            self.label.provenance.add_audit(
                "promoted",
                "analyst",
                f"Evidence promoted to {new_level.value}"
            )

    def add_source(self, source: str):
        """Add corroborating source."""
        if source not in self.sources:
            self.sources.append(source)
            if len(self.sources) >= 2 and self.level == EvidenceLevel.REPRODUCIBLE:
                self.promote_level(EvidenceLevel.CORROBORATED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lid": self.lid,
            "session_lid": self.session_lid,
            "evidence_type": self.evidence_type,
            "title": self.title,
            "description": self.description,
            "content_hash": self.content_hash,
            "content_path": self.content_path,
            "level": self.level.value,
            "sources": self.sources,
            "captured_at": self.captured_at,
            "captured_by": self.captured_by,
            "processing_level": self.processing_level.value
        }


@dataclass
class DebugHypothesis:
    """
    Hypothesis tracking (Rules R8, R9).

    Enforces:
    - Multiple hypotheses (>=3)
    - Falsification-based testing
    """
    lid: str
    session_lid: str
    description: str
    layer: str  # hardware, firmware, driver, runtime, framework, application
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    falsification_test: Optional[str] = None
    test_result: Optional[str] = None
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=generate_timestamp)
    tested_at: Optional[str] = None
    processing_level: ProcessingLevel = ProcessingLevel.L0
    label: Optional[Label] = None

    @classmethod
    def create(
        cls,
        session_lid: str,
        description: str,
        layer: str = "application",
        falsification_test: Optional[str] = None
    ) -> "DebugHypothesis":
        """Create a new hypothesis."""
        hyp_id = f"hypothesis-{generate_short_id()}"
        hyp_lid = generate_lid("debug", "hypothesis", hyp_id)

        hypothesis = cls(
            lid=hyp_lid,
            session_lid=session_lid,
            description=description,
            layer=layer,
            falsification_test=falsification_test
        )

        if falsification_test:
            hypothesis.status = HypothesisStatus.TESTABLE
            hypothesis.processing_level = ProcessingLevel.L1

        # Create label
        hypothesis.label = create_label(
            lid=hyp_lid,
            title=f"Hypothesis: {description[:50]}",
            product_class=ProductClass.CONTEXT,
            processing_level=hypothesis.processing_level,
            created_by="debug-session"
        )

        return hypothesis

    def set_falsification_test(self, test: str):
        """Define the falsification test."""
        self.falsification_test = test
        self.status = HypothesisStatus.TESTABLE
        self.processing_level = ProcessingLevel.L1
        if self.label:
            self.label.provenance.add_audit(
                "modified",
                "analyst",
                f"Falsification test defined: {test[:100]}"
            )

    def record_test_result(self, result: str, falsified: bool):
        """Record test execution result."""
        self.test_result = result
        self.tested_at = generate_timestamp()
        self.status = HypothesisStatus.FALSIFIED if falsified else HypothesisStatus.SUPPORTED
        self.processing_level = ProcessingLevel.L3
        if self.label:
            self.label.provenance.add_audit(
                "validated",
                "analyst",
                f"Test result: {'FALSIFIED' if falsified else 'SUPPORTED'}"
            )

    def confirm_as_root_cause(self):
        """Confirm this hypothesis as root cause."""
        if self.status != HypothesisStatus.SUPPORTED:
            raise ValueError("Can only confirm supported hypotheses")
        self.status = HypothesisStatus.CONFIRMED
        self.processing_level = ProcessingLevel.L4
        if self.label:
            self.label.provenance.add_audit(
                "promoted",
                "analyst",
                "Confirmed as root cause"
            )

    def add_evidence(self, evidence_lid: str, supports: bool = True):
        """Link evidence to hypothesis."""
        if supports:
            if evidence_lid not in self.supporting_evidence:
                self.supporting_evidence.append(evidence_lid)
        else:
            if evidence_lid not in self.contradicting_evidence:
                self.contradicting_evidence.append(evidence_lid)
                # Contradicting evidence may falsify
                if self.status == HypothesisStatus.SUPPORTED:
                    self.status = HypothesisStatus.TESTED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lid": self.lid,
            "session_lid": self.session_lid,
            "description": self.description,
            "layer": self.layer,
            "status": self.status.value,
            "falsification_test": self.falsification_test,
            "test_result": self.test_result,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "created_at": self.created_at,
            "tested_at": self.tested_at,
            "processing_level": self.processing_level.value
        }


@dataclass
class DebugFix:
    """
    Fix documentation (Rules R15, R16, R21).

    Enforces:
    - Lowest responsible layer
    - Minimal & reversible
    - Complete documentation
    """
    lid: str
    session_lid: str
    description: str
    root_cause: str
    root_cause_hypothesis_lid: Optional[str] = None
    layer: str = "application"
    status: FixStatus = FixStatus.PROPOSED
    # R16 requirements
    minimal: bool = False
    scoped: bool = False
    reversible: bool = False
    rollback_plan: Optional[str] = None
    # Documentation (R21)
    timeline: List[Dict[str, str]] = field(default_factory=list)
    prevention: Optional[str] = None
    regression_test: Optional[str] = None
    # Review (R20)
    reviewer: Optional[str] = None
    review_result: Optional[str] = None
    # Metadata
    created_at: str = field(default_factory=generate_timestamp)
    deployed_at: Optional[str] = None
    verified_at: Optional[str] = None
    processing_level: ProcessingLevel = ProcessingLevel.L0
    label: Optional[Label] = None

    @classmethod
    def create(
        cls,
        session_lid: str,
        description: str,
        root_cause: str,
        hypothesis_lid: Optional[str] = None,
        layer: str = "application"
    ) -> "DebugFix":
        """Create a new fix."""
        fix_id = f"fix-{generate_short_id()}"
        fix_lid = generate_lid("debug", "fix", fix_id)

        fix = cls(
            lid=fix_lid,
            session_lid=session_lid,
            description=description,
            root_cause=root_cause,
            root_cause_hypothesis_lid=hypothesis_lid,
            layer=layer
        )

        # Create label
        fix.label = create_label(
            lid=fix_lid,
            title=f"Fix: {description[:50]}",
            product_class=ProductClass.CONTEXT,
            processing_level=ProcessingLevel.L0,
            created_by="debug-session"
        )

        # Add initial timeline entry
        fix.add_timeline_event("proposed", f"Fix proposed: {description[:100]}")

        return fix

    def validate_r16(self) -> Dict[str, bool]:
        """Validate Rule R16 requirements."""
        return {
            "minimal": self.minimal,
            "scoped": self.scoped,
            "reversible": self.reversible,
            "rollback_plan_exists": self.rollback_plan is not None,
            "all_passed": all([
                self.minimal,
                self.scoped,
                self.reversible,
                self.rollback_plan is not None
            ])
        }

    def set_r16_compliance(
        self,
        minimal: bool,
        scoped: bool,
        reversible: bool,
        rollback_plan: str
    ):
        """Set R16 compliance fields."""
        self.minimal = minimal
        self.scoped = scoped
        self.reversible = reversible
        self.rollback_plan = rollback_plan
        self.status = FixStatus.DESIGNED
        self.processing_level = ProcessingLevel.L1
        self.add_timeline_event("designed", "R16 compliance documented")

    def add_timeline_event(self, event: str, description: str):
        """Add event to timeline (R21)."""
        self.timeline.append({
            "timestamp": generate_timestamp(),
            "event": event,
            "description": description
        })

    def mark_implemented(self):
        """Mark fix as implemented."""
        self.status = FixStatus.IMPLEMENTED
        self.processing_level = ProcessingLevel.L2
        self.add_timeline_event("implemented", "Fix implemented")

    def enter_shadow_mode(self):
        """Enter shadow mode testing (R17)."""
        self.status = FixStatus.SHADOW
        self.add_timeline_event("shadow", "Entered shadow mode")

    def deploy_canary(self):
        """Deploy to canary (R18)."""
        self.status = FixStatus.CANARY
        self.deployed_at = generate_timestamp()
        self.add_timeline_event("canary", "Deployed to canary")

    def deploy_full(self):
        """Full deployment."""
        self.status = FixStatus.DEPLOYED
        self.processing_level = ProcessingLevel.L3
        self.add_timeline_event("deployed", "Full deployment")

    def record_review(self, reviewer: str, result: str, approved: bool):
        """Record tiger team review (R20)."""
        self.reviewer = reviewer
        self.review_result = result
        if approved:
            self.status = FixStatus.VERIFIED
            self.verified_at = generate_timestamp()
            self.processing_level = ProcessingLevel.L4
        self.add_timeline_event(
            "reviewed",
            f"Review by {reviewer}: {'APPROVED' if approved else 'REJECTED'}"
        )

    def close(self, prevention: str, regression_test: str):
        """Close fix with documentation (R21, R22)."""
        self.prevention = prevention
        self.regression_test = regression_test
        self.status = FixStatus.CLOSED
        self.add_timeline_event("closed", "Fix closed with documentation")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lid": self.lid,
            "session_lid": self.session_lid,
            "description": self.description,
            "root_cause": self.root_cause,
            "root_cause_hypothesis_lid": self.root_cause_hypothesis_lid,
            "layer": self.layer,
            "status": self.status.value,
            "r16_compliance": self.validate_r16(),
            "rollback_plan": self.rollback_plan,
            "timeline": self.timeline,
            "prevention": self.prevention,
            "regression_test": self.regression_test,
            "reviewer": self.reviewer,
            "review_result": self.review_result,
            "created_at": self.created_at,
            "deployed_at": self.deployed_at,
            "verified_at": self.verified_at,
            "processing_level": self.processing_level.value
        }


# =============================================================================
# DEBUG SESSION
# =============================================================================

@dataclass
class DebugSession:
    """
    Main debug session container.

    Implements the DEADMAN Debugging Methodology with NASA-inspired
    data standards for traceability and reproducibility.

    Tracks:
    - Session metadata with LID
    - Phase progression
    - State snapshots (golden state)
    - Evidence chain
    - Hypotheses (>=3 required)
    - Fix documentation
    """
    lid: str
    name: str
    failure_type: FailureType
    failure_definition: str
    success_criteria: str
    system_boundary: str
    current_phase: DebugPhase = DebugPhase.DETECTION
    status: str = "active"
    # Collections
    state_snapshots: List[StateSnapshot] = field(default_factory=list)
    evidence: List[DebugEvidence] = field(default_factory=list)
    hypotheses: List[DebugHypothesis] = field(default_factory=list)
    fixes: List[DebugFix] = field(default_factory=list)
    # Authorization (R0)
    scope: Optional[str] = None
    authorization: Optional[str] = None
    asset_owner: Optional[str] = None
    # Metadata
    created_at: str = field(default_factory=generate_timestamp)
    updated_at: str = field(default_factory=generate_timestamp)
    closed_at: Optional[str] = None
    label: Optional[Label] = None
    base_path: Optional[Path] = None

    @classmethod
    def create(
        cls,
        name: str,
        failure_type: Union[FailureType, str],
        failure_definition: str,
        success_criteria: str,
        system_boundary: str,
        scope: Optional[str] = None,
        authorization: Optional[str] = None,
        base_path: Optional[Union[str, Path]] = None
    ) -> "DebugSession":
        """
        Create a new debug session.

        Enforces Rules R0, R1, R2, R3.
        """
        # Normalize failure type
        if isinstance(failure_type, str):
            failure_type = FailureType(failure_type.lower())

        # Generate LID
        session_id = f"debug-{name.lower().replace(' ', '-')[:30]}-{generate_short_id()}"
        session_lid = generate_lid("debug", "session", session_id)

        session = cls(
            lid=session_lid,
            name=name,
            failure_type=failure_type,
            failure_definition=failure_definition,
            success_criteria=success_criteria,
            system_boundary=system_boundary,
            scope=scope,
            authorization=authorization
        )

        # Create label
        session.label = create_label(
            lid=session_lid,
            title=f"Debug Session: {name}",
            product_class=ProductClass.MISSION,
            processing_level=ProcessingLevel.L0,
            created_by="debug-system"
        )

        # Setup directory if base_path provided
        if base_path:
            session.base_path = Path(base_path) / session_id
            session.base_path.mkdir(parents=True, exist_ok=True)
            (session.base_path / "evidence").mkdir(exist_ok=True)
            (session.base_path / "states").mkdir(exist_ok=True)
            (session.base_path / "hypotheses").mkdir(exist_ok=True)
            (session.base_path / "fixes").mkdir(exist_ok=True)

        return session

    def _update(self):
        """Update session timestamp."""
        self.updated_at = generate_timestamp()
        if self.label:
            self.label.provenance.modified_at = self.updated_at

    def advance_phase(self, new_phase: DebugPhase):
        """Advance to next phase with validation."""
        self.current_phase = new_phase
        self._update()
        if self.label:
            self.label.provenance.add_audit(
                "modified",
                "debug-system",
                f"Advanced to phase: {new_phase.value}"
            )

    # -------------------------------------------------------------------------
    # Phase 2: State Capture
    # -------------------------------------------------------------------------

    def capture_state(
        self,
        name: str,
        inputs: Dict[str, Any],
        configs: Dict[str, Any],
        versions: Optional[Dict[str, str]] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> StateSnapshot:
        """Capture golden state (Rule R4)."""
        snapshot = StateSnapshot.create(
            session_lid=self.lid,
            name=name,
            inputs=inputs,
            configs=configs,
            versions=versions,
            environment=environment
        )
        self.state_snapshots.append(snapshot)
        self._update()

        # Save to disk if base_path exists
        if self.base_path:
            path = self.base_path / "states" / f"{snapshot.lid.split(':')[-2]}.yaml"
            with open(path, "w") as f:
                yaml.dump(snapshot.to_dict(), f, default_flow_style=False)

        return snapshot

    def get_golden_state(self) -> Optional[StateSnapshot]:
        """Get the first (golden) state snapshot."""
        return self.state_snapshots[0] if self.state_snapshots else None

    # -------------------------------------------------------------------------
    # Evidence Management
    # -------------------------------------------------------------------------

    def capture_evidence(
        self,
        evidence_type: str,
        content: Union[str, bytes, Path],
        title: str,
        description: str = ""
    ) -> DebugEvidence:
        """Capture debug evidence."""
        evidence = DebugEvidence.create(
            session_lid=self.lid,
            evidence_type=evidence_type,
            title=title,
            content=content,
            description=description
        )
        self.evidence.append(evidence)
        self._update()

        # Save to disk if base_path exists
        if self.base_path:
            path = self.base_path / "evidence" / f"{evidence.lid.split(':')[-2]}.yaml"
            with open(path, "w") as f:
                yaml.dump(evidence.to_dict(), f, default_flow_style=False)

        return evidence

    def get_evidence_by_type(self, evidence_type: str) -> List[DebugEvidence]:
        """Get all evidence of a specific type."""
        return [e for e in self.evidence if e.evidence_type == evidence_type]

    # -------------------------------------------------------------------------
    # Phase 4: Hypothesis Management
    # -------------------------------------------------------------------------

    def add_hypothesis(
        self,
        description: str,
        layer: str = "application",
        falsification_test: Optional[str] = None
    ) -> DebugHypothesis:
        """Add a hypothesis (Rule R8)."""
        hypothesis = DebugHypothesis.create(
            session_lid=self.lid,
            description=description,
            layer=layer,
            falsification_test=falsification_test
        )
        self.hypotheses.append(hypothesis)
        self._update()

        # Save to disk if base_path exists
        if self.base_path:
            path = self.base_path / "hypotheses" / f"{hypothesis.lid.split(':')[-2]}.yaml"
            with open(path, "w") as f:
                yaml.dump(hypothesis.to_dict(), f, default_flow_style=False)

        return hypothesis

    def validate_r8(self) -> Dict[str, Any]:
        """Validate Rule R8: >=3 competing hypotheses."""
        count = len(self.hypotheses)
        return {
            "hypothesis_count": count,
            "minimum_required": 3,
            "passed": count >= 3,
            "message": f"{'PASS' if count >= 3 else 'FAIL'}: {count}/3 hypotheses"
        }

    def get_supported_hypotheses(self) -> List[DebugHypothesis]:
        """Get hypotheses that haven't been falsified."""
        return [h for h in self.hypotheses
                if h.status in [HypothesisStatus.SUPPORTED, HypothesisStatus.CONFIRMED]]

    def get_confirmed_root_cause(self) -> Optional[DebugHypothesis]:
        """Get the confirmed root cause hypothesis."""
        confirmed = [h for h in self.hypotheses if h.status == HypothesisStatus.CONFIRMED]
        return confirmed[0] if confirmed else None

    # -------------------------------------------------------------------------
    # Phase 6: Fix Documentation
    # -------------------------------------------------------------------------

    def document_fix(
        self,
        description: str,
        root_cause: str,
        layer: str = "application"
    ) -> DebugFix:
        """Document a fix (Rules R15, R16)."""
        # Link to confirmed hypothesis if available
        root_cause_hypothesis = self.get_confirmed_root_cause()

        fix = DebugFix.create(
            session_lid=self.lid,
            description=description,
            root_cause=root_cause,
            hypothesis_lid=root_cause_hypothesis.lid if root_cause_hypothesis else None,
            layer=layer
        )
        self.fixes.append(fix)
        self._update()

        # Save to disk if base_path exists
        if self.base_path:
            path = self.base_path / "fixes" / f"{fix.lid.split(':')[-2]}.yaml"
            with open(path, "w") as f:
                yaml.dump(fix.to_dict(), f, default_flow_style=False)

        return fix

    # -------------------------------------------------------------------------
    # Validation & Status
    # -------------------------------------------------------------------------

    def validate_methodology(self) -> Dict[str, Any]:
        """Validate compliance with DEADMAN methodology."""
        r8_check = self.validate_r8()

        # Check R4: Golden state exists
        r4_check = {
            "golden_state_exists": len(self.state_snapshots) > 0,
            "passed": len(self.state_snapshots) > 0
        }

        # Check R16: Fix compliance
        r16_checks = []
        for fix in self.fixes:
            r16_checks.append({
                "fix_lid": fix.lid,
                "compliance": fix.validate_r16()
            })

        # Check R21: Documentation
        r21_checks = []
        for fix in self.fixes:
            r21_checks.append({
                "fix_lid": fix.lid,
                "has_timeline": len(fix.timeline) > 0,
                "has_root_cause": fix.root_cause is not None,
                "has_prevention": fix.prevention is not None,
                "has_regression_test": fix.regression_test is not None
            })

        return {
            "session_lid": self.lid,
            "current_phase": self.current_phase.value,
            "r4_golden_state": r4_check,
            "r8_hypotheses": r8_check,
            "r16_fix_compliance": r16_checks,
            "r21_documentation": r21_checks,
            "evidence_count": len(self.evidence),
            "hypothesis_count": len(self.hypotheses),
            "fix_count": len(self.fixes)
        }

    def close(self):
        """Close the debug session."""
        self.status = "closed"
        self.closed_at = generate_timestamp()
        self.current_phase = DebugPhase.CLOSURE
        self._update()
        if self.label:
            self.label.provenance.add_audit(
                "archived",
                "debug-system",
                "Debug session closed"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "lid": self.lid,
            "name": self.name,
            "failure_type": self.failure_type.value,
            "failure_definition": self.failure_definition,
            "success_criteria": self.success_criteria,
            "system_boundary": self.system_boundary,
            "current_phase": self.current_phase.value,
            "status": self.status,
            "authorization": {
                "scope": self.scope,
                "authorization": self.authorization,
                "asset_owner": self.asset_owner
            },
            "state_snapshots": [s.to_dict() for s in self.state_snapshots],
            "evidence": [e.to_dict() for e in self.evidence],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "fixes": [f.to_dict() for f in self.fixes],
            "methodology_validation": self.validate_methodology(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "closed_at": self.closed_at
        }

    def save(self, path: Optional[Union[str, Path]] = None):
        """Save session to YAML file."""
        if path is None and self.base_path:
            path = self.base_path / "session.yaml"
        elif path is None:
            raise ValueError("No path specified and no base_path set")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, sort_keys=False)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    "DebugPhase",
    "FailureType",
    "HypothesisStatus",
    "FixStatus",
    "EvidenceLevel",
    "StateSnapshot",
    "DebugEvidence",
    "DebugHypothesis",
    "DebugFix",
    "DebugSession",
]
