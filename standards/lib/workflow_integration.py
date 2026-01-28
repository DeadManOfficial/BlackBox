"""
BlackBox Workflow Integration
Apply NASA-inspired standards to existing workflows

This module provides integration points between the data standards
and existing BlackBox functionality, enhancing without replacing.

Usage:
    from standards.lib.workflow_integration import (
        StandardizedMission,
        StandardizedFinding,
        wrap_tool_output,
        create_assessment_context
    )

    # Create a standardized mission
    mission = StandardizedMission.create(
        name="ACME Pentest Q1 2026",
        target_name="acme.com",
        mission_type="pentest"
    )

    # Wrap tool output with metadata
    labeled_output = wrap_tool_output(
        tool_name="nmap",
        output_file="/path/to/nmap.xml",
        mission=mission
    )
"""

import json
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field

from .data_standards import (
    Label,
    ProcessingLevel,
    ProductClass,
    Severity,
    FindingStatus,
    MissionStatus,
    ToolInfo,
    FileInfo,
    Reference,
    Provenance,
    generate_lid,
    generate_short_id,
    generate_timestamp,
    create_label,
    create_mission_structure,
    calculate_checksum,
    promote_processing_level,
)


# =============================================================================
# STANDARDIZED WRAPPERS
# =============================================================================

@dataclass
class StandardizedMission:
    """
    Wrapper to add NASA-inspired standards to mission data.

    This enhances existing mission structures with:
    - Logical identifiers
    - Processing level tracking
    - Provenance and audit trails
    - Standardized metadata
    """
    lid: str
    name: str
    mission_type: str
    status: MissionStatus
    target_lid: str
    target_name: str
    scope_lid: Optional[str] = None
    start_time: str = field(default_factory=generate_timestamp)
    end_time: Optional[str] = None
    assessments: List[str] = field(default_factory=list)  # Assessment LIDs
    label: Optional[Label] = None
    base_path: Optional[Path] = None

    @classmethod
    def create(
        cls,
        name: str,
        target_name: str,
        mission_type: str = "pentest",
        base_path: Optional[Union[str, Path]] = None
    ) -> "StandardizedMission":
        """
        Create a new standardized mission.

        Args:
            name: Mission name
            target_name: Primary target name
            mission_type: Type (pentest, bugbounty, audit, research)
            base_path: Optional base directory for mission files

        Returns:
            New StandardizedMission instance
        """
        # Generate identifiers
        short_id = generate_short_id()
        mission_id = f"{mission_type}-{name.lower().replace(' ', '-')}-{short_id}"
        mission_lid = generate_lid("mission", mission_id)
        target_lid = generate_lid("target", target_name.lower().replace(".", "-"))

        # Create instance
        mission = cls(
            lid=mission_lid,
            name=name,
            mission_type=mission_type,
            status=MissionStatus.PLANNING,
            target_lid=target_lid,
            target_name=target_name
        )

        # Create label
        mission.label = create_label(
            lid=mission_lid,
            title=name,
            product_class=ProductClass.MISSION,
            created_by="blackbox"
        )

        # Setup directory structure if base_path provided
        if base_path:
            mission.base_path = Path(base_path)
            create_mission_structure(base_path, mission_id)

        return mission

    def add_assessment(self, assessment_lid: str):
        """Add an assessment to this mission."""
        if assessment_lid not in self.assessments:
            self.assessments.append(assessment_lid)
            if self.label:
                self.label.provenance.add_audit(
                    "modified",
                    "system",
                    f"Added assessment: {assessment_lid}"
                )

    def set_status(self, status: MissionStatus, actor: str = "system"):
        """Update mission status."""
        old_status = self.status
        self.status = status
        if self.label:
            self.label.provenance.add_audit(
                "modified",
                actor,
                f"Status changed: {old_status.value} → {status.value}"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "lid": self.lid,
            "name": self.name,
            "mission_type": self.mission_type,
            "status": self.status.value,
            "target": {
                "lid": self.target_lid,
                "name": self.target_name
            },
            "scope_lid": self.scope_lid,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "assessments": self.assessments,
            "label": self.label.to_dict() if self.label else None
        }

    def save(self, path: Optional[Union[str, Path]] = None):
        """Save mission metadata."""
        if path is None and self.base_path:
            path = self.base_path / "mission.yaml"
        elif path is None:
            raise ValueError("No path specified and no base_path set")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)


@dataclass
class StandardizedFinding:
    """
    Wrapper to add NASA-inspired standards to findings.

    Enhances findings with:
    - Logical identifiers
    - Processing level tracking
    - Evidence chain management
    - Standardized severity mapping
    """
    lid: str
    title: str
    description: str
    severity: Severity
    status: FindingStatus
    assessment_lid: str
    processing_level: ProcessingLevel = ProcessingLevel.L0
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    evidence_lids: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    discovered_at: str = field(default_factory=generate_timestamp)
    label: Optional[Label] = None

    @classmethod
    def create(
        cls,
        title: str,
        description: str,
        severity: Union[Severity, str],
        assessment_lid: str,
        cvss_score: Optional[float] = None,
        cwe_id: Optional[str] = None
    ) -> "StandardizedFinding":
        """
        Create a new standardized finding.

        Args:
            title: Finding title
            description: Detailed description
            severity: Severity level
            assessment_lid: Parent assessment LID
            cvss_score: Optional CVSS score
            cwe_id: Optional CWE identifier

        Returns:
            New StandardizedFinding instance
        """
        # Normalize severity
        if isinstance(severity, str):
            severity = Severity(severity.lower())

        # Generate LID
        finding_id = f"{title.lower().replace(' ', '-')[:30]}-{generate_short_id()}"
        finding_lid = generate_lid("finding", finding_id)

        # Create instance
        finding = cls(
            lid=finding_lid,
            title=title,
            description=description,
            severity=severity,
            status=FindingStatus.NEW,
            assessment_lid=assessment_lid,
            cvss_score=cvss_score,
            cwe_id=cwe_id
        )

        # Create label
        finding.label = create_label(
            lid=finding_lid,
            title=title,
            product_class=ProductClass.FINDING,
            processing_level=ProcessingLevel.L0,
            created_by="blackbox"
        )

        return finding

    def add_evidence(self, evidence_lid: str):
        """Link evidence to this finding."""
        if evidence_lid not in self.evidence_lids:
            self.evidence_lids.append(evidence_lid)
            if self.label:
                self.label.internal_references.append(
                    Reference(lid=evidence_lid, type="child")
                )
                self.label.provenance.add_audit(
                    "modified",
                    "system",
                    f"Added evidence: {evidence_lid}"
                )

    def promote(self, new_level: ProcessingLevel, actor: str = "analyst"):
        """Promote finding to higher processing level."""
        self.processing_level = new_level
        if self.label:
            promote_processing_level(self.label, new_level, actor)

    def confirm(self, actor: str = "analyst"):
        """Confirm finding and promote to L3."""
        self.status = FindingStatus.CONFIRMED
        self.promote(ProcessingLevel.L3, actor)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "lid": self.lid,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "assessment_lid": self.assessment_lid,
            "processing_level": self.processing_level.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cwe_id": self.cwe_id,
            "evidence": self.evidence_lids,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at,
            "label": self.label.to_dict() if self.label else None
        }


# =============================================================================
# TOOL OUTPUT INTEGRATION
# =============================================================================

def wrap_tool_output(
    tool_name: str,
    output_file: Union[str, Path],
    mission: Optional[StandardizedMission] = None,
    assessment_lid: Optional[str] = None,
    tool_version: Optional[str] = None,
    parameters: Optional[str] = None,
    processing_level: ProcessingLevel = ProcessingLevel.L0
) -> Label:
    """
    Wrap tool output with standardized metadata.

    This creates a label for any tool output file, adding:
    - Logical identifier
    - Checksums for integrity
    - Tool execution context
    - Provenance tracking

    Args:
        tool_name: Name of the tool
        output_file: Path to output file
        mission: Optional parent mission
        assessment_lid: Optional parent assessment LID
        tool_version: Optional tool version
        parameters: Optional command parameters
        processing_level: Initial processing level

    Returns:
        Label for the tool output
    """
    output_path = Path(output_file)
    if not output_path.exists():
        raise FileNotFoundError(f"Output file not found: {output_file}")

    # Generate LID
    output_id = f"{tool_name}-{output_path.stem}-{generate_short_id()}"
    output_lid = generate_lid("tool-output", output_id)

    # Create label
    label = create_label(
        lid=output_lid,
        title=f"{tool_name} output: {output_path.name}",
        product_class=ProductClass.TOOL_EXECUTION,
        file_path=output_path,
        processing_level=processing_level,
        created_by=tool_name
    )

    # Add tool info
    label.tools.append(ToolInfo(
        name=tool_name,
        version=tool_version or "",
        parameters=parameters or ""
    ))

    # Link to mission/assessment
    if mission:
        label.mission_lid = mission.lid
        label.internal_references.append(
            Reference(lid=mission.lid, type="parent")
        )
    if assessment_lid:
        label.assessment_lid = assessment_lid
        label.internal_references.append(
            Reference(lid=assessment_lid, type="parent")
        )

    return label


def create_assessment_context(
    name: str,
    assessment_type: str,
    mission: StandardizedMission,
    tools: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Create standardized assessment context.

    Args:
        name: Assessment name
        assessment_type: Type (recon, scanning, exploitation, etc.)
        mission: Parent mission
        tools: List of tool names to be used

    Returns:
        Assessment context dictionary with LID and metadata
    """
    # Generate LID
    assessment_id = f"{assessment_type}-{generate_short_id()}"
    assessment_lid = generate_lid(
        "mission", mission.lid.split(":")[2],
        assessment_id
    )

    # Create label
    label = create_label(
        lid=assessment_lid,
        title=f"{name} - {assessment_type}",
        product_class=ProductClass.ASSESSMENT,
        processing_level=ProcessingLevel.L0,
        created_by="blackbox"
    )

    label.mission_lid = mission.lid
    label.internal_references.append(
        Reference(lid=mission.lid, type="parent")
    )

    # Add to mission
    mission.add_assessment(assessment_lid)

    return {
        "lid": assessment_lid,
        "name": name,
        "type": assessment_type,
        "mission_lid": mission.lid,
        "tools": tools or [],
        "processing_level": ProcessingLevel.L0.value,
        "label": label.to_dict(),
        "start_time": generate_timestamp(),
        "findings": [],
        "products": []
    }


# =============================================================================
# EVIDENCE CHAIN
# =============================================================================

def capture_evidence(
    evidence_type: str,
    content_or_path: Union[str, bytes, Path],
    finding: Optional[StandardizedFinding] = None,
    title: Optional[str] = None,
    description: Optional[str] = None
) -> Dict[str, Any]:
    """
    Capture and standardize evidence.

    Args:
        evidence_type: Type (screenshot, log, request, response, code)
        content_or_path: Evidence content or file path
        finding: Optional parent finding
        title: Evidence title
        description: Evidence description

    Returns:
        Evidence metadata dictionary
    """
    # Generate LID
    evidence_id = f"{evidence_type}-{generate_short_id()}"
    evidence_lid = generate_lid("evidence", evidence_id)

    # Handle content
    if isinstance(content_or_path, Path) or (isinstance(content_or_path, str) and Path(content_or_path).exists()):
        path = Path(content_or_path)
        checksum = calculate_checksum(path)
        file_info = FileInfo.from_file(path)
    else:
        # Content provided directly
        if isinstance(content_or_path, str):
            content_or_path = content_or_path.encode("utf-8")
        checksum = f"sha256:{__import__('hashlib').sha256(content_or_path).hexdigest()}"
        file_info = None

    # Create label
    label = create_label(
        lid=evidence_lid,
        title=title or f"Evidence: {evidence_type}",
        product_class=ProductClass.EVIDENCE,
        processing_level=ProcessingLevel.L1,  # Evidence starts at L1
        created_by="blackbox"
    )

    if finding:
        label.internal_references.append(
            Reference(lid=finding.lid, type="parent")
        )
        finding.add_evidence(evidence_lid)

    return {
        "lid": evidence_lid,
        "type": evidence_type,
        "title": title or f"Evidence: {evidence_type}",
        "description": description,
        "checksum": checksum,
        "file_info": file_info.__dict__ if file_info else None,
        "finding_lid": finding.lid if finding else None,
        "captured_at": generate_timestamp(),
        "label": label.to_dict()
    }


# =============================================================================
# WORKFLOW HELPERS
# =============================================================================

def apply_standards_to_existing(
    data: Dict[str, Any],
    product_class: ProductClass
) -> Dict[str, Any]:
    """
    Apply standards to existing data structure.

    This wraps existing data with standardized metadata
    without modifying the original structure.

    Args:
        data: Existing data dictionary
        product_class: Product class type

    Returns:
        Enhanced data with standards metadata
    """
    # Generate LID if not present
    if "lid" not in data:
        name = data.get("name", data.get("title", "unknown"))
        data["lid"] = generate_lid(
            product_class.value.lower(),
            f"{name.lower().replace(' ', '-')[:30]}-{generate_short_id()}"
        )

    # Add processing level if not present
    if "processing_level" not in data:
        data["processing_level"] = ProcessingLevel.L0.value

    # Add timestamps if not present
    if "created_at" not in data:
        data["created_at"] = generate_timestamp()

    # Add provenance wrapper
    if "_standards" not in data:
        data["_standards"] = {
            "version": "1.0.0",
            "product_class": product_class.value,
            "lid": data["lid"],
            "processing_level": data["processing_level"],
            "provenance": {
                "created_at": data["created_at"],
                "applied_standards_at": generate_timestamp()
            }
        }

    return data


__all__ = [
    "StandardizedMission",
    "StandardizedFinding",
    "wrap_tool_output",
    "create_assessment_context",
    "capture_evidence",
    "apply_standards_to_existing",
]
