"""
BlackBox Data Standards Library
NASA PDS4-Inspired Data Management

This module provides utilities for creating, validating, and managing
data products according to BlackBox Data Standards.

Usage:
    from standards.lib.data_standards import (
        generate_lid,
        create_label,
        validate_label,
        ProcessingLevel,
        ProductClass
    )

    # Generate a logical identifier
    lid = generate_lid("mission", "pentest-acme", version="1.0")

    # Create a product label
    label = create_label(
        lid=lid,
        title="ACME Penetration Test",
        product_class=ProductClass.MISSION,
        file_name="mission.yaml"
    )
"""

import hashlib
import json
import yaml
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict


# =============================================================================
# ENUMERATIONS
# =============================================================================

class ProcessingLevel(Enum):
    """Data processing levels (NASA-inspired)"""
    L0 = "L0"  # Raw - Unprocessed tool output
    L1 = "L1"  # Validated - Verified and deduplicated
    L2 = "L2"  # Enriched - Correlated with context
    L3 = "L3"  # Analyzed - Expert-reviewed
    L4 = "L4"  # Actionable - Remediation-ready


class ProductClass(Enum):
    """Product class types"""
    MISSION = "Mission"
    ASSESSMENT = "Assessment"
    FINDING = "Finding"
    EVIDENCE = "Evidence"
    TARGET = "Target"
    SCOPE = "Scope"
    TOOL_EXECUTION = "ToolExecution"
    REPORT = "Report"
    CONTEXT = "Context"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(Enum):
    """Finding status values"""
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    WONTFIX = "wontfix"


class MissionStatus(Enum):
    """Mission lifecycle states"""
    PLANNING = "planning"
    SCOPING = "scoping"
    ACTIVE = "active"
    PAUSED = "paused"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Checksum:
    """File integrity checksum"""
    type: str = "SHA-256"
    value: str = ""

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "Checksum":
        """Calculate checksum from file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)

        return cls(type="SHA-256", value=sha256.hexdigest())

    @classmethod
    def from_content(cls, content: Union[str, bytes]) -> "Checksum":
        """Calculate checksum from content"""
        if isinstance(content, str):
            content = content.encode("utf-8")
        return cls(type="SHA-256", value=hashlib.sha256(content).hexdigest())


@dataclass
class FileInfo:
    """File area information"""
    name: str
    size: int = 0
    checksum: Checksum = field(default_factory=Checksum)
    format: str = ""
    encoding: str = "UTF-8"

    @classmethod
    def from_file(cls, file_path: Union[str, Path]) -> "FileInfo":
        """Create FileInfo from actual file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        return cls(
            name=path.name,
            size=path.stat().st_size,
            checksum=Checksum.from_file(path),
            format=path.suffix.upper().lstrip(".") or "UNKNOWN"
        )


@dataclass
class Reference:
    """Internal or external reference"""
    lid: str = ""
    type: str = "related"  # parent, child, related, derived, supersedes
    description: str = ""


@dataclass
class AuditEntry:
    """Audit trail entry"""
    action: str  # created, modified, validated, promoted, archived
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    actor: str = "system"
    details: str = ""


@dataclass
class Provenance:
    """Data provenance tracking"""
    created_by: str = "blackbox"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    modified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    audit_trail: List[AuditEntry] = field(default_factory=list)

    def add_audit(self, action: str, actor: str = "system", details: str = ""):
        """Add audit trail entry"""
        self.audit_trail.append(AuditEntry(
            action=action,
            actor=actor,
            details=details
        ))
        self.modified_at = datetime.now(timezone.utc).isoformat()


@dataclass
class ToolInfo:
    """Tool execution information"""
    name: str
    version: str = ""
    parameters: str = ""


@dataclass
class Label:
    """Complete product label structure"""
    # Identification
    lid: str
    version: str = "1.0"
    title: str = ""
    product_class: str = ""

    # Observation
    mission_lid: Optional[str] = None
    assessment_lid: Optional[str] = None
    target_lid: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    processing_level: str = "L0"

    # Context
    tools: List[ToolInfo] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)

    # File
    file_info: Optional[FileInfo] = None

    # References
    internal_references: List[Reference] = field(default_factory=list)
    external_references: List[Dict[str, str]] = field(default_factory=list)

    # Provenance
    provenance: Provenance = field(default_factory=Provenance)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "identification_area": {
                "lid": self.lid,
                "version": self.version,
                "title": self.title,
                "product_class": self.product_class
            },
            "observation_area": {
                k: v for k, v in {
                    "mission_lid": self.mission_lid,
                    "assessment_lid": self.assessment_lid,
                    "target_lid": self.target_lid,
                    "start_time": self.start_time,
                    "end_time": self.end_time,
                    "processing_level": self.processing_level
                }.items() if v is not None
            },
            "context_area": {
                "tools": [asdict(t) for t in self.tools] if self.tools else [],
                "environment": self.environment
            },
            "file_area": {
                "file": asdict(self.file_info) if self.file_info else {}
            },
            "reference_list": {
                "internal_references": [asdict(r) for r in self.internal_references],
                "external_references": self.external_references
            },
            "provenance": {
                "created_by": self.provenance.created_by,
                "created_at": self.provenance.created_at,
                "modified_at": self.provenance.modified_at,
                "audit_trail": [asdict(a) for a in self.provenance.audit_trail]
            }
        }

    def to_yaml(self) -> str:
        """Serialize to YAML"""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps(self.to_dict(), indent=2)

    def save(self, path: Union[str, Path], format: str = "yaml"):
        """Save label to file"""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        content = self.to_yaml() if format == "yaml" else self.to_json()
        path.write_text(content)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_lid(
    namespace: str,
    identifier: str,
    *path_segments: str,
    version: str = "1.0"
) -> str:
    """
    Generate a Logical Identifier (LID).

    Format: urn:blackbox:{namespace}:{identifier}[:{segments}]::version

    Args:
        namespace: Top-level namespace (mission, finding, evidence, etc.)
        identifier: Unique identifier within namespace
        path_segments: Optional path segments
        version: Version string (default: "1.0")

    Returns:
        Complete LID string

    Example:
        >>> generate_lid("mission", "pentest-acme", version="1.0")
        'urn:blackbox:mission:pentest-acme::1.0'

        >>> generate_lid("mission", "pentest-acme", "recon", "nmap-001")
        'urn:blackbox:mission:pentest-acme:recon:nmap-001::1.0'
    """
    parts = ["urn", "blackbox", namespace, identifier]
    parts.extend(path_segments)
    base = ":".join(parts)
    return f"{base}::{version}"


def generate_short_id() -> str:
    """Generate a short unique identifier"""
    return uuid.uuid4().hex[:8]


def generate_timestamp() -> str:
    """Generate ISO 8601 timestamp"""
    return datetime.now(timezone.utc).isoformat()


def generate_file_timestamp() -> str:
    """Generate filename-safe timestamp"""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def create_label(
    lid: str,
    title: str,
    product_class: Union[ProductClass, str],
    file_name: Optional[str] = None,
    file_path: Optional[Union[str, Path]] = None,
    processing_level: Union[ProcessingLevel, str] = ProcessingLevel.L0,
    created_by: str = "blackbox"
) -> Label:
    """
    Create a new product label.

    Args:
        lid: Logical identifier
        title: Human-readable title
        product_class: Product class type
        file_name: Optional file name (if no file_path)
        file_path: Optional path to actual file
        processing_level: Data processing level
        created_by: Creator identifier

    Returns:
        New Label instance
    """
    # Normalize enums
    if isinstance(product_class, ProductClass):
        product_class = product_class.value
    if isinstance(processing_level, ProcessingLevel):
        processing_level = processing_level.value

    # Extract version from LID
    version = lid.split("::")[-1] if "::" in lid else "1.0"

    # Create file info
    file_info = None
    if file_path:
        file_info = FileInfo.from_file(file_path)
    elif file_name:
        file_info = FileInfo(name=file_name)

    # Create label
    label = Label(
        lid=lid,
        version=version,
        title=title,
        product_class=product_class,
        processing_level=processing_level,
        file_info=file_info,
        provenance=Provenance(created_by=created_by)
    )

    # Add creation audit entry
    label.provenance.add_audit("created", created_by, f"Created {product_class}: {title}")

    return label


def validate_lid(lid: str) -> bool:
    """
    Validate a Logical Identifier format.

    Args:
        lid: LID to validate

    Returns:
        True if valid, False otherwise
    """
    import re
    pattern = r"^urn:blackbox:[a-z0-9-]+(?::[a-z0-9-]+)*::[0-9]+\.[0-9]+$"
    return bool(re.match(pattern, lid))


def parse_lid(lid: str) -> Dict[str, str]:
    """
    Parse a LID into its components.

    Args:
        lid: LID to parse

    Returns:
        Dictionary with namespace, identifier, path, version
    """
    if not validate_lid(lid):
        raise ValueError(f"Invalid LID format: {lid}")

    # Split off version
    base, version = lid.rsplit("::", 1)

    # Remove urn:blackbox: prefix
    parts = base.replace("urn:blackbox:", "").split(":")

    return {
        "namespace": parts[0],
        "identifier": parts[1] if len(parts) > 1 else "",
        "path": parts[2:] if len(parts) > 2 else [],
        "version": version,
        "full": lid
    }


def promote_processing_level(
    label: Label,
    new_level: Union[ProcessingLevel, str],
    actor: str = "system",
    details: str = ""
) -> Label:
    """
    Promote a product to a higher processing level.

    Args:
        label: Label to promote
        new_level: Target processing level
        actor: Who is promoting
        details: Promotion details

    Returns:
        Updated label
    """
    if isinstance(new_level, ProcessingLevel):
        new_level = new_level.value

    current = label.processing_level
    levels = ["L0", "L1", "L2", "L3", "L4"]

    if levels.index(new_level) <= levels.index(current):
        raise ValueError(f"Cannot demote from {current} to {new_level}")

    label.processing_level = new_level
    label.provenance.add_audit(
        "promoted",
        actor,
        details or f"Promoted from {current} to {new_level}"
    )

    return label


def calculate_checksum(file_path: Union[str, Path]) -> str:
    """Calculate SHA-256 checksum for a file"""
    return Checksum.from_file(file_path).value


# =============================================================================
# DIRECTORY STRUCTURE HELPERS
# =============================================================================

def create_mission_structure(
    base_path: Union[str, Path],
    mission_id: str
) -> Dict[str, Path]:
    """
    Create NASA-inspired mission directory structure.

    Args:
        base_path: Base directory for missions
        mission_id: Mission identifier

    Returns:
        Dictionary of created paths
    """
    base = Path(base_path)
    mission_path = base / mission_id

    paths = {
        "root": mission_path,
        "assessments": mission_path / "assessments",
        "findings": mission_path / "findings",
        "reports": mission_path / "reports",
        "context": mission_path / "context",
        "evidence": mission_path / "evidence"
    }

    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)

    return paths


def get_product_path(
    base_path: Union[str, Path],
    lid: str
) -> Path:
    """
    Get filesystem path for a product based on its LID.

    Args:
        base_path: Base directory
        lid: Product LID

    Returns:
        Path to product directory
    """
    parsed = parse_lid(lid)
    base = Path(base_path)

    # Build path from LID components
    parts = [parsed["namespace"], parsed["identifier"]] + parsed["path"]
    return base.joinpath(*parts)


# =============================================================================
# VALIDATION HELPERS
# =============================================================================

def validate_label(label: Union[Label, Dict[str, Any]]) -> List[str]:
    """
    Validate a label against the schema.

    Args:
        label: Label to validate

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    # Convert to dict if needed
    if isinstance(label, Label):
        data = label.to_dict()
    else:
        data = label

    # Check required fields
    required_sections = ["identification_area", "file_area", "provenance"]
    for section in required_sections:
        if section not in data:
            errors.append(f"Missing required section: {section}")

    # Check identification area
    if "identification_area" in data:
        id_area = data["identification_area"]
        for field in ["lid", "version", "title", "product_class"]:
            if field not in id_area or not id_area[field]:
                errors.append(f"Missing required field: identification_area.{field}")

        # Validate LID format
        if "lid" in id_area and not validate_lid(id_area["lid"]):
            errors.append(f"Invalid LID format: {id_area['lid']}")

    # Check provenance
    if "provenance" in data:
        prov = data["provenance"]
        for field in ["created_by", "created_at"]:
            if field not in prov or not prov[field]:
                errors.append(f"Missing required field: provenance.{field}")

    return errors


# =============================================================================
# MODULE INFO
# =============================================================================

__version__ = "1.0.0"
__all__ = [
    "ProcessingLevel",
    "ProductClass",
    "Severity",
    "FindingStatus",
    "MissionStatus",
    "Checksum",
    "FileInfo",
    "Reference",
    "AuditEntry",
    "Provenance",
    "ToolInfo",
    "Label",
    "generate_lid",
    "generate_short_id",
    "generate_timestamp",
    "generate_file_timestamp",
    "create_label",
    "validate_lid",
    "parse_lid",
    "promote_processing_level",
    "calculate_checksum",
    "create_mission_structure",
    "get_product_path",
    "validate_label",
]
