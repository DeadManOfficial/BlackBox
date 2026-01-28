"""
BlackBox Data Standards
NASA PDS4-Inspired Data Management Framework

This package provides standardized data organization, labeling,
and workflow management inspired by NASA's Planetary Data System.

Core Concepts:
- Logical Identifiers (LID) for unique product identification
- Processing Levels (L0-L4) for data maturity tracking
- Standardized labels with provenance tracking
- Hierarchical organization (Mission > Assessment > Finding > Evidence)

Usage:
    from standards import (
        generate_lid,
        create_label,
        ProcessingLevel,
        ProductClass
    )

    # Create a mission
    lid = generate_lid("mission", "pentest-acme-2026")
    label = create_label(
        lid=lid,
        title="ACME Penetration Test 2026",
        product_class=ProductClass.MISSION
    )
"""

from pathlib import Path

# Package info
__version__ = "1.0.0"
__author__ = "BlackBox"

# Paths
STANDARDS_DIR = Path(__file__).parent
DICTIONARIES_DIR = STANDARDS_DIR / "dictionaries"
SCHEMAS_DIR = STANDARDS_DIR / "schemas"
LIB_DIR = STANDARDS_DIR / "lib"

# Import main components
try:
    from .lib.data_standards import (
        # Enums
        ProcessingLevel,
        ProductClass,
        Severity,
        FindingStatus,
        MissionStatus,
        # Data classes
        Checksum,
        FileInfo,
        Reference,
        AuditEntry,
        Provenance,
        ToolInfo,
        Label,
        # Functions
        generate_lid,
        generate_short_id,
        generate_timestamp,
        generate_file_timestamp,
        create_label,
        validate_lid,
        parse_lid,
        promote_processing_level,
        calculate_checksum,
        create_mission_structure,
        get_product_path,
        validate_label,
    )

    STANDARDS_AVAILABLE = True
except ImportError as e:
    STANDARDS_AVAILABLE = False
    _import_error = str(e)


def get_info() -> dict:
    """Get standards package information."""
    return {
        "version": __version__,
        "available": STANDARDS_AVAILABLE,
        "standards_dir": str(STANDARDS_DIR),
        "dictionaries": list(DICTIONARIES_DIR.glob("*.yaml")) if DICTIONARIES_DIR.exists() else [],
        "schemas": list(SCHEMAS_DIR.glob("*.yaml")) if SCHEMAS_DIR.exists() else [],
    }


def load_dictionary(name: str = "core") -> dict:
    """
    Load a data dictionary.

    Args:
        name: Dictionary name (without .yaml extension)

    Returns:
        Dictionary contents
    """
    import yaml

    dict_path = DICTIONARIES_DIR / f"{name}.yaml"
    if not dict_path.exists():
        raise FileNotFoundError(f"Dictionary not found: {name}")

    with open(dict_path) as f:
        return yaml.safe_load(f)


def load_schema(name: str = "label") -> dict:
    """
    Load a validation schema.

    Args:
        name: Schema name (without .schema.yaml extension)

    Returns:
        Schema contents
    """
    import yaml

    schema_path = SCHEMAS_DIR / f"{name}.schema.yaml"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found: {name}")

    with open(schema_path) as f:
        return yaml.safe_load(f)


__all__ = [
    # Version
    "__version__",
    # Paths
    "STANDARDS_DIR",
    "DICTIONARIES_DIR",
    "SCHEMAS_DIR",
    # Info
    "get_info",
    "load_dictionary",
    "load_schema",
    # Enums
    "ProcessingLevel",
    "ProductClass",
    "Severity",
    "FindingStatus",
    "MissionStatus",
    # Data classes
    "Checksum",
    "FileInfo",
    "Reference",
    "AuditEntry",
    "Provenance",
    "ToolInfo",
    "Label",
    # Functions
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
