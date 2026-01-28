"""
JSON Repair Utility for AI Agent Outputs
Based on ai-json-cleanroom patterns
Handles malformed JSON from LLM responses
"""

import re
import json
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class JSONResult:
    """Result of JSON validation/repair"""
    json_valid: bool
    data: Optional[Any] = None
    errors: List[str] = None
    was_repaired: bool = False
    truncated: bool = False
    raw_extracted: Optional[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


def extract_json_from_text(text: str) -> Tuple[Optional[str], bool]:
    """
    Extract JSON from markdown code blocks or plain text.
    Returns (json_string, was_in_code_block)
    """
    # Try markdown code block first
    code_block_patterns = [
        r'```json\s*([\s\S]*?)\s*```',
        r'```\s*([\s\S]*?)\s*```',
        r'`([\s\S]*?)`',
    ]

    for pattern in code_block_patterns:
        match = re.search(pattern, text)
        if match:
            extracted = match.group(1).strip()
            if extracted.startswith('{') or extracted.startswith('['):
                return extracted, True

    # Try to find raw JSON
    # Look for object
    obj_match = re.search(r'(\{[\s\S]*\})', text)
    if obj_match:
        return obj_match.group(1), False

    # Look for array
    arr_match = re.search(r'(\[[\s\S]*\])', text)
    if arr_match:
        return arr_match.group(1), False

    return None, False


def detect_truncation(json_str: str) -> bool:
    """
    Detect if JSON was truncated (incomplete output).
    """
    # Count brackets
    open_braces = json_str.count('{')
    close_braces = json_str.count('}')
    open_brackets = json_str.count('[')
    close_brackets = json_str.count(']')

    if open_braces != close_braces or open_brackets != close_brackets:
        return True

    # Check for suspicious trailing patterns
    suspicious_endings = ['...', '…', ', ', ': ', '": ', '":', ',']
    stripped = json_str.rstrip()
    for ending in suspicious_endings:
        if stripped.endswith(ending):
            return True

    return False


def repair_json(json_str: str) -> Tuple[str, List[str]]:
    """
    Apply conservative repairs to malformed JSON.
    Returns (repaired_string, list_of_repairs_made)
    """
    repairs = []
    result = json_str

    # 1. Replace Python constants with JSON equivalents
    python_to_json = [
        (r'\bTrue\b', 'true', 'Replaced True with true'),
        (r'\bFalse\b', 'false', 'Replaced False with false'),
        (r'\bNone\b', 'null', 'Replaced None with null'),
    ]

    for pattern, replacement, description in python_to_json:
        if re.search(pattern, result):
            result = re.sub(pattern, replacement, result)
            repairs.append(description)

    # 2. Convert single quotes to double quotes (careful with nested)
    # Only do this if no double quotes exist around keys/values
    if "'" in result and '"' not in result:
        result = result.replace("'", '"')
        repairs.append('Converted single quotes to double quotes')

    # 3. Add quotes to unquoted keys
    unquoted_key = r'([{,]\s*)(\w+)(\s*:)'
    if re.search(unquoted_key, result):
        result = re.sub(unquoted_key, r'\1"\2"\3', result)
        repairs.append('Added quotes to unquoted keys')

    # 4. Remove trailing commas before } or ]
    trailing_comma = r',(\s*[}\]])'
    if re.search(trailing_comma, result):
        result = re.sub(trailing_comma, r'\1', result)
        repairs.append('Removed trailing commas')

    # 5. Remove single-line comments
    single_comment = r'//[^\n]*'
    if re.search(single_comment, result):
        result = re.sub(single_comment, '', result)
        repairs.append('Removed single-line comments')

    # 6. Remove multi-line comments
    multi_comment = r'/\*[\s\S]*?\*/'
    if re.search(multi_comment, result):
        result = re.sub(multi_comment, '', result)
        repairs.append('Removed multi-line comments')

    # 7. Fix common escape issues
    # Unescaped quotes inside strings - basic fix
    # This is tricky, only do simple cases

    return result, repairs


def validate_ai_json(
    response: str,
    schema: Optional[Dict] = None,
    expected_keys: Optional[List[str]] = None
) -> JSONResult:
    """
    Validate and repair JSON from AI response.

    Args:
        response: Raw AI response text
        schema: Optional JSON schema for validation
        expected_keys: Optional list of required top-level keys

    Returns:
        JSONResult with parsed data or error details
    """
    result = JSONResult(json_valid=False)

    # Extract JSON from text
    json_str, was_in_block = extract_json_from_text(response)

    if json_str is None:
        result.errors.append('No JSON found in response')
        return result

    result.raw_extracted = json_str

    # Check for truncation
    if detect_truncation(json_str):
        result.truncated = True
        result.errors.append('JSON appears to be truncated (incomplete output)')

    # Try parsing as-is first
    try:
        result.data = json.loads(json_str)
        result.json_valid = True
    except json.JSONDecodeError as e:
        # Try repairs
        repaired, repairs_made = repair_json(json_str)

        try:
            result.data = json.loads(repaired)
            result.json_valid = True
            result.was_repaired = True
            result.errors.extend([f'Repair: {r}' for r in repairs_made])
        except json.JSONDecodeError as e2:
            result.errors.append(f'JSON parse error: {str(e2)}')
            result.errors.append(f'Original error: {str(e)}')

    # Validate expected keys if provided
    if result.json_valid and expected_keys and isinstance(result.data, dict):
        missing = [k for k in expected_keys if k not in result.data]
        if missing:
            result.errors.append(f'Missing expected keys: {missing}')

    # Schema validation would go here if jsonschema is available

    return result


def safe_json_loads(text: str, default: Any = None) -> Any:
    """
    Convenience function for simple JSON parsing with repair.
    Returns default if parsing fails.
    """
    result = validate_ai_json(text)
    return result.data if result.json_valid else default


# Agent output schemas for Pentest Mission Control
VULNERABILITY_SCHEMA = {
    "required": ["severity", "title", "description"],
    "optional": ["cvss_score", "cve_id", "remediation", "evidence"]
}

SCAN_RESULT_SCHEMA = {
    "required": ["status", "findings"],
    "optional": ["target", "duration", "agent_id"]
}


def parse_agent_output(response: str, output_type: str = "vulnerability") -> JSONResult:
    """
    Parse agent output with type-specific validation.
    """
    schemas = {
        "vulnerability": VULNERABILITY_SCHEMA,
        "scan_result": SCAN_RESULT_SCHEMA,
    }

    schema = schemas.get(output_type, {})
    expected_keys = schema.get("required", [])

    return validate_ai_json(response, expected_keys=expected_keys)
