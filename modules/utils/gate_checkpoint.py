#!/usr/bin/env python3
"""
Gate Checkpoint Manager
=======================
Manages context checkpoints between bounty gates to prevent token overflow.

Usage:
    from modules.utils.gate_checkpoint import GateCheckpoint

    # Initialize for target
    checkpoint = GateCheckpoint("viewcreator.ai")

    # Save gate results
    summary = checkpoint.save("GATE_1", {
        "findings": [...],
        "urls_mapped": 120,
        "status": "complete"
    })

    # Load previous gate (for next gate)
    prev_data = checkpoint.load("GATE_1")

    # Get summary only (for context)
    summary = checkpoint.get_summary("GATE_1")
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List


class GateCheckpoint:
    """Manages context checkpoints between bounty gates"""

    GATES = ["GATE_0", "GATE_1", "GATE_2", "GATE_3", "GATE_4", "GATE_5", "GATE_6"]

    def __init__(self, target: str, base_path: str = None):
        """
        Initialize checkpoint manager for a target.

        Args:
            target: Target domain/identifier
            base_path: Base path for targets (default: ~/BlackBox/targets)
        """
        self.target = target
        if base_path:
            self.base_path = Path(base_path).expanduser()
        else:
            self.base_path = Path.home() / "BlackBox" / "targets"

        self.target_path = self.base_path / target
        self.checkpoint_path = self.target_path / "checkpoints"
        self.checkpoint_path.mkdir(parents=True, exist_ok=True)

    def save(self, gate: str, data: Dict[str, Any]) -> str:
        """
        Save gate checkpoint and return context-friendly summary.

        Args:
            gate: Gate identifier (e.g., "GATE_1")
            data: Full gate data to save

        Returns:
            Short summary suitable for LLM context
        """
        # Add metadata
        checkpoint_data = {
            "gate": gate,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }

        # Save full data
        filepath = self.checkpoint_path / f"{gate}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(checkpoint_data, f, indent=2, default=str)

        # Generate summary
        summary = self._generate_summary(gate, data, filepath)

        # Save summary separately for quick access
        summary_path = self.checkpoint_path / f"{gate}_summary.txt"
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary)

        return summary

    def load(self, gate: str) -> Optional[Dict[str, Any]]:
        """
        Load full checkpoint data for a gate.

        Args:
            gate: Gate identifier

        Returns:
            Full checkpoint data or None if not found
        """
        filepath = self.checkpoint_path / f"{gate}.json"
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        return None

    def get_summary(self, gate: str) -> Optional[str]:
        """
        Get only the summary for a gate (token-efficient).

        Args:
            gate: Gate identifier

        Returns:
            Summary string or None if not found
        """
        summary_path = self.checkpoint_path / f"{gate}_summary.txt"
        if summary_path.exists():
            return summary_path.read_text()

        # Generate from full data if summary doesn't exist
        data = self.load(gate)
        if data:
            return self._generate_summary(gate, data.get("data", {}),
                                         self.checkpoint_path / f"{gate}.json")
        return None

    def get_all_summaries(self) -> str:
        """
        Get summaries for all completed gates.

        Returns:
            Combined summary string
        """
        summaries = []
        for gate in self.GATES:
            summary = self.get_summary(gate)
            if summary:
                summaries.append(summary)

        if summaries:
            return "\n---\n".join(summaries)
        return "No checkpoints found"

    def get_status(self) -> Dict[str, str]:
        """
        Get status of all gates.

        Returns:
            Dictionary of gate -> status
        """
        status = {}
        for gate in self.GATES:
            filepath = self.checkpoint_path / f"{gate}.json"
            if filepath.exists():
                status[gate] = "COMPLETE"
            else:
                status[gate] = "PENDING"
        return status

    def get_last_completed_gate(self) -> Optional[str]:
        """
        Get the last completed gate.

        Returns:
            Gate identifier or None
        """
        for gate in reversed(self.GATES):
            if (self.checkpoint_path / f"{gate}.json").exists():
                return gate
        return None

    def get_next_gate(self) -> Optional[str]:
        """
        Get the next gate to execute.

        Returns:
            Next gate identifier or None if all complete
        """
        last = self.get_last_completed_gate()
        if last is None:
            return self.GATES[0]

        idx = self.GATES.index(last)
        if idx < len(self.GATES) - 1:
            return self.GATES[idx + 1]
        return None

    def _generate_summary(self, gate: str, data: Dict[str, Any], filepath: Path) -> str:
        """Generate a token-efficient summary from gate data."""
        lines = [f"## {gate} COMPLETE"]
        lines.append(f"- Target: {self.target}")
        lines.append(f"- Path: {filepath}")

        # Extract key metrics
        if "findings" in data:
            findings = data["findings"]
            if isinstance(findings, list):
                lines.append(f"- Findings: {len(findings)}")
                # Show severity breakdown if available
                severities = {}
                for f in findings:
                    sev = f.get("severity", "INFO")
                    severities[sev] = severities.get(sev, 0) + 1
                if severities:
                    sev_str = ", ".join(f"{k}:{v}" for k, v in severities.items())
                    lines.append(f"- Severity: {sev_str}")

        if "urls_mapped" in data:
            lines.append(f"- URLs: {data['urls_mapped']}")

        if "endpoints" in data:
            endpoints = data["endpoints"]
            if isinstance(endpoints, list):
                lines.append(f"- Endpoints: {len(endpoints)}")

        if "status" in data:
            lines.append(f"- Status: {data['status']}")

        if "next_steps" in data:
            next_steps = data["next_steps"]
            if isinstance(next_steps, list) and next_steps:
                lines.append(f"- Next: {next_steps[0]}")

        return "\n".join(lines)

    def clear(self, gate: str = None):
        """
        Clear checkpoint(s).

        Args:
            gate: Specific gate to clear, or None for all
        """
        if gate:
            files = [
                self.checkpoint_path / f"{gate}.json",
                self.checkpoint_path / f"{gate}_summary.txt"
            ]
            for f in files:
                if f.exists():
                    f.unlink()
        else:
            for f in self.checkpoint_path.glob("*.json"):
                f.unlink()
            for f in self.checkpoint_path.glob("*.txt"):
                f.unlink()


class ContextManager:
    """
    Manages context across multiple operations to prevent overflow.
    Tracks token estimates and triggers checkpoints when needed.
    """

    # Rough estimate: 1 token ≈ 4 characters
    CHARS_PER_TOKEN = 4
    MAX_CONTEXT_TOKENS = 150000  # Leave headroom from 200K
    CHECKPOINT_THRESHOLD = 0.7  # Checkpoint at 70% capacity

    def __init__(self):
        self.current_tokens = 0
        self.operations = []

    def add_operation(self, content: str, operation_name: str = ""):
        """
        Track an operation's token usage.

        Args:
            content: Content that was added to context
            operation_name: Name of the operation for tracking
        """
        tokens = len(content) // self.CHARS_PER_TOKEN
        self.current_tokens += tokens
        self.operations.append({
            "name": operation_name,
            "tokens": tokens,
            "timestamp": datetime.now().isoformat()
        })

    def should_checkpoint(self) -> bool:
        """Check if we should checkpoint to prevent overflow."""
        return self.current_tokens >= (self.MAX_CONTEXT_TOKENS * self.CHECKPOINT_THRESHOLD)

    def get_usage(self) -> Dict[str, Any]:
        """Get current context usage statistics."""
        return {
            "current_tokens": self.current_tokens,
            "max_tokens": self.MAX_CONTEXT_TOKENS,
            "usage_percent": (self.current_tokens / self.MAX_CONTEXT_TOKENS) * 100,
            "should_checkpoint": self.should_checkpoint(),
            "operations": len(self.operations)
        }

    def reset(self):
        """Reset context tracking (after checkpoint)."""
        self.current_tokens = 0
        self.operations = []


# Convenience functions
def checkpoint(target: str, gate: str, data: Dict) -> str:
    """Quick checkpoint function."""
    cp = GateCheckpoint(target)
    return cp.save(gate, data)


def load_checkpoint(target: str, gate: str) -> Optional[Dict]:
    """Quick load function."""
    cp = GateCheckpoint(target)
    return cp.load(gate)


def get_summary(target: str, gate: str) -> Optional[str]:
    """Quick summary function."""
    cp = GateCheckpoint(target)
    return cp.get_summary(gate)


if __name__ == "__main__":
    # Test
    print("Testing GateCheckpoint...")

    cp = GateCheckpoint("test_target")

    # Save test checkpoint
    summary = cp.save("GATE_1", {
        "findings": [
            {"id": "F1", "severity": "HIGH", "title": "Test Finding 1"},
            {"id": "F2", "severity": "MEDIUM", "title": "Test Finding 2"},
        ],
        "urls_mapped": 50,
        "status": "complete",
        "next_steps": ["Continue to GATE_2"]
    })

    print("Summary:")
    print(summary)
    print()

    print("Status:", cp.get_status())
    print("Last completed:", cp.get_last_completed_gate())
    print("Next gate:", cp.get_next_gate())

    # Cleanup
    cp.clear()
    print("\nTest complete, checkpoints cleared.")
