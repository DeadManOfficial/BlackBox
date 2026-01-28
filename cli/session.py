#!/usr/bin/env python3
"""
BlackBox AI - Session Manager
==============================

Track pentest sessions, progress through phases, and collected data.
"""

import os
import re
import yaml
import json
import shutil
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from enum import Enum

# Session ID validation pattern (security fix)
SESSION_ID_PATTERN = re.compile(r'^sess_[a-zA-Z0-9_-]+$')

# Phase key constants
PHASE_KEYS = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6']

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn
from rich import box

console = Console()

DATA_DIR = Path(__file__).parent.parent / "data"
SESSIONS_DIR = DATA_DIR / "sessions"


class Phase(Enum):
    """Pentest phases."""
    P1_RECON = "P1 - Reconnaissance"
    P2_SCANNING = "P2 - Scanning"
    P3_ASSESSMENT = "P3 - Assessment"
    P4_EXPLOITATION = "P4 - Exploitation"
    P5_FORENSIC = "P5 - Forensic"
    P6_ADVANCED = "P6 - Advanced"
    COMPLETE = "Complete"

    @classmethod
    def get_phase_display_name(cls, phase_key: str) -> str:
        """Get display name for a phase key (P1, P2, etc.)."""
        phase_mapping = {
            'P1': 'Reconnaissance',
            'P2': 'Scanning',
            'P3': 'Assessment',
            'P4': 'Exploitation',
            'P5': 'Forensic',
            'P6': 'Advanced'
        }
        return phase_mapping.get(phase_key, 'Unknown')


@dataclass
class SessionTarget:
    """Target being tested in a session."""
    name: str
    url: str = ""
    ip: str = ""
    scope_asset: str = ""
    notes: str = ""
    status: str = "pending"


@dataclass
class SessionData:
    """Pentest session data."""
    id: str
    name: str
    created_at: str
    updated_at: str
    current_phase: str = "P1 - Reconnaissance"
    targets: List[Dict] = field(default_factory=list)
    findings_count: int = 0
    phase_progress: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    scope_reference: str = ""

    def __post_init__(self):
        if not self.phase_progress:
            self.phase_progress = {
                "P1": "pending",
                "P2": "pending",
                "P3": "pending",
                "P4": "pending",
                "P5": "pending",
                "P6": "pending"
            }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionData':
        return cls(**data)


class SessionManager:
    """Manages pentest sessions."""

    def __init__(self):
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self.sessions: Dict[str, SessionData] = {}
        self._load_sessions()

    def _load_sessions(self):
        """Load all sessions from disk."""
        for session_dir in SESSIONS_DIR.iterdir():
            if session_dir.is_dir():
                session_file = session_dir / "session.yaml"
                if session_file.exists():
                    with open(session_file, 'r') as f:
                        data = yaml.safe_load(f)
                        if data:
                            self.sessions[data['id']] = SessionData.from_dict(data)

    def _save_session(self, session: SessionData):
        """Save session to disk."""
        session_dir = SESSIONS_DIR / session.id
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (session_dir / "evidence").mkdir(exist_ok=True)
        (session_dir / "notes").mkdir(exist_ok=True)
        (session_dir / "scans").mkdir(exist_ok=True)

        session_file = session_dir / "session.yaml"
        session.updated_at = datetime.now().isoformat()

        with open(session_file, 'w') as f:
            yaml.dump(session.to_dict(), f, default_flow_style=False)

    def create_session(self, name: str, targets: List[str] = None) -> SessionData:
        """Create a new pentest session."""
        session_id = f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        session = SessionData(
            id=session_id,
            name=name,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            targets=[{"name": t, "status": "pending"} for t in (targets or [])]
        )

        self.sessions[session_id] = session
        self._save_session(session)

        console.print(f"[green]✓ Session created: {session_id}[/green]")
        return session

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[SessionData]:
        """List all sessions."""
        return list(self.sessions.values())

    def update_phase(self, session_id: str, phase: str, status: str = "in_progress") -> bool:
        """Update session phase status."""
        session = self.get_session(session_id)
        if not session:
            return False

        phase_key = phase.split()[0] if ' ' in phase else phase
        session.phase_progress[phase_key] = status

        if status == "complete":
            # Move to next phase
            current_idx = PHASE_KEYS.index(phase_key) if phase_key in PHASE_KEYS else -1
            if current_idx < len(PHASE_KEYS) - 1:
                next_phase = PHASE_KEYS[current_idx + 1]
                phase_name = Phase.get_phase_display_name(next_phase)
                session.current_phase = f"{next_phase} - {phase_name}"
            else:
                session.current_phase = "Complete"
        else:
            session.current_phase = phase

        self._save_session(session)
        return True

    def add_target(self, session_id: str, target: Dict[str, str]) -> bool:
        """Add target to session."""
        session = self.get_session(session_id)
        if not session:
            return False

        session.targets.append(target)
        self._save_session(session)
        return True

    def add_note(self, session_id: str, note: str, phase: str = None) -> bool:
        """Add note to session."""
        session = self.get_session(session_id)
        if not session:
            return False

        timestamp = datetime.now().isoformat()
        note_entry = f"\n[{timestamp}] {phase or session.current_phase}: {note}"
        session.notes += note_entry

        # Also save to notes file
        notes_dir = SESSIONS_DIR / session_id / "notes"
        notes_file = notes_dir / f"notes_{datetime.now().strftime('%Y%m%d')}.md"

        with open(notes_file, 'a') as f:
            f.write(f"\n## {timestamp}\n**Phase:** {phase or session.current_phase}\n\n{note}\n\n---\n")

        self._save_session(session)
        return True

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        # Security: Validate session_id format to prevent path traversal
        if not SESSION_ID_PATTERN.match(session_id):
            console.print(f"[red]Invalid session ID format: {session_id}[/red]")
            return False

        if session_id not in self.sessions:
            return False

        session_dir = SESSIONS_DIR / session_id
        # Additional security check: ensure path is within SESSIONS_DIR
        try:
            session_dir.resolve().relative_to(SESSIONS_DIR.resolve())
        except ValueError:
            console.print(f"[red]Security error: Invalid session path[/red]")
            return False

        if session_dir.exists():
            shutil.rmtree(session_dir)

        del self.sessions[session_id]
        return True

    def display_session(self, session: SessionData):
        """Display session details."""
        # Calculate progress
        completed = sum(1 for s in session.phase_progress.values() if s == "complete")
        total = len(session.phase_progress)
        progress_pct = (completed / total) * 100

        console.print(Panel(
            f"[bold]{session.name}[/bold]\n\n"
            f"ID: [cyan]{session.id}[/cyan]\n"
            f"Created: {session.created_at[:19]}\n"
            f"Current Phase: [yellow]{session.current_phase}[/yellow]\n"
            f"Progress: {completed}/{total} phases ({progress_pct:.0f}%)\n"
            f"Targets: {len(session.targets)}\n"
            f"Findings: {session.findings_count}",
            title="Session Details",
            border_style="blue"
        ))

        # Phase progress
        table = Table(title="Phase Progress", box=box.ROUNDED)
        table.add_column("Phase", style="cyan", width=25)
        table.add_column("Status", width=15)
        table.add_column("", width=20)

        phase_names = {
            "P1": "Reconnaissance",
            "P2": "Scanning",
            "P3": "Assessment",
            "P4": "Exploitation",
            "P5": "Forensic Analysis",
            "P6": "Advanced"
        }

        for phase, status in session.phase_progress.items():
            status_color = {
                "pending": "dim",
                "in_progress": "yellow",
                "complete": "green"
            }.get(status, "white")

            status_icon = {
                "pending": "○",
                "in_progress": "◐",
                "complete": "●"
            }.get(status, "?")

            table.add_row(
                f"{phase} - {phase_names.get(phase, '')}",
                f"[{status_color}]{status.upper()}[/{status_color}]",
                f"[{status_color}]{status_icon}[/{status_color}]"
            )

        console.print(table)

        # Targets
        if session.targets:
            target_table = Table(title="Targets", box=box.SIMPLE)
            target_table.add_column("Name", style="cyan")
            target_table.add_column("URL/IP", style="dim")
            target_table.add_column("Status")

            for t in session.targets:
                target_table.add_row(
                    t.get('name', 'Unknown'),
                    t.get('url', t.get('ip', 'N/A')),
                    t.get('status', 'pending').upper()
                )

            console.print(target_table)

    def display_sessions_list(self):
        """Display all sessions."""
        if not self.sessions:
            console.print("[yellow]No sessions found.[/yellow]")
            return

        table = Table(title="Pentest Sessions", box=box.ROUNDED)
        table.add_column("ID", style="cyan", width=25)
        table.add_column("Name", style="white", width=30)
        table.add_column("Phase", style="yellow", width=20)
        table.add_column("Progress", width=12)
        table.add_column("Created", style="dim", width=12)

        for session in sorted(self.sessions.values(), key=lambda s: s.created_at, reverse=True):
            completed = sum(1 for s in session.phase_progress.values() if s == "complete")
            total = len(session.phase_progress)

            table.add_row(
                session.id,
                session.name[:28] + ('...' if len(session.name) > 28 else ''),
                session.current_phase.split(' - ')[0],
                f"{completed}/{total}",
                session.created_at[:10]
            )

        console.print(table)


class EvidenceCollector:
    """Collect and manage evidence for findings."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.evidence_dir = SESSIONS_DIR / session_id / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def save_request_response(self, name: str, request: str, response: str, notes: str = "") -> str:
        """Save HTTP request/response as evidence."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{name.replace(' ', '_')}.txt"
        filepath = self.evidence_dir / filename

        content = f"""# Evidence: {name}
# Captured: {datetime.now().isoformat()}
# Session: {self.session_id}

## Request
```
{request}
```

## Response
```
{response}
```

## Notes
{notes}
"""
        with open(filepath, 'w') as f:
            f.write(content)

        console.print(f"[green]✓ Evidence saved: {filename}[/green]")
        return str(filepath)

    def save_screenshot(self, name: str, image_path: str) -> str:
        """Copy screenshot to evidence directory."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ext = Path(image_path).suffix
        filename = f"{timestamp}_{name.replace(' ', '_')}{ext}"
        filepath = self.evidence_dir / filename

        shutil.copy(image_path, filepath)
        console.print(f"[green]✓ Screenshot saved: {filename}[/green]")
        return str(filepath)

    def save_output(self, name: str, tool: str, output: str) -> str:
        """Save tool output as evidence."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{tool}_{name.replace(' ', '_')}.txt"
        filepath = self.evidence_dir / filename

        content = f"""# Tool Output: {tool}
# Evidence: {name}
# Captured: {datetime.now().isoformat()}

{output}
"""
        with open(filepath, 'w') as f:
            f.write(content)

        console.print(f"[green]✓ Output saved: {filename}[/green]")
        return str(filepath)

    def list_evidence(self) -> List[Dict[str, str]]:
        """List all evidence files."""
        evidence = []
        for f in sorted(self.evidence_dir.iterdir()):
            if f.is_file():
                evidence.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })
        return evidence

    def display_evidence(self):
        """Display evidence list."""
        evidence = self.list_evidence()

        if not evidence:
            console.print("[yellow]No evidence collected yet.[/yellow]")
            return

        table = Table(title=f"Evidence ({self.session_id})", box=box.ROUNDED)
        table.add_column("File", style="cyan")
        table.add_column("Size", style="dim")
        table.add_column("Modified", style="dim")

        for e in evidence:
            size_kb = e['size'] / 1024
            table.add_row(
                e['name'],
                f"{size_kb:.1f} KB",
                e['modified'][:19]
            )

        console.print(table)


# Singleton
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get session manager instance."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
