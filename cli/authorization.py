#!/usr/bin/env python3
"""
BlackBox AI - Authorization & Scope Management
================================================

Handles authorized scope confirmation and tracking for security testing.
"""

import os
import yaml
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich.text import Text
from rich import box

console = Console()

# Authorization state file
AUTH_STATE_FILE = Path(__file__).parent.parent / "data" / ".auth_state"


class AuthorizationManager:
    """Manages authorization scope and confirmation for security testing."""

    def __init__(self, scope_file: Optional[str] = None):
        self.scope_file = scope_file or str(
            Path(__file__).parent.parent / "config" / "authorized_scope.yaml"
        )
        self.scope_data: Dict[str, Any] = {}
        self.is_authorized = False
        self.session_id = None
        self._load_scope()

    def _load_scope(self) -> None:
        """Load authorized scope from YAML file."""
        try:
            with open(self.scope_file, 'r') as f:
                self.scope_data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            self.scope_data = {"authorization": {"required": False}}
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load scope file: {e}[/yellow]")
            self.scope_data = {"authorization": {"required": False}}

    def _generate_session_id(self) -> str:
        """Generate unique session ID for audit logging."""
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}-{os.getpid()}-{os.getlogin() if hasattr(os, 'getlogin') else 'user'}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _save_auth_state(self) -> None:
        """Save authorization state for session persistence."""
        AUTH_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "scope_hash": hashlib.sha256(
                yaml.dump(self.scope_data).encode()
            ).hexdigest()[:16],
            "authorized": self.is_authorized
        }
        with open(AUTH_STATE_FILE, 'w') as f:
            yaml.dump(state, f)

    def _log_authorization(self, accepted: bool) -> None:
        """Log authorization decision for audit trail."""
        log_dir = Path(__file__).parent.parent / "data" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "action": "scope_accepted" if accepted else "scope_declined",
            "program": self.scope_data.get("program", {}).get("name", "Unknown"),
            "user": os.getenv("USER", "unknown"),
            "targets_count": len(self.scope_data.get("targets", []))
        }

        log_file = log_dir / "authorization.log"
        with open(log_file, 'a') as f:
            f.write(yaml.dump([log_entry], default_flow_style=False))
            f.write("---\n")

    def display_scope_banner(self) -> None:
        """Display the authorization scope banner."""
        program = self.scope_data.get("program", {})
        auth_config = self.scope_data.get("authorization", {})
        scope_def = self.scope_data.get("scope_definition", {})

        # Header
        header = Text()
        header.append("AUTHORIZED SECURITY TESTING SCOPE\n", style="bold red")
        header.append("=" * 50 + "\n", style="red")

        # Authorization status
        auth_status = auth_config.get('status', 'pending').upper()
        if auth_status == "CONFIRMED":
            header.append(f"\nAuthorization: ", style="white")
            header.append(f"CONFIRMED\n", style="bold green")
            doc_loc = auth_config.get('document_location', 'this file')
            header.append(f"Document: ", style="white")
            header.append(f"{doc_loc}\n", style="dim")
        else:
            header.append(f"\nAuthorization: ", style="white")
            header.append(f"PENDING CONFIRMATION\n", style="bold yellow")

        header.append(f"\nProgram: ", style="white")
        header.append(f"{program.get('name', 'Unknown')}\n", style="bold cyan")
        header.append(f"Type: ", style="white")
        header.append(f"{program.get('type', 'Unknown').upper()}\n", style="yellow")
        header.append(f"Scope: ", style="white")
        header.append(f"{scope_def.get('type', 'defined').upper()} ", style="bold magenta")
        header.append(f"(Full app in scope with focus areas)\n", style="dim")
        header.append(f"Status: ", style="white")
        header.append(f"{program.get('status', 'Unknown').upper()}\n", style="green bold")

        console.print(Panel(header, box=box.DOUBLE, border_style="red"))

    def display_targets_summary(self) -> None:
        """Display summary table of authorized targets."""
        targets = self.scope_data.get("targets", [])

        if not targets:
            console.print("[yellow]No targets defined in scope.[/yellow]")
            return

        table = Table(
            title="[bold]Authorized Targets[/bold]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )

        table.add_column("#", style="dim", width=3)
        table.add_column("Asset", style="cyan", width=30)
        table.add_column("System Area", style="green", width=18)
        table.add_column("Phase", style="yellow", width=20)
        table.add_column("Tier", style="red", width=25)
        table.add_column("Status", style="white", width=8)

        for i, target in enumerate(targets, 1):
            table.add_row(
                str(i),
                target.get("asset", "Unknown")[:28],
                target.get("system_area", "")[:16],
                target.get("phase", "")[:18],
                target.get("tier", "").split("(")[0].strip()[:23],
                target.get("status", "Open")
            )

        console.print(table)

    def display_rules_of_engagement(self) -> None:
        """Display rules of engagement."""
        rules = self.scope_data.get("rules_of_engagement", [])
        out_of_scope = self.scope_data.get("out_of_scope", [])

        if rules:
            console.print("\n[bold yellow]Rules of Engagement:[/bold yellow]")
            for rule in rules:
                console.print(f"  [green]\u2714[/green] {rule}")

        if out_of_scope:
            console.print("\n[bold red]Out of Scope:[/bold red]")
            for item in out_of_scope:
                console.print(f"  [red]\u2718[/red] {item}")

    def display_legal_warning(self) -> None:
        """Display legal warning and disclaimer."""
        warning = Text()
        warning.append("\n\u26a0  LEGAL WARNING\n", style="bold yellow")
        warning.append("-" * 40 + "\n", style="yellow")
        warning.append(
            "By proceeding, you confirm that:\n\n"
            "1. You have WRITTEN AUTHORIZATION for this testing\n"
            "2. You will operate ONLY within the defined scope\n"
            "3. You accept responsibility for your actions\n"
            "4. Unauthorized access is a criminal offense\n",
            style="white"
        )

        console.print(Panel(warning, box=box.HEAVY, border_style="yellow"))

    def require_confirmation(self, force: bool = False) -> bool:
        """
        Display scope and require user confirmation.

        Args:
            force: Force re-confirmation even if already authorized

        Returns:
            True if authorized, False otherwise
        """
        auth_config = self.scope_data.get("authorization", {})

        # Check if authorization is required
        if not auth_config.get("required", True) and not force:
            self.is_authorized = True
            return True

        # Generate session ID
        self.session_id = self._generate_session_id()

        # Display full scope information
        console.print("\n")
        self.display_scope_banner()
        self.display_targets_summary()
        self.display_rules_of_engagement()
        self.display_legal_warning()

        # Require confirmation
        console.print("\n")

        try:
            confirmed = Confirm.ask(
                "[bold red]Do you have written authorization and agree to operate within scope?[/bold red]",
                default=False
            )
        except (EOFError, KeyboardInterrupt):
            confirmed = False

        if confirmed:
            self.is_authorized = True
            console.print(
                f"\n[green]\u2714 Authorization confirmed. Session ID: {self.session_id}[/green]"
            )
            console.print("[dim]Authorization logged for audit trail.[/dim]\n")
        else:
            self.is_authorized = False
            console.print("\n[red]\u2718 Authorization declined. Exiting.[/red]\n")

        # Log the decision
        if auth_config.get("log_acceptance", True):
            self._log_authorization(confirmed)

        # Save state
        self._save_auth_state()

        return self.is_authorized

    def get_target_by_asset(self, asset_name: str) -> Optional[Dict[str, Any]]:
        """Get target details by asset name."""
        for target in self.scope_data.get("targets", []):
            if asset_name.lower() in target.get("asset", "").lower():
                return target
        return None

    def get_targets_by_phase(self, phase: str) -> List[Dict[str, Any]]:
        """Get all targets for a specific phase."""
        return [
            t for t in self.scope_data.get("targets", [])
            if phase.lower() in t.get("phase", "").lower()
        ]

    def get_targets_by_tier(self, tier_num: int) -> List[Dict[str, Any]]:
        """Get all targets for a specific tier."""
        return [
            t for t in self.scope_data.get("targets", [])
            if f"Tier {tier_num}" in t.get("tier", "")
        ]

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within authorized scope."""
        targets = self.scope_data.get("targets", [])
        target_lower = target.lower()

        for t in targets:
            # Check asset name
            if target_lower in t.get("asset", "").lower():
                return True
            # Check system area
            if target_lower in t.get("system_area", "").lower():
                return True
            # Check tooling
            for tool in t.get("tooling", []):
                if target_lower in tool.lower():
                    return True

        return False

    def check_out_of_scope(self, action: str) -> bool:
        """Check if an action is explicitly out of scope."""
        out_of_scope = self.scope_data.get("out_of_scope", [])
        action_lower = action.lower()

        for item in out_of_scope:
            if item.lower() in action_lower or action_lower in item.lower():
                return True

        return False


# Singleton instance
_auth_manager: Optional[AuthorizationManager] = None


def get_auth_manager() -> AuthorizationManager:
    """Get the singleton authorization manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthorizationManager()
    return _auth_manager


def require_authorization(func):
    """Decorator to require authorization before running a function."""
    def wrapper(*args, **kwargs):
        manager = get_auth_manager()
        if not manager.is_authorized:
            if not manager.require_confirmation():
                raise SystemExit(1)
        return func(*args, **kwargs)
    return wrapper


def check_scope(target: str) -> bool:
    """
    Quick check if a target is in scope.

    Args:
        target: Target to check

    Returns:
        True if in scope, False otherwise
    """
    manager = get_auth_manager()
    return manager.is_in_scope(target)
