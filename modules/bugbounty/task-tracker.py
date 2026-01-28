#!/usr/bin/env python3
"""
Task Tracker
Manages research and implementation tasks from TASK_PLAN.md

Usage:
    ./task-tracker.py --status
    ./task-tracker.py --complete 1.1.1
    ./task-tracker.py --start-phase 1
"""

import argparse
import json
import re
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
TASK_PLAN = FRAMEWORK_DIR / "TASK_PLAN.md"
TASK_STATE = FRAMEWORK_DIR / ".task-state.json"


def load_state():
    """Load task completion state"""
    if TASK_STATE.exists():
        return json.loads(TASK_STATE.read_text())
    return {"completed": [], "in_progress": [], "started": datetime.now().isoformat()}


def save_state(state):
    """Save task completion state"""
    state["updated"] = datetime.now().isoformat()
    TASK_STATE.write_text(json.dumps(state, indent=2))


def parse_tasks(content):
    """Parse tasks from TASK_PLAN.md"""
    tasks = []
    current_phase = None
    current_task = None

    for line in content.split('\n'):
        # Phase header
        if line.startswith('## Phase'):
            match = re.search(r'Phase (\d+):', line)
            if match:
                current_phase = int(match.group(1))

        # Task header
        if line.startswith('### Task'):
            match = re.search(r'Task (\d+\.\d+):', line)
            if match:
                current_task = match.group(1)

        # Task item
        if '|' in line and re.search(r'\d+\.\d+\.\d+', line):
            match = re.search(r'(\d+\.\d+\.\d+)', line)
            if match:
                task_id = match.group(1)
                # Extract description
                parts = line.split('|')
                if len(parts) >= 3:
                    desc = parts[2].strip() if len(parts) > 2 else ""
                    status = '[x]' in line.lower()
                    tasks.append({
                        "id": task_id,
                        "phase": current_phase,
                        "parent": current_task,
                        "description": desc,
                        "done": status
                    })

    return tasks


def show_status(state):
    """Display current status"""
    content = TASK_PLAN.read_text()
    tasks = parse_tasks(content)

    print("\n" + "="*60)
    print("TASK TRACKER STATUS")
    print("="*60)

    # Group by phase
    phases = {}
    for task in tasks:
        phase = task["phase"]
        if phase not in phases:
            phases[phase] = {"total": 0, "done": 0, "tasks": []}
        phases[phase]["total"] += 1
        if task["done"] or task["id"] in state.get("completed", []):
            phases[phase]["done"] += 1
        phases[phase]["tasks"].append(task)

    for phase_num in sorted(phases.keys()):
        phase = phases[phase_num]
        pct = (phase["done"] / phase["total"] * 100) if phase["total"] > 0 else 0
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"\nPhase {phase_num}: [{bar}] {pct:.0f}% ({phase['done']}/{phase['total']})")

        for task in phase["tasks"]:
            status = "✓" if task["done"] or task["id"] in state.get("completed", []) else " "
            in_prog = "→" if task["id"] in state.get("in_progress", []) else " "
            print(f"  [{status}]{in_prog} {task['id']}: {task['description'][:50]}")

    # Summary
    total = len(tasks)
    done = sum(1 for t in tasks if t["done"] or t["id"] in state.get("completed", []))
    print("\n" + "-"*60)
    print(f"Overall Progress: {done}/{total} tasks ({done/total*100:.1f}%)")
    print(f"Started: {state.get('started', 'N/A')}")
    print(f"Updated: {state.get('updated', 'N/A')}")


def complete_task(state, task_id):
    """Mark a task as complete"""
    if task_id not in state["completed"]:
        state["completed"].append(task_id)
        if task_id in state.get("in_progress", []):
            state["in_progress"].remove(task_id)
    save_state(state)
    print(f"[+] Task {task_id} marked complete")


def start_task(state, task_id):
    """Mark a task as in progress"""
    if "in_progress" not in state:
        state["in_progress"] = []
    if task_id not in state["in_progress"]:
        state["in_progress"].append(task_id)
    save_state(state)
    print(f"[*] Task {task_id} marked in progress")


def start_phase(state, phase_num):
    """Start all tasks in a phase"""
    content = TASK_PLAN.read_text()
    tasks = parse_tasks(content)

    if "in_progress" not in state:
        state["in_progress"] = []

    count = 0
    for task in tasks:
        if task["phase"] == phase_num and task["id"] not in state["completed"]:
            if task["id"] not in state["in_progress"]:
                state["in_progress"].append(task["id"])
                count += 1

    save_state(state)
    print(f"[+] Started {count} tasks in Phase {phase_num}")


def generate_report(state):
    """Generate progress report"""
    content = TASK_PLAN.read_text()
    tasks = parse_tasks(content)

    report = []
    report.append("# Task Progress Report")
    report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Statistics
    total = len(tasks)
    done = sum(1 for t in tasks if t["done"] or t["id"] in state.get("completed", []))
    in_prog = len(state.get("in_progress", []))

    report.append("## Summary")
    report.append(f"- **Total Tasks:** {total}")
    report.append(f"- **Completed:** {done}")
    report.append(f"- **In Progress:** {in_prog}")
    report.append(f"- **Remaining:** {total - done}")
    report.append(f"- **Completion:** {done/total*100:.1f}%\n")

    # By phase
    report.append("## By Phase")
    phases = {}
    for task in tasks:
        phase = task["phase"]
        if phase not in phases:
            phases[phase] = {"total": 0, "done": 0}
        phases[phase]["total"] += 1
        if task["done"] or task["id"] in state.get("completed", []):
            phases[phase]["done"] += 1

    for phase_num in sorted(phases.keys()):
        phase = phases[phase_num]
        pct = (phase["done"] / phase["total"] * 100) if phase["total"] > 0 else 0
        report.append(f"- Phase {phase_num}: {phase['done']}/{phase['total']} ({pct:.0f}%)")

    # Completed tasks
    report.append("\n## Completed Tasks")
    for task in tasks:
        if task["done"] or task["id"] in state.get("completed", []):
            report.append(f"- [x] {task['id']}: {task['description']}")

    # In progress
    report.append("\n## In Progress")
    for task_id in state.get("in_progress", []):
        task = next((t for t in tasks if t["id"] == task_id), None)
        if task:
            report.append(f"- [ ] {task['id']}: {task['description']}")

    report_content = "\n".join(report)
    report_path = FRAMEWORK_DIR / "reports" / f"progress-{datetime.now().strftime('%Y%m%d')}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_content)

    print(f"[+] Report saved to: {report_path}")
    return report_content


def main():
    parser = argparse.ArgumentParser(description="Task Tracker")
    parser.add_argument("--status", "-s", action="store_true", help="Show status")
    parser.add_argument("--complete", "-c", help="Mark task complete (e.g., 1.1.1)")
    parser.add_argument("--start", help="Mark task in progress (e.g., 1.1.1)")
    parser.add_argument("--start-phase", type=int, help="Start all tasks in phase")
    parser.add_argument("--report", "-r", action="store_true", help="Generate report")

    args = parser.parse_args()
    state = load_state()

    if args.complete:
        complete_task(state, args.complete)
    elif args.start:
        start_task(state, args.start)
    elif args.start_phase:
        start_phase(state, args.start_phase)
    elif args.report:
        generate_report(state)
    else:
        show_status(state)


if __name__ == "__main__":
    main()
