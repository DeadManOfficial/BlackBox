"""
Parallel Recon Orchestrator
===========================

Orchestrates parallel agent execution for efficient reconnaissance.

Learned from: TikTok engagement - 20+ agents in parallel

Author: DeadMan Toolkit v5.3
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import concurrent.futures


class AgentStatus(Enum):
    """Agent execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentGroup(Enum):
    """Agent execution groups (execution order)"""
    FOUNDATION = "foundation"      # Run first - infrastructure, signatures, API
    TIER5 = "tier5"               # High value - AI, Auth
    TIER4 = "tier4"               # Medium-high - Upload, Transcoding
    TIER3 = "tier3"               # Medium - Features
    TIER2 = "tier2"               # Lower priority
    DELIVERABLES = "deliverables"  # Run last - Documentation, Reports


@dataclass
class AgentTask:
    """An agent task"""
    name: str
    group: AgentGroup
    function: Callable
    args: Dict = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    status: AgentStatus = AgentStatus.PENDING
    result: Any = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None


class ParallelOrchestrator:
    """
    Orchestrates parallel agent execution.

    Usage:
        orchestrator = ParallelOrchestrator()

        # Register agents by group
        orchestrator.register("signatures", AgentGroup.FOUNDATION, analyze_signatures)
        orchestrator.register("api_schema", AgentGroup.FOUNDATION, discover_api)
        orchestrator.register("ai_analysis", AgentGroup.TIER5, analyze_ai,
                            dependencies=["api_schema"])
        orchestrator.register("auth_analysis", AgentGroup.TIER5, analyze_auth)

        # Run all
        results = await orchestrator.run_all()

        # Or run specific groups
        results = await orchestrator.run_group(AgentGroup.FOUNDATION)
    """

    # Default agent configuration for security engagements
    DEFAULT_AGENTS = {
        AgentGroup.FOUNDATION: [
            "signatures",       # X-Bogus, request signing
            "api_schema",       # API endpoint discovery
            "infrastructure",   # Domain/subdomain mapping
            "fingerprinting",   # Device fingerprint analysis
            "websocket",        # WebSocket protocol analysis
            "js_bundles"        # JavaScript analysis
        ],
        AgentGroup.TIER5: [
            "ai_analysis",      # AI/ML pipeline security
            "auth_analysis"     # Authentication/authorization
        ],
        AgentGroup.TIER4: [
            "upload_analysis",      # File upload security
            "transcoding_analysis", # Media processing
            "export_analysis",      # Download/export security
            "jobqueue_analysis"     # Async job security
        ],
        AgentGroup.TIER3: [
            "clip_analysis",    # Clip/edit features
            "caption_analysis", # Captioning/ASR
            "oauth_analysis"    # OAuth security
        ],
        AgentGroup.TIER2: [
            "logging_analysis", # Telemetry/logging
            "rate_limit_analysis"
        ],
        AgentGroup.DELIVERABLES: [
            "documentation",    # Architecture docs
            "poc_collection",   # PoC compilation
            "report_generation" # HackerOne reports
        ]
    }

    def __init__(self, max_workers: int = 10):
        self.tasks: Dict[str, AgentTask] = {}
        self.max_workers = max_workers
        self.execution_log: List[Dict] = []

    def register(
        self,
        name: str,
        group: AgentGroup,
        function: Callable,
        args: Optional[Dict] = None,
        dependencies: Optional[List[str]] = None
    ):
        """Register an agent task"""
        self.tasks[name] = AgentTask(
            name=name,
            group=group,
            function=function,
            args=args or {},
            dependencies=dependencies or []
        )

    def get_tasks_by_group(self, group: AgentGroup) -> List[AgentTask]:
        """Get all tasks in a group"""
        return [t for t in self.tasks.values() if t.group == group]

    def get_ready_tasks(self) -> List[AgentTask]:
        """Get tasks that are ready to run (dependencies met)"""
        ready = []
        for task in self.tasks.values():
            if task.status != AgentStatus.PENDING:
                continue

            # Check dependencies
            deps_met = all(
                self.tasks[dep].status == AgentStatus.COMPLETED
                for dep in task.dependencies
                if dep in self.tasks
            )

            if deps_met:
                ready.append(task)

        return ready

    async def run_task(self, task: AgentTask) -> Any:
        """Run a single task"""
        task.status = AgentStatus.RUNNING
        task.start_time = datetime.now()

        self._log(f"Starting: {task.name}")

        try:
            if asyncio.iscoroutinefunction(task.function):
                result = await task.function(**task.args)
            else:
                # Run sync function in thread pool
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(
                    None, lambda: task.function(**task.args)
                )

            task.result = result
            task.status = AgentStatus.COMPLETED
            self._log(f"Completed: {task.name}")

        except Exception as e:
            task.error = str(e)
            task.status = AgentStatus.FAILED
            self._log(f"Failed: {task.name} - {e}")

        finally:
            task.end_time = datetime.now()

        return task.result

    async def run_group(self, group: AgentGroup) -> Dict[str, Any]:
        """Run all tasks in a group in parallel"""
        tasks = self.get_tasks_by_group(group)

        self._log(f"Running group: {group.value} ({len(tasks)} tasks)")

        # Run all tasks in parallel
        results = await asyncio.gather(
            *[self.run_task(t) for t in tasks],
            return_exceptions=True
        )

        return {t.name: r for t, r in zip(tasks, results)}

    async def run_all(self) -> Dict[str, Any]:
        """Run all tasks respecting groups and dependencies"""
        results = {}

        # Run groups in order
        group_order = [
            AgentGroup.FOUNDATION,
            AgentGroup.TIER5,
            AgentGroup.TIER4,
            AgentGroup.TIER3,
            AgentGroup.TIER2,
            AgentGroup.DELIVERABLES
        ]

        for group in group_order:
            group_results = await self.run_group(group)
            results.update(group_results)

        return results

    async def run_dynamic(self) -> Dict[str, Any]:
        """Run tasks dynamically based on dependencies"""
        results = {}

        while True:
            ready = self.get_ready_tasks()
            if not ready:
                # Check if any tasks are still running
                running = [t for t in self.tasks.values()
                          if t.status == AgentStatus.RUNNING]
                if not running:
                    break
                await asyncio.sleep(0.1)
                continue

            # Run ready tasks in parallel
            batch_results = await asyncio.gather(
                *[self.run_task(t) for t in ready],
                return_exceptions=True
            )

            for task, result in zip(ready, batch_results):
                results[task.name] = result

        return results

    def _log(self, message: str):
        """Log execution event"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'message': message
        }
        self.execution_log.append(entry)

    def get_status(self) -> Dict:
        """Get execution status summary"""
        status_counts = {}
        for status in AgentStatus:
            status_counts[status.value] = len([
                t for t in self.tasks.values() if t.status == status
            ])

        return {
            'total_tasks': len(self.tasks),
            'by_status': status_counts,
            'by_group': {
                group.value: len(self.get_tasks_by_group(group))
                for group in AgentGroup
            },
            'failed_tasks': [
                {'name': t.name, 'error': t.error}
                for t in self.tasks.values()
                if t.status == AgentStatus.FAILED
            ]
        }

    def get_timing_report(self) -> Dict:
        """Get timing report for completed tasks"""
        completed = [t for t in self.tasks.values()
                    if t.status == AgentStatus.COMPLETED and t.duration]

        if not completed:
            return {'tasks': [], 'total_duration': 0}

        return {
            'tasks': sorted([
                {'name': t.name, 'duration': t.duration, 'group': t.group.value}
                for t in completed
            ], key=lambda x: x['duration'], reverse=True),
            'total_duration': sum(t.duration for t in completed),
            'average_duration': sum(t.duration for t in completed) / len(completed)
        }

    def export_report(self, filepath: str):
        """Export execution report to JSON"""
        report = {
            'status': self.get_status(),
            'timing': self.get_timing_report(),
            'execution_log': self.execution_log,
            'tasks': {
                name: {
                    'group': t.group.value,
                    'status': t.status.value,
                    'duration': t.duration,
                    'error': t.error
                }
                for name, t in self.tasks.items()
            }
        }

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)


# Convenience function for quick orchestration
async def orchestrate_engagement(
    target: str,
    agent_configs: Dict[str, Callable],
    output_dir: str
) -> Dict:
    """
    Quick orchestration for a security engagement.

    Args:
        target: Target identifier
        agent_configs: Dict mapping agent names to functions
        output_dir: Output directory for results

    Returns:
        Dict of results
    """
    orchestrator = ParallelOrchestrator()

    # Auto-detect groups from agent names
    for name, func in agent_configs.items():
        group = AgentGroup.TIER3  # Default

        if any(x in name for x in ['signature', 'api', 'infra', 'websocket', 'finger']):
            group = AgentGroup.FOUNDATION
        elif any(x in name for x in ['ai', 'auth', 'session']):
            group = AgentGroup.TIER5
        elif any(x in name for x in ['upload', 'transcode', 'export', 'job']):
            group = AgentGroup.TIER4
        elif any(x in name for x in ['log', 'rate', 'analytics']):
            group = AgentGroup.TIER2
        elif any(x in name for x in ['doc', 'report', 'poc']):
            group = AgentGroup.DELIVERABLES

        orchestrator.register(name, group, func, {'target': target})

    results = await orchestrator.run_all()

    # Export report
    orchestrator.export_report(f"{output_dir}/orchestration_report.json")

    return results
