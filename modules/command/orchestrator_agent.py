# =============================================================================
# Pentest Mission Control - Security Orchestrator Agent
# =============================================================================
# Tech-lead style orchestrator that coordinates security agents
# Following awesome-claude-agents pattern for multi-agent orchestration
# =============================================================================

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging
import json

from .security_base_agent import (
    BaseSecurityAgent,
    SecurityAgentRegistry,
    SecurityCapability,
    AgentResult,
    ConfidenceLevel,
    FindingSeverity,
    AgentStatus,
    security_agent,
)

logger = logging.getLogger(__name__)


@dataclass
class AgentTask:
    """Task assignment for an agent."""
    task_id: str
    description: str
    agent_name: str
    params: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    fallback_agent: Optional[str] = None
    priority: int = 1


@dataclass
class ExecutionPlan:
    """Plan for multi-agent execution."""
    tasks: List[AgentTask]
    parallel_groups: List[List[str]]  # Task IDs that can run in parallel
    sequential_order: List[str]  # Task IDs that must run sequentially


@security_agent
class SecurityOrchestrator(BaseSecurityAgent):
    """
    Security orchestrator that coordinates multiple security agents.

    Based on tech-lead-orchestrator pattern from awesome-claude-agents:
    - Analyzes requirements
    - Creates agent routing map
    - Coordinates execution order
    - Aggregates findings
    """

    @property
    def name(self) -> str:
        return "orchestrator"

    @property
    def description(self) -> str:
        return """Security orchestrator that coordinates multi-agent security assessments.
        Analyzes targets, plans execution, routes tasks to specialists, and aggregates findings."""

    @property
    def capabilities(self) -> List[SecurityCapability]:
        return [
            SecurityCapability(
                name="plan_assessment",
                description="Plan a full security assessment",
                tool_name="orchestrator",
                input_schema={"target": "string", "scope": "string", "agents": "list"},
                output_schema={"plan": "ExecutionPlan", "routing_map": "dict"},
            ),
            SecurityCapability(
                name="coordinate_agents",
                description="Coordinate multiple agents for assessment",
                tool_name="orchestrator",
                input_schema={"plan": "ExecutionPlan"},
                output_schema={"results": "list", "aggregate_findings": "list"},
            ),
            SecurityCapability(
                name="aggregate_findings",
                description="Aggregate findings from multiple agents",
                tool_name="orchestrator",
                input_schema={"results": "list"},
                output_schema={"summary": "dict", "attack_paths": "list"},
            ),
        ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._available_agents = SecurityAgentRegistry.list_agents()

    async def execute(
        self,
        task_type: str,
        target: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Execute orchestrator task."""

        if task_type == "plan_assessment":
            return await self._plan_assessment(target, params, context)
        elif task_type == "coordinate_agents":
            return await self._coordinate_agents(params, context)
        elif task_type == "aggregate_findings":
            return await self._aggregate_findings(params, context)
        else:
            return AgentResult(
                success=False,
                data=None,
                confidence=ConfidenceLevel.UNKNOWN,
                reasoning=f"Unknown task type: {task_type}",
            )

    async def _plan_assessment(
        self,
        target: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Plan a security assessment.

        Returns execution plan and agent routing map.
        """
        scope = params.get("scope", "single")
        requested_agents = params.get("agents", [])

        # Get available agents
        routing_map = SecurityAgentRegistry.get_routing_map()

        # Determine which agents to use
        if not requested_agents:
            # Default assessment flow
            requested_agents = ["recon", "vulnerability", "js_analysis", "llm_security", "exploit"]

        # Filter to available agents
        available = [a for a in requested_agents if a in routing_map or a in self._available_agents]

        # Create tasks
        tasks = []
        task_id = 1

        # Always start with recon if available
        if "recon" in available:
            tasks.append(AgentTask(
                task_id=f"task_{task_id}",
                description="Reconnaissance and information gathering",
                agent_name="recon",
                params={"target": target, "scope": scope},
                priority=1,
            ))
            task_id += 1

        # Parallel scanning phase
        parallel_tasks = []
        if "vulnerability" in available:
            t = AgentTask(
                task_id=f"task_{task_id}",
                description="Vulnerability scanning with Nuclei",
                agent_name="vulnerability",
                params={"target": target},
                depends_on=["task_1"] if "recon" in available else [],
                priority=2,
            )
            tasks.append(t)
            parallel_tasks.append(t.task_id)
            task_id += 1

        if "js_analysis" in available:
            t = AgentTask(
                task_id=f"task_{task_id}",
                description="JavaScript security analysis",
                agent_name="js_analysis",
                params={"target": target},
                depends_on=["task_1"] if "recon" in available else [],
                priority=2,
            )
            tasks.append(t)
            parallel_tasks.append(t.task_id)
            task_id += 1

        # LLM security if AI endpoint provided
        ai_endpoint = params.get("ai_endpoint")
        if "llm_security" in available and ai_endpoint:
            tasks.append(AgentTask(
                task_id=f"task_{task_id}",
                description="LLM security testing",
                agent_name="llm_security",
                params={"target": ai_endpoint},
                depends_on=parallel_tasks if parallel_tasks else [],
                priority=3,
            ))
            task_id += 1

        # Exploitation analysis
        if "exploit" in available:
            exploit_depends = [t.task_id for t in tasks if t.agent_name in ["vulnerability", "js_analysis"]]
            tasks.append(AgentTask(
                task_id=f"task_{task_id}",
                description="Exploitation analysis and attack path planning",
                agent_name="exploit",
                params={"target": target, "safe_mode": params.get("safe_mode", True)},
                depends_on=exploit_depends,
                priority=4,
            ))
            task_id += 1

        # Synthesis always runs last
        synthesis_depends = [t.task_id for t in tasks]
        tasks.append(AgentTask(
            task_id=f"task_{task_id}",
            description="Synthesize findings and generate attack paths",
            agent_name="synthesis",
            params={"target": target},
            depends_on=synthesis_depends,
            priority=5,
        ))

        # Create execution plan
        plan = ExecutionPlan(
            tasks=tasks,
            parallel_groups=[parallel_tasks] if parallel_tasks else [],
            sequential_order=[t.task_id for t in sorted(tasks, key=lambda x: x.priority)],
        )

        return AgentResult(
            success=True,
            data={
                "plan": {
                    "tasks": [
                        {
                            "id": t.task_id,
                            "description": t.description,
                            "agent": t.agent_name,
                            "depends_on": t.depends_on,
                        }
                        for t in plan.tasks
                    ],
                    "parallel_groups": plan.parallel_groups,
                    "sequential_order": plan.sequential_order,
                },
                "routing_map": {
                    t.agent_name: {
                        "task_id": t.task_id,
                        "description": t.description,
                    }
                    for t in plan.tasks
                },
            },
            confidence=ConfidenceLevel.HIGH,
            reasoning="Created execution plan based on target analysis and available agents",
            next_steps=[
                f"Execute {len(plan.tasks)} tasks in planned order",
                "Monitor agent progress and handle failures",
                "Aggregate findings after completion",
            ],
            handoff_context={
                "target": target,
                "scope": scope,
                "agent_count": len(available),
            },
        )

    async def _coordinate_agents(
        self,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Coordinate agent execution based on plan.

        Note: Actual agent execution would be done by the chat engine
        or external orchestrator. This provides coordination logic.
        """
        plan_data = params.get("plan", {})
        tasks = plan_data.get("tasks", [])

        coordination_instructions = []

        # Group tasks by priority
        priority_groups = {}
        for task in tasks:
            priority = task.get("priority", 1)
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(task)

        # Generate instructions
        for priority in sorted(priority_groups.keys()):
            group = priority_groups[priority]
            if len(group) == 1:
                task = group[0]
                coordination_instructions.append(
                    f"Step {priority}: Run {task['agent']} for {task['description']}"
                )
            else:
                agents = [t['agent'] for t in group]
                coordination_instructions.append(
                    f"Step {priority}: Run in parallel: {', '.join(agents)}"
                )

        return AgentResult(
            success=True,
            data={
                "coordination_instructions": coordination_instructions,
                "total_tasks": len(tasks),
                "parallel_groups": plan_data.get("parallel_groups", []),
            },
            confidence=ConfidenceLevel.HIGH,
            reasoning="Generated coordination instructions for multi-agent execution",
        )

    async def _aggregate_findings(
        self,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Aggregate findings from multiple agent results."""
        results = params.get("results", [])

        # Collect all findings
        all_findings = []
        all_entities = []

        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for result in results:
            findings = result.get("findings", [])
            entities = result.get("entities", [])

            all_findings.extend(findings)
            all_entities.extend(entities)

            for finding in findings:
                severity = finding.get("severity", "info").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Calculate risk score
        risk_score = min(100, (
            severity_counts["critical"] * 25 +
            severity_counts["high"] * 15 +
            severity_counts["medium"] * 8 +
            severity_counts["low"] * 3 +
            severity_counts["info"] * 1
        ))

        # Identify attack paths (simplified)
        attack_paths = []
        critical_findings = [f for f in all_findings if f.get("severity") == "critical"]
        high_findings = [f for f in all_findings if f.get("severity") == "high"]

        if critical_findings:
            attack_paths.append({
                "name": "Critical Vulnerability Chain",
                "steps": [f.get("title") for f in critical_findings[:3]],
                "risk": "critical",
            })

        return AgentResult(
            success=True,
            data={
                "summary": {
                    "total_findings": len(all_findings),
                    "total_entities": len(all_entities),
                    "severity_breakdown": severity_counts,
                    "risk_score": risk_score,
                },
                "attack_paths": attack_paths,
            },
            confidence=ConfidenceLevel.HIGH,
            reasoning=f"Aggregated {len(all_findings)} findings from {len(results)} agents",
            findings=[],  # Aggregated findings are in data
            entities=all_entities,
        )

    def get_agent_routing_instructions(self) -> str:
        """
        Get routing instructions following awesome-claude-agents pattern.
        """
        routing_map = SecurityAgentRegistry.get_routing_map()

        lines = [
            "## Agent Routing Map",
            "",
            "### Available Security Agents:",
        ]

        for name, info in routing_map.items():
            lines.append(f"- **{name}**: {info.get('description', 'No description')}")
            caps = info.get("capabilities", [])
            if caps:
                lines.append(f"  - Capabilities: {', '.join(caps)}")

        lines.extend([
            "",
            "### Execution Rules:",
            "- Maximum 2 agents run in parallel",
            "- Follow dependency order strictly",
            "- Use fallback agents when primary unavailable",
            "- Aggregate findings after each phase",
        ])

        return "\n".join(lines)
