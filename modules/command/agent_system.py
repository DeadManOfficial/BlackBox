"""
Pentest Mission Control - Multi-Agent System
=============================================

XBOW/HexStrike/PentAGI inspired autonomous agent architecture.

Agent Hierarchy:
- Orchestrator: Central brain, coordinates all agents
- Researcher: Intel gathering, target analysis, knowledge retrieval
- Planner: Attack strategy, exploit selection, tool chaining
- Executor: Tool execution, result collection
- Analyzer: Result interpretation, finding extraction
- Reporter: Documentation, visualization updates

Memory Systems:
- Long-term: Vector embeddings of past findings, techniques
- Working: Current engagement context
- Episodic: Action history for this session
"""

import asyncio
import logging
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable
from enum import Enum
from datetime import datetime
import uuid

logger = logging.getLogger(__name__)


# =============================================================================
# Agent Types & States
# =============================================================================

class AgentType(Enum):
    """Types of specialized agents"""
    ORCHESTRATOR = "orchestrator"
    RESEARCHER = "researcher"
    PLANNER = "planner"
    EXECUTOR = "executor"
    ANALYZER = "analyzer"
    REPORTER = "reporter"


class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"
    THINKING = "thinking"
    EXECUTING = "executing"
    WAITING = "waiting"
    ERROR = "error"
    COMPLETE = "complete"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class AgentMessage:
    """Message passed between agents"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    sender: AgentType = AgentType.ORCHESTRATOR
    recipient: AgentType = AgentType.ORCHESTRATOR
    action: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    priority: int = 0  # Higher = more urgent


@dataclass
class Finding:
    """A discovered finding/vulnerability"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""  # "endpoint", "secret", "vulnerability", "file", "function", etc.
    severity: str = "info"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    source_agent: AgentType = AgentType.ANALYZER
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """A task for an agent to execute"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str = ""  # "scan", "extract", "analyze", "exploit", etc.
    target: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"  # pending, running, complete, failed
    result: Any = None
    error: Optional[str] = None
    assigned_to: Optional[AgentType] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None


@dataclass
class EngagementContext:
    """Current engagement/session context (working memory)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    scope: List[str] = field(default_factory=list)
    objective: str = ""
    findings: List[Finding] = field(default_factory=list)
    tasks: List[Task] = field(default_factory=list)
    entities: Dict[str, Any] = field(default_factory=dict)  # Knowledge graph
    action_history: List[Dict] = field(default_factory=list)  # Episodic memory
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())


# =============================================================================
# Base Agent
# =============================================================================

class BaseAgent(ABC):
    """
    Abstract base class for all agents.

    Each agent has:
    - A specific role/capability
    - Access to tools relevant to its role
    - Ability to send/receive messages
    - Connection to LLM for reasoning
    """

    def __init__(self, agent_type: AgentType):
        self.type = agent_type
        self.state = AgentState.IDLE
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.tools: Dict[str, Callable] = {}
        self.llm = None  # Set by orchestrator

    @property
    def name(self) -> str:
        return self.type.value

    def register_tool(self, name: str, func: Callable):
        """Register a tool this agent can use"""
        self.tools[name] = func
        logger.debug(f"{self.name}: Registered tool '{name}'")

    async def receive(self, message: AgentMessage):
        """Receive a message"""
        await self.message_queue.put(message)
        logger.debug(f"{self.name}: Received message from {message.sender.value}")

    @abstractmethod
    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process a message and return response"""
        pass

    async def execute_tool(self, tool_name: str, **params) -> Any:
        """Execute a registered tool"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        self.state = AgentState.EXECUTING
        try:
            result = self.tools[tool_name](**params)
            if asyncio.iscoroutine(result):
                result = await result
            return result
        finally:
            self.state = AgentState.IDLE

    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "type": self.type.value,
            "state": self.state.value,
            "tools": list(self.tools.keys()),
            "queue_size": self.message_queue.qsize(),
        }


# =============================================================================
# Specialized Agents
# =============================================================================

class ResearcherAgent(BaseAgent):
    """
    Intel gathering and target analysis.

    Capabilities:
    - Target fingerprinting
    - Technology detection
    - OSINT gathering
    - Knowledge base queries
    - Similar case retrieval
    """

    SYSTEM_PROMPT = """You are the Researcher Agent for Pentest Mission Control.

ROLE: Gather intelligence on targets. Identify technologies, entry points, and relevant prior knowledge.

ACTIONS:
- [RESEARCH:fingerprint(target)] - Identify technologies, frameworks, versions
- [RESEARCH:osint(target)] - Passive information gathering
- [RESEARCH:similar(target)] - Find similar past engagements/findings
- [RESEARCH:cve_lookup(tech, version)] - Find relevant CVEs

OUTPUT: Structured findings with confidence levels. Pass actionable intel to Planner."""

    def __init__(self):
        super().__init__(AgentType.RESEARCHER)

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process research request"""
        action = message.action
        payload = message.payload

        if action == "analyze_target":
            target = payload.get("target", context.target)
            # Execute research tools
            findings = await self._research_target(target, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.PLANNER,
                action="research_complete",
                payload={"findings": findings, "target": target}
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="error",
            payload={"error": f"Unknown action: {action}"}
        )

    async def _research_target(self, target: str, context: EngagementContext) -> List[Dict]:
        """Execute target research"""
        findings = []

        # Fingerprint
        if "fingerprint" in self.tools:
            result = await self.execute_tool("fingerprint", target=target)
            findings.append({"type": "fingerprint", "data": result})

        # Technology detection
        if "detect_tech" in self.tools:
            result = await self.execute_tool("detect_tech", target=target)
            findings.append({"type": "technologies", "data": result})

        return findings


class PlannerAgent(BaseAgent):
    """
    Attack strategy and tool selection.

    Capabilities:
    - Attack path planning
    - Tool/technique selection
    - Exploit matching
    - Risk assessment
    """

    SYSTEM_PROMPT = """You are the Planner Agent for Pentest Mission Control.

ROLE: Devise attack strategies based on research findings. Select tools and techniques.

INPUT: Research findings from Researcher Agent.

ACTIONS:
- [PLAN:attack_path(findings)] - Generate attack tree
- [PLAN:select_tools(attack)] - Choose appropriate tools
- [PLAN:prioritize(tasks)] - Order tasks by impact/likelihood

OUTPUT: Ordered task list for Executor Agent."""

    def __init__(self):
        super().__init__(AgentType.PLANNER)

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process planning request"""
        action = message.action

        if action == "research_complete":
            findings = message.payload.get("findings", [])
            tasks = await self._plan_attack(findings, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.EXECUTOR,
                action="execute_tasks",
                payload={"tasks": tasks}
            )

        if action == "plan_extraction":
            target = message.payload.get("target")
            extraction_type = message.payload.get("type", "full")
            tasks = await self._plan_extraction(target, extraction_type, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.EXECUTOR,
                action="execute_tasks",
                payload={"tasks": tasks}
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="error",
            payload={"error": f"Unknown action: {action}"}
        )

    async def _plan_attack(self, findings: List[Dict], context: EngagementContext) -> List[Task]:
        """Generate attack plan from findings"""
        tasks = []

        for finding in findings:
            if finding.get("type") == "technologies":
                techs = finding.get("data", {})
                for tech, version in techs.items():
                    tasks.append(Task(
                        type="cve_scan",
                        target=context.target,
                        params={"technology": tech, "version": version}
                    ))

        return tasks

    async def _plan_extraction(self, target: str, extraction_type: str, context: EngagementContext) -> List[Task]:
        """Plan extraction tasks"""
        tasks = []

        if extraction_type in ("full", "js"):
            tasks.append(Task(type="extract_js", target=target, params={"deobfuscate": True}))

        if extraction_type in ("full", "api"):
            tasks.append(Task(type="map_apis", target=target, params={}))

        if extraction_type in ("full", "binary"):
            tasks.append(Task(type="decompile", target=target, params={}))

        return tasks


class ExecutorAgent(BaseAgent):
    """
    Tool execution and result collection.

    Capabilities:
    - Run security tools
    - Manage execution sandbox
    - Collect raw results
    - Handle timeouts/errors
    """

    SYSTEM_PROMPT = """You are the Executor Agent for Pentest Mission Control.

ROLE: Execute tools and collect results. Handle errors gracefully.

INPUT: Task list from Planner Agent.

EXECUTION:
- Run tools in sandboxed environment
- Capture all output
- Track timing and resource usage
- Retry on transient failures

OUTPUT: Raw results to Analyzer Agent."""

    def __init__(self):
        super().__init__(AgentType.EXECUTOR)

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process execution request"""
        action = message.action

        if action == "execute_tasks":
            tasks = message.payload.get("tasks", [])
            results = await self._execute_tasks(tasks, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.ANALYZER,
                action="analyze_results",
                payload={"results": results}
            )

        if action == "execute_single":
            task = message.payload.get("task")
            result = await self._execute_single(task, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.ANALYZER,
                action="analyze_result",
                payload={"result": result}
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="error",
            payload={"error": f"Unknown action: {action}"}
        )

    async def _execute_tasks(self, tasks: List[Task], context: EngagementContext) -> List[Dict]:
        """Execute multiple tasks"""
        results = []
        for task in tasks:
            result = await self._execute_single(task, context)
            results.append(result)
            # Record in action history
            context.action_history.append({
                "task": task.type,
                "target": task.target,
                "timestamp": datetime.now().isoformat(),
                "success": result.get("success", False)
            })
        return results

    async def _execute_single(self, task: Task, context: EngagementContext) -> Dict:
        """Execute a single task"""
        tool_name = task.type
        if tool_name not in self.tools:
            return {"success": False, "error": f"Tool not available: {tool_name}"}

        try:
            self.state = AgentState.EXECUTING
            result = await self.execute_tool(tool_name, target=task.target, **task.params)
            return {"success": True, "data": result, "task_id": task.id}
        except Exception as e:
            logger.error(f"Task execution failed: {e}")
            return {"success": False, "error": str(e), "task_id": task.id}
        finally:
            self.state = AgentState.IDLE


class AnalyzerAgent(BaseAgent):
    """
    Result interpretation and finding extraction.

    Capabilities:
    - Parse tool output
    - Extract findings
    - Correlate data
    - Severity assessment
    """

    SYSTEM_PROMPT = """You are the Analyzer Agent for Pentest Mission Control.

ROLE: Interpret results, extract findings, assess severity.

INPUT: Raw results from Executor Agent.

ANALYSIS:
- Parse structured and unstructured data
- Extract vulnerabilities, endpoints, secrets
- Correlate findings across sources
- Assign severity based on impact

OUTPUT: Structured findings to Reporter and Orchestrator."""

    def __init__(self):
        super().__init__(AgentType.ANALYZER)

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process analysis request"""
        action = message.action

        if action == "analyze_results":
            results = message.payload.get("results", [])
            findings = await self._analyze_results(results, context)
            # Add findings to context
            context.findings.extend(findings)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.REPORTER,
                action="update_report",
                payload={"findings": findings}
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="error",
            payload={"error": f"Unknown action: {action}"}
        )

    async def _analyze_results(self, results: List[Dict], context: EngagementContext) -> List[Finding]:
        """Analyze results and extract findings"""
        findings = []

        for result in results:
            if not result.get("success"):
                continue

            data = result.get("data", {})

            # Extract findings based on data type
            if isinstance(data, dict):
                for key, value in data.items():
                    if key in ("vulnerabilities", "vulns"):
                        for vuln in value:
                            findings.append(Finding(
                                type="vulnerability",
                                severity=vuln.get("severity", "medium"),
                                title=vuln.get("title", "Unknown"),
                                description=vuln.get("description", ""),
                                evidence=vuln
                            ))
                    elif key in ("endpoints", "apis"):
                        for endpoint in value:
                            findings.append(Finding(
                                type="endpoint",
                                severity="info",
                                title=f"API Endpoint: {endpoint.get('path', 'unknown')}",
                                evidence=endpoint
                            ))
                    elif key in ("secrets", "credentials"):
                        for secret in value:
                            findings.append(Finding(
                                type="secret",
                                severity="critical",
                                title=f"Exposed Secret: {secret.get('type', 'unknown')}",
                                evidence=secret
                            ))

        return findings


class ReporterAgent(BaseAgent):
    """
    Documentation and visualization.

    Capabilities:
    - Update knowledge graph
    - Generate reports
    - Update visual mapper
    - Export artifacts
    """

    SYSTEM_PROMPT = """You are the Reporter Agent for Pentest Mission Control.

ROLE: Document findings, update visualizations, maintain knowledge graph.

INPUT: Findings from Analyzer Agent.

ACTIONS:
- Update visual attack surface map
- Add entities to knowledge graph
- Generate summary reports
- Export artifacts and evidence"""

    def __init__(self):
        super().__init__(AgentType.REPORTER)
        self.update_callbacks: List[Callable] = []

    def on_update(self, callback: Callable):
        """Register callback for visualization updates"""
        self.update_callbacks.append(callback)

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process reporting request"""
        action = message.action

        if action == "update_report":
            findings = message.payload.get("findings", [])
            await self._update_visualizations(findings, context)
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.ORCHESTRATOR,
                action="report_updated",
                payload={"findings_count": len(findings)}
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="error",
            payload={"error": f"Unknown action: {action}"}
        )

    async def _update_visualizations(self, findings: List[Finding], context: EngagementContext):
        """Update visualizations with new findings"""
        # Build graph update
        graph_update = {
            "nodes": [],
            "edges": []
        }

        for finding in findings:
            node = {
                "id": finding.id,
                "type": finding.type,
                "label": finding.title,
                "severity": finding.severity,
            }
            graph_update["nodes"].append(node)

            # Connect to target
            graph_update["edges"].append({
                "source": context.target,
                "target": finding.id,
                "type": "has_finding"
            })

        # Notify callbacks
        for callback in self.update_callbacks:
            try:
                callback(graph_update)
            except Exception as e:
                logger.error(f"Visualization callback error: {e}")


# =============================================================================
# Orchestrator
# =============================================================================

class OrchestratorAgent(BaseAgent):
    """
    Central coordination agent.

    Manages all other agents, routes messages, maintains context.
    """

    SYSTEM_PROMPT = """You are the Orchestrator for Pentest Mission Control.

ROLE: Coordinate all agents. Interpret user commands. Maintain engagement context.

AGENTS:
- Researcher: Intel gathering, fingerprinting
- Planner: Attack strategy, tool selection
- Executor: Run tools, collect results
- Analyzer: Interpret results, extract findings
- Reporter: Document, visualize

USER COMMANDS:
- Parse natural language requests
- Route to appropriate agents
- Aggregate and present results"""

    def __init__(self):
        super().__init__(AgentType.ORCHESTRATOR)
        self.agents: Dict[AgentType, BaseAgent] = {}
        self.context: Optional[EngagementContext] = None

    def register_agent(self, agent: BaseAgent):
        """Register a sub-agent"""
        self.agents[agent.type] = agent
        logger.info(f"Orchestrator: Registered {agent.type.value} agent")

    def init_engagement(self, target: str, objective: str = "") -> EngagementContext:
        """Initialize a new engagement"""
        self.context = EngagementContext(
            target=target,
            objective=objective
        )
        logger.info(f"Orchestrator: New engagement for {target}")
        return self.context

    async def process(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Process a message (typically from user)"""
        # Route based on action
        action = message.action

        if action == "user_command":
            return await self._handle_user_command(message, context)

        if action == "report_updated":
            # Engagement cycle complete for this round
            return AgentMessage(
                sender=self.type,
                recipient=AgentType.ORCHESTRATOR,  # Self
                action="cycle_complete",
                payload=message.payload
            )

        return AgentMessage(
            sender=self.type,
            recipient=message.sender,
            action="acknowledged",
            payload={}
        )

    async def _handle_user_command(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Handle a user command"""
        command = message.payload.get("command", "")

        # Simple command routing (LLM would do this more intelligently)
        if any(word in command.lower() for word in ["scan", "recon", "analyze"]):
            # Start research
            research_msg = AgentMessage(
                sender=self.type,
                recipient=AgentType.RESEARCHER,
                action="analyze_target",
                payload={"target": context.target}
            )
            return await self._route_message(research_msg, context)

        if any(word in command.lower() for word in ["extract", "pull", "get"]):
            # Plan extraction
            plan_msg = AgentMessage(
                sender=self.type,
                recipient=AgentType.PLANNER,
                action="plan_extraction",
                payload={"target": context.target, "command": command}
            )
            return await self._route_message(plan_msg, context)

        # Default: pass to LLM for interpretation
        return AgentMessage(
            sender=self.type,
            recipient=AgentType.ORCHESTRATOR,
            action="need_llm",
            payload={"command": command}
        )

    async def _route_message(self, message: AgentMessage, context: EngagementContext) -> AgentMessage:
        """Route message to appropriate agent"""
        recipient = self.agents.get(message.recipient)
        if not recipient:
            return AgentMessage(
                sender=self.type,
                recipient=message.sender,
                action="error",
                payload={"error": f"Unknown agent: {message.recipient}"}
            )

        # Process and chain
        response = await recipient.process(message, context)

        # If response needs further routing
        if response.recipient != self.type and response.recipient in self.agents:
            return await self._route_message(response, context)

        return response

    async def run_command(self, command: str) -> Dict[str, Any]:
        """Run a user command through the agent system"""
        if not self.context:
            return {"error": "No engagement initialized"}

        message = AgentMessage(
            sender=AgentType.ORCHESTRATOR,
            recipient=AgentType.ORCHESTRATOR,
            action="user_command",
            payload={"command": command}
        )

        result = await self.process(message, self.context)
        return {
            "action": result.action,
            "payload": result.payload,
            "findings": [f.__dict__ for f in self.context.findings],
            "action_history": self.context.action_history
        }


# =============================================================================
# Factory
# =============================================================================

def create_agent_system() -> OrchestratorAgent:
    """Create and wire up the full agent system"""
    orchestrator = OrchestratorAgent()

    # Create sub-agents
    researcher = ResearcherAgent()
    planner = PlannerAgent()
    executor = ExecutorAgent()
    analyzer = AnalyzerAgent()
    reporter = ReporterAgent()

    # Register with orchestrator
    orchestrator.register_agent(researcher)
    orchestrator.register_agent(planner)
    orchestrator.register_agent(executor)
    orchestrator.register_agent(analyzer)
    orchestrator.register_agent(reporter)

    return orchestrator


# =============================================================================
# Test
# =============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    async def test():
        # Create system
        orchestrator = create_agent_system()

        # Initialize engagement
        orchestrator.init_engagement(
            target="https://example.com",
            objective="Full security assessment"
        )

        # Run command
        result = await orchestrator.run_command("scan the target")
        print(json.dumps(result, indent=2, default=str))

    asyncio.run(test())
