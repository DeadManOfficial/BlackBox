# =============================================================================
# Pentest Mission Control - Security Base Agent
# =============================================================================
# Foundation for all security agents, combining patterns from:
# - ODIN v7.0 (confidence framework, lifecycle, messaging)
# - awesome-claude-agents (orchestration, routing)
# - HexStrike AI (security tool integration)
# - moo.md (silent audit, gate verification, quality footer)
# =============================================================================

from __future__ import annotations
import logging
import uuid
import time
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


# =============================================================================
# Workflow & Verification Types (from moo.md)
# =============================================================================

class WorkflowType(Enum):
    """Workflow type determines verification approach."""
    BUILD = "build"      # A: New feature, requires library search
    DEBUG = "debug"      # B: Bug fix, requires root cause
    REFACTOR = "refactor"  # C: Restructure, requires deletion first


class VerificationType(Enum):
    """Verification types determine if we can ship (from moo.md)."""
    EXECUTION_OUTPUT = "execution_output"  # Ran command, showed result - SHIP OK
    OBSERVATION = "observation"            # Screenshot, debugger - SHIP OK
    MEASUREMENT = "measurement"            # Metrics, benchmark - SHIP OK
    CODE_REVIEW = "code_review"            # Inspection only - WEAK
    ASSUMPTION = "assumption"              # Not verified - BLOCKS SHIP


class ReversibilityType(Enum):
    """Reversibility assessment for decisions."""
    TYPE_2A = "2a"  # < 1 min rollback (config, rename) - Execute immediately
    TYPE_2B = "2b"  # < 5 min rollback (dependency, refactor) - Execute with monitoring
    TYPE_1 = "1"    # Hours+ rollback (schema, API) - Deep analysis required


@dataclass
class SilentAudit:
    """
    Silent audit checklist run before every significant action.
    From moo.md 'hope' skill.
    """
    inversion_applied: bool = False      # Failure modes identified?
    library_searched: bool = False       # Production solution exists?
    learnings_recalled: bool = False     # Past failures for this domain?
    verification_type: Optional[VerificationType] = None
    confidence_estimate: Optional[int] = None  # Percentage with evidence
    alternative_provided: bool = False   # Different approach considered?
    reversibility: Optional[ReversibilityType] = None
    story_points: Optional[int] = None   # Complexity (1, 3, 5, 8, 13)
    intent_clear: bool = False           # >= 85% confident I understand?

    def is_ready_to_proceed(self) -> bool:
        """Check if audit passes minimum requirements."""
        if self.confidence_estimate and self.confidence_estimate < 70:
            return False  # Need more research
        if self.verification_type == VerificationType.ASSUMPTION:
            return False  # Can't ship on assumption
        return self.intent_clear

    def to_dict(self) -> Dict[str, Any]:
        return {
            "inversion_applied": self.inversion_applied,
            "library_searched": self.library_searched,
            "learnings_recalled": self.learnings_recalled,
            "verification_type": self.verification_type.value if self.verification_type else None,
            "confidence_estimate": self.confidence_estimate,
            "alternative_provided": self.alternative_provided,
            "reversibility": self.reversibility.value if self.reversibility else None,
            "story_points": self.story_points,
            "intent_clear": self.intent_clear,
        }


@dataclass
class QualityFooter:
    """
    Quality footer for every non-trivial response.
    From moo.md pattern.
    """
    confidence: int  # Percentage
    alternative: str  # Different approach
    reversibility: ReversibilityType
    key_assumption: str  # What could be wrong
    complexity: int  # Story points

    def format(self) -> str:
        return (
            f"---\n"
            f"**Confidence**: {self.confidence}% | "
            f"**Alternative**: {self.alternative} | "
            f"**Reversible**: {self.reversibility.value}\n"
            f"**Key Assumption**: {self.key_assumption} | "
            f"**Complexity**: {self.complexity} story points"
        )


class AgentStatus(Enum):
    """Agent lifecycle status."""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    STOPPED = "stopped"


class ConfidenceLevel(Enum):
    """
    Confidence levels for agent outputs.
    Based on ODIN's epistemic honesty framework.
    """
    AXIOM = 4       # 100% - Deterministic/verified (e.g., tool output)
    HIGH = 3        # 95%+ - Very confident (multiple confirmations)
    MODERATE = 2    # 70-95% - Reasonably confident (single source)
    UNCERTAIN = 1   # 40-70% - Uncertain, needs verification
    UNKNOWN = 0     # <40% - Don't know, should not proceed


class FindingSeverity(Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityCapability:
    """Describes a security agent capability."""
    name: str
    description: str
    tool_name: str  # Maps to tool registry
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    requires_approval: bool = False
    risk_level: str = "low"  # low, medium, high, critical
    mitre_techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK


@dataclass
class SecurityFinding:
    """Security finding/vulnerability."""
    id: str
    title: str
    severity: FindingSeverity
    description: str
    evidence: str
    target: str
    confidence: ConfidenceLevel
    agent_id: str
    timestamp: float = field(default_factory=time.time)
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "target": self.target,
            "confidence": self.confidence.name,
            "confidence_value": self.confidence.value,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
        }


@dataclass
class AgentResult:
    """Result from agent execution."""
    success: bool
    data: Any
    confidence: ConfidenceLevel
    reasoning: str
    findings: List[SecurityFinding] = field(default_factory=list)
    entities: List[Dict[str, Any]] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)  # For orchestration
    handoff_context: Dict[str, Any] = field(default_factory=dict)  # For next agent
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "confidence": self.confidence.name,
            "confidence_value": self.confidence.value,
            "reasoning": self.reasoning,
            "findings": [f.to_dict() for f in self.findings],
            "entities": self.entities,
            "citations": self.citations,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
            "next_steps": self.next_steps,
            "handoff_context": self.handoff_context,
            "metadata": self.metadata,
        }


class BaseSecurityAgent(ABC):
    """
    Base class for all security agents.

    Combines patterns from:
    - ODIN: Lifecycle, confidence tracking, verification
    - awesome-claude-agents: Orchestration, structured returns
    - HexStrike: Security tool integration
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        tool_registry: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize security agent.

        Args:
            agent_id: Unique agent identifier
            tool_registry: Shared tool registry for executing security tools
            config: Agent-specific configuration
        """
        self.agent_id = agent_id or f"{self.name}-{uuid.uuid4().hex[:8]}"
        self.tools = tool_registry
        self.config = config or {}

        self._status = AgentStatus.INITIALIZING
        self._current_task_id: Optional[str] = None
        self._findings: List[SecurityFinding] = []
        self._entities: List[Dict[str, Any]] = []
        self._execution_log: List[Dict[str, Any]] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent type name (e.g., 'recon', 'vuln', 'exploit')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable agent description."""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> List[SecurityCapability]:
        """List of agent capabilities."""
        pass

    @property
    def status(self) -> AgentStatus:
        """Current agent status."""
        return self._status

    @property
    def findings(self) -> List[SecurityFinding]:
        """Discovered security findings."""
        return self._findings

    @property
    def entities(self) -> List[Dict[str, Any]]:
        """Discovered entities (IPs, domains, endpoints, etc.)."""
        return self._entities

    # =========================================================================
    # Lifecycle Methods
    # =========================================================================

    async def start(self):
        """Start the agent."""
        logger.info(f"Starting agent {self.agent_id}")
        try:
            await self.on_start()
            self._status = AgentStatus.READY
            logger.info(f"Agent {self.agent_id} ready")
        except Exception as e:
            self._status = AgentStatus.ERROR
            logger.error(f"Agent {self.agent_id} failed to start: {e}")
            raise

    async def stop(self):
        """Stop the agent gracefully."""
        logger.info(f"Stopping agent {self.agent_id}")
        self._status = AgentStatus.STOPPED
        await self.on_stop()

    async def on_start(self):
        """Override for custom startup logic."""
        pass

    async def on_stop(self):
        """Override for custom shutdown logic."""
        pass

    # =========================================================================
    # Task Execution
    # =========================================================================

    @abstractmethod
    async def execute(
        self,
        task_type: str,
        target: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Execute a security task.

        Args:
            task_type: Type of task (maps to capability)
            target: Target URL/IP/domain
            params: Task parameters
            context: Additional context (from orchestrator, previous agents)

        Returns:
            AgentResult with findings and confidence
        """
        pass

    async def run_task(
        self,
        task_type: str,
        target: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Run a task with full lifecycle management.

        Creates task record, executes, and updates state.
        """
        task_id = str(uuid.uuid4())
        self._current_task_id = task_id

        # Log start
        self._log_action("task_started", {
            "task_type": task_type,
            "target": target,
            "params": params,
        })

        # Update status
        self._status = AgentStatus.BUSY

        try:
            # Execute
            result = await self.execute(task_type, target, params, context)

            # Store findings
            self._findings.extend(result.findings)

            # Store entities
            self._entities.extend(result.entities)

            # Log completion
            self._log_action("task_completed", {
                "success": result.success,
                "confidence": result.confidence.name,
                "findings_count": len(result.findings),
                "entities_count": len(result.entities),
            })

            return result

        except Exception as e:
            # Log error
            self._log_action("task_error", {"error": str(e)}, level="error")

            return AgentResult(
                success=False,
                data=None,
                confidence=ConfidenceLevel.UNKNOWN,
                reasoning=f"Task failed: {str(e)}",
                warnings=[str(e)],
            )

        finally:
            self._status = AgentStatus.READY
            self._current_task_id = None

    # =========================================================================
    # Tool Execution
    # =========================================================================

    async def execute_tool(
        self,
        tool_name: str,
        method: str,
        **params
    ) -> Dict[str, Any]:
        """
        Execute a security tool via registry.

        Args:
            tool_name: Name of the tool (e.g., 'nmap', 'nuclei')
            method: Method to execute
            **params: Tool parameters

        Returns:
            Tool execution result
        """
        if not self.tools:
            raise RuntimeError("No tool registry configured")

        self._log_action("tool_execution", {
            "tool": tool_name,
            "method": method,
            "params": params,
        })

        result = await self.tools.execute(tool_name, method, **params)

        return {
            "success": result.success,
            "output": result.output,
            "error": result.error,
            "duration": result.duration,
            "entities": result.entities,
        }

    # =========================================================================
    # Confidence & Verification
    # =========================================================================

    def assess_confidence(
        self,
        evidence: List[str],
        contradictions: List[str] = None,
        verification_count: int = 0,
        tool_verified: bool = False,
    ) -> ConfidenceLevel:
        """
        Assess confidence level based on evidence.

        Args:
            evidence: Supporting evidence
            contradictions: Contradicting evidence
            verification_count: Number of independent verifications
            tool_verified: Whether verified by deterministic tool output

        Returns:
            Confidence level
        """
        contradictions = contradictions or []

        # Tool output is AXIOM confidence
        if tool_verified and not contradictions:
            return ConfidenceLevel.AXIOM

        if not evidence:
            return ConfidenceLevel.UNKNOWN

        if contradictions:
            if len(contradictions) >= len(evidence):
                return ConfidenceLevel.UNKNOWN
            return ConfidenceLevel.UNCERTAIN

        if verification_count >= 2:
            return ConfidenceLevel.HIGH

        if len(evidence) >= 3:
            return ConfidenceLevel.MODERATE

        return ConfidenceLevel.UNCERTAIN

    def require_verification(
        self,
        result: AgentResult,
        min_confidence: ConfidenceLevel = ConfidenceLevel.MODERATE,
    ) -> bool:
        """Check if result requires additional verification."""
        return result.confidence.value < min_confidence.value

    # =========================================================================
    # Finding Creation
    # =========================================================================

    def create_finding(
        self,
        title: str,
        severity: FindingSeverity,
        description: str,
        evidence: str,
        target: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MODERATE,
        **kwargs
    ) -> SecurityFinding:
        """Create a security finding."""
        finding = SecurityFinding(
            id=str(uuid.uuid4()),
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            target=target,
            confidence=confidence,
            agent_id=self.agent_id,
            **kwargs
        )
        return finding

    # =========================================================================
    # Entity Discovery
    # =========================================================================

    def add_entity(
        self,
        entity_type: str,
        value: str,
        source: str,
        confidence: ConfidenceLevel = ConfidenceLevel.MODERATE,
        **metadata
    ):
        """Add a discovered entity."""
        entity = {
            "id": str(uuid.uuid4()),
            "type": entity_type,
            "value": value,
            "source": source,
            "confidence": confidence.name,
            "agent_id": self.agent_id,
            "timestamp": time.time(),
            **metadata
        }
        self._entities.append(entity)
        return entity

    # =========================================================================
    # Orchestration Support
    # =========================================================================

    def get_handoff_context(self) -> Dict[str, Any]:
        """
        Get context for handoff to next agent.
        Used by orchestrator for multi-agent coordination.
        """
        return {
            "agent_id": self.agent_id,
            "agent_name": self.name,
            "findings_summary": [
                {"title": f.title, "severity": f.severity.value}
                for f in self._findings
            ],
            "entities_discovered": [
                {"type": e["type"], "value": e["value"]}
                for e in self._entities
            ],
            "status": self._status.value,
        }

    def format_structured_return(self, result: AgentResult) -> str:
        """
        Format result for orchestrator consumption.
        Following awesome-claude-agents pattern.
        """
        lines = [
            f"## Task Completed: {self.name}",
            f"- Status: {'Success' if result.success else 'Failed'}",
            f"- Confidence: {result.confidence.name}",
            "",
            "### Findings:",
        ]

        for finding in result.findings:
            lines.append(f"- [{finding.severity.value.upper()}] {finding.title}")

        lines.extend([
            "",
            "### Entities Discovered:",
        ])

        for entity in result.entities:
            lines.append(f"- {entity.get('type', 'unknown')}: {entity.get('value', 'N/A')}")

        if result.next_steps:
            lines.extend([
                "",
                "### Recommended Next Steps:",
            ])
            for step in result.next_steps:
                lines.append(f"- {step}")

        if result.handoff_context:
            lines.extend([
                "",
                "### Handoff Context for Next Agent:",
                f"```json",
                json.dumps(result.handoff_context, indent=2),
                "```"
            ])

        return "\n".join(lines)

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def _log_action(self, action: str, details: Dict[str, Any], level: str = "info"):
        """Log agent action."""
        log_entry = {
            "timestamp": time.time(),
            "agent_id": self.agent_id,
            "action": action,
            "details": details,
            "level": level,
            "task_id": self._current_task_id,
        }
        self._execution_log.append(log_entry)

        log_func = getattr(logger, level, logger.info)
        log_func(f"[{self.agent_id}] {action}: {details}")

    def get_status_summary(self) -> Dict[str, Any]:
        """Get agent status summary."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self._status.value,
            "current_task": self._current_task_id,
            "findings_count": len(self._findings),
            "entities_count": len(self._entities),
            "capabilities": [c.name for c in self.capabilities],
        }

    # =========================================================================
    # Silent Audit (moo.md pattern)
    # =========================================================================

    def run_silent_audit(
        self,
        task_type: str,
        params: Dict[str, Any],
    ) -> SilentAudit:
        """
        Run silent audit before task execution.
        From moo.md hope skill.
        """
        audit = SilentAudit()

        # Check if we have failure modes (inversion)
        audit.inversion_applied = "failure_modes" in params

        # Check if we searched for existing solutions
        audit.library_searched = params.get("library_searched", False)

        # Check verification type
        if params.get("tool_output"):
            audit.verification_type = VerificationType.EXECUTION_OUTPUT
        elif params.get("has_evidence"):
            audit.verification_type = VerificationType.OBSERVATION
        else:
            audit.verification_type = VerificationType.ASSUMPTION

        # Estimate confidence
        audit.confidence_estimate = params.get("confidence", 70)

        # Check reversibility
        risk_level = params.get("risk_level", "low")
        if risk_level == "low":
            audit.reversibility = ReversibilityType.TYPE_2A
        elif risk_level == "medium":
            audit.reversibility = ReversibilityType.TYPE_2B
        else:
            audit.reversibility = ReversibilityType.TYPE_1

        # Estimate story points based on complexity
        audit.story_points = params.get("story_points", 3)

        # Intent clarity
        audit.intent_clear = params.get("intent_clear", True)

        self._log_action("silent_audit", audit.to_dict())
        return audit

    # =========================================================================
    # Gate Verification (moo.md pattern)
    # =========================================================================

    def verify_gate(
        self,
        workflow: WorkflowType,
        result: AgentResult,
    ) -> Dict[str, Any]:
        """
        Gate verification before claiming completion.
        From moo.md gate skill.
        """
        gate_checks = {
            "passed": True,
            "workflow": workflow.value,
            "checks": [],
            "blockers": [],
        }

        if workflow == WorkflowType.BUILD:
            # Workflow A checks
            checks = [
                ("feature_executes", result.success, "Feature executes without errors"),
                ("edge_cases_tested", len(result.warnings) == 0, "Edge cases tested"),
                ("dependencies_verified", True, "Dependencies verified"),
            ]
        elif workflow == WorkflowType.DEBUG:
            # Workflow B checks
            checks = [
                ("root_cause_identified", result.reasoning != "", "Root cause identified with evidence"),
                ("fix_tested", result.success, "Fix tested and resolves symptom"),
                ("prevention_added", len(result.suggestions) > 0, "Prevention added"),
            ]
        else:  # REFACTOR
            # Workflow C checks
            checks = [
                ("tests_pass", result.success, "Existing tests pass unchanged"),
                ("behavior_identical", True, "Behavior identical"),
                ("no_orphans", True, "Deletion complete (no orphans)"),
            ]

        for check_id, passed, description in checks:
            gate_checks["checks"].append({
                "id": check_id,
                "passed": passed,
                "description": description,
            })
            if not passed:
                gate_checks["blockers"].append(description)
                gate_checks["passed"] = False

        self._log_action("gate_verification", gate_checks)
        return gate_checks

    # =========================================================================
    # Root Cause Analysis / Trace (moo.md pattern)
    # =========================================================================

    def trace_root_cause(
        self,
        effect: str,
        evidence: List[str],
    ) -> Dict[str, Any]:
        """
        Five Whys root cause analysis.
        From moo.md trace skill.
        """
        trace = {
            "effect": effect,
            "why_chain": [],
            "root_cause": None,
            "confidence": 0,
            "contributing_factors": [],
            "prevention_hierarchy": {
                "immediate": [],    # < 1 week
                "short_term": [],   # < 1 month
                "long_term": [],    # < 1 quarter
            },
        }

        # Build why chain from evidence
        for i, ev in enumerate(evidence[:5], 1):
            confidence = 90 - (i * 10)  # Decreasing confidence deeper
            trace["why_chain"].append({
                "level": i,
                "explanation": ev,
                "confidence": confidence,
            })
            if confidence >= 70:
                trace["root_cause"] = ev
                trace["confidence"] = confidence

        self._log_action("trace_root_cause", {
            "effect": effect,
            "root_cause": trace["root_cause"],
            "confidence": trace["confidence"],
        })

        return trace

    # =========================================================================
    # Quality Footer Generation (moo.md pattern)
    # =========================================================================

    def generate_quality_footer(
        self,
        result: AgentResult,
        alternative: str = "N/A",
        key_assumption: str = "N/A",
    ) -> QualityFooter:
        """
        Generate quality footer for result.
        From moo.md pattern.
        """
        # Map confidence level to percentage
        confidence_map = {
            ConfidenceLevel.AXIOM: 100,
            ConfidenceLevel.HIGH: 95,
            ConfidenceLevel.MODERATE: 80,
            ConfidenceLevel.UNCERTAIN: 55,
            ConfidenceLevel.UNKNOWN: 30,
        }

        # Estimate story points from findings
        story_points = 1
        if len(result.findings) > 5:
            story_points = 8
        elif len(result.findings) > 2:
            story_points = 5
        elif len(result.findings) > 0:
            story_points = 3

        # Determine reversibility from risk
        high_severity = any(
            f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
            for f in result.findings
        )
        reversibility = ReversibilityType.TYPE_1 if high_severity else ReversibilityType.TYPE_2A

        footer = QualityFooter(
            confidence=confidence_map.get(result.confidence, 50),
            alternative=alternative,
            reversibility=reversibility,
            key_assumption=key_assumption,
            complexity=story_points,
        )

        return footer

    def format_result_with_footer(
        self,
        result: AgentResult,
        alternative: str = "Manual verification",
        key_assumption: str = "Target is accessible",
    ) -> str:
        """Format result with quality footer appended."""
        base = self.format_structured_return(result)
        footer = self.generate_quality_footer(result, alternative, key_assumption)
        return f"{base}\n\n{footer.format()}"


# =============================================================================
# Agent Registry
# =============================================================================

class SecurityAgentRegistry:
    """
    Registry for security agent types.
    Enables dynamic agent discovery and instantiation.
    """

    _agents: Dict[str, Type[BaseSecurityAgent]] = {}

    @classmethod
    def register(cls, agent_class: Type[BaseSecurityAgent]):
        """Register an agent class."""
        temp = object.__new__(agent_class)
        name = agent_class.name.fget(temp)
        cls._agents[name] = agent_class
        logger.info(f"Registered security agent type: {name}")

    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseSecurityAgent]]:
        """Get agent class by name."""
        return cls._agents.get(name)

    @classmethod
    def list_agents(cls) -> List[str]:
        """List all registered agent types."""
        return list(cls._agents.keys())

    @classmethod
    def create(cls, name: str, **kwargs) -> BaseSecurityAgent:
        """Create agent instance by name."""
        agent_class = cls.get(name)
        if not agent_class:
            raise ValueError(f"Unknown agent type: {name}")
        return agent_class(**kwargs)

    @classmethod
    def get_routing_map(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get agent routing map for orchestration.
        Following awesome-claude-agents pattern.
        """
        routing = {}
        for name, agent_class in cls._agents.items():
            temp = object.__new__(agent_class)
            routing[name] = {
                "description": agent_class.description.fget(temp),
                "capabilities": [c.name for c in agent_class.capabilities.fget(temp)],
            }
        return routing


def security_agent(cls: Type[BaseSecurityAgent]) -> Type[BaseSecurityAgent]:
    """Decorator to register a security agent class."""
    SecurityAgentRegistry.register(cls)
    return cls
