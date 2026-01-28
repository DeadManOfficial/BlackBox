"""
Intelligence Module - Threat Intelligence & OSINT

Components for intelligence gathering and analysis:
- Intelligence agents for automated research
- Mission commander for coordinated intel ops
- CLI interface for intel operations
"""

from .intelligence_agents import (
    IntelligenceFinding,
    BaseIntelligenceAgent,
    MarketIntelligenceAgent,
    TechnologySurveillanceAgent,
    PolicyMonitoringAgent,
    OSINTAnalysisAgent,
    SynthesisAgent,
    IntelligenceAgentFactory
)

from .mission_commander import (
    MissionParameters,
    MissionCycle,
    AgentTelemetry,
    MissionCommander
)

__version__ = "1.0.0"
__author__ = "DeadManOfficial"

__all__ = [
    # Intelligence agents
    "IntelligenceFinding",
    "BaseIntelligenceAgent",
    "MarketIntelligenceAgent",
    "TechnologySurveillanceAgent",
    "PolicyMonitoringAgent",
    "OSINTAnalysisAgent",
    "SynthesisAgent",
    "IntelligenceAgentFactory",
    # Mission commander
    "MissionParameters",
    "MissionCycle",
    "AgentTelemetry",
    "MissionCommander"
]
