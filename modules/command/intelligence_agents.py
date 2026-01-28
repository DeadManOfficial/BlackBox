"""
Specialized Intelligence Agents for Mission Control System
Each agent specializes in different intelligence domains
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from abc import ABC, abstractmethod
import subprocess

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class IntelligenceFinding:
    finding_id: str
    agent_id: str
    finding_type: str
    content: str
    confidence_score: float
    priority: int  # 1-5 scale
    source_urls: List[str]
    timestamp: datetime
    tags: List[str]
    metadata: Dict[str, Any]

class BaseIntelligenceAgent(ABC):
    """
    Base class for all specialized intelligence agents
    Following the orchestrator-worker pattern
    """

    def __init__(self, agent_id: str, specialization: str):
        self.agent_id = agent_id
        self.specialization = specialization
        self.is_active = False
        self.current_task = ""
        self.findings: List[IntelligenceFinding] = []
        self.confidence_threshold = 0.6
        self.max_findings_per_burst = 10

    @abstractmethod
    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute specialized intelligence gathering mission"""
        pass

    def _create_claude_prompt(self, research_topic: str, focus_areas: List[str]) -> str:
        """Create Claude Code research prompt for this agent's specialization"""
        base_prompt = f"""
# {self.specialization} Intelligence Mission

You are a specialized intelligence agent focused on {self.specialization}.
Your mission is to conduct focused research on: {research_topic}

## Mission Parameters:
- Focus Areas: {', '.join(focus_areas)}
- Time Constraint: 3-minute focused research burst
- Intelligence Quality: High-confidence findings only
- Output Format: Structured intelligence report

## Research Objectives:
1. Identify key developments and trends in your specialization area
2. Find high-confidence intelligence with verifiable sources
3. Assess significance and potential impact
4. Cross-reference multiple sources for verification
5. Flag any anomalies or unexpected patterns

## Required Output Format:
Return a JSON object with structured findings:

```json
{{
    "findings": [
        {{
            "type": "trend|development|alert|anomaly",
            "title": "Brief descriptive title",
            "content": "Detailed finding description",
            "confidence": 0.0-1.0,
            "priority": 1-5,
            "sources": ["url1", "url2"],
            "tags": ["tag1", "tag2"],
            "significance": "Brief impact assessment"
        }}
    ],
    "summary": "Overall intelligence summary",
    "agent_confidence": 0.0-1.0,
    "recommendations": ["action1", "action2"]
}}
```

## Specialization Guidelines:
{self._get_specialization_guidelines()}

Begin intelligence gathering now. Focus on actionable, high-confidence findings.
"""
        return base_prompt.strip()

    @abstractmethod
    def _get_specialization_guidelines(self) -> str:
        """Get specific guidelines for this agent's specialization"""
        pass

    def _execute_claude_research(self, prompt: str) -> str:
        """Execute Claude Code research with error handling"""
        try:
            logger.debug(f"🤖 {self.agent_id}: Executing Claude Code research...")

            result = subprocess.run([
                'claude',
                prompt
            ],
            text=True,
            capture_output=True,
            timeout=180  # 3-minute timeout for burst research
            )

            if result.returncode != 0:
                raise Exception(f"Claude Code execution failed: {result.stderr}")

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            logger.error(f"❌ {self.agent_id}: Research timeout")
            raise Exception("Research timeout - mission parameters may be too complex")
        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Claude Code execution failed: {e}")
            raise

    def _parse_claude_response(self, response: str) -> List[IntelligenceFinding]:
        """Parse Claude Code response into structured findings"""
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start == -1 or json_end == 0:
                raise ValueError("No JSON found in Claude Code response")

            json_str = response[json_start:json_end]
            data = json.loads(json_str)

            findings = []
            for finding_data in data.get('findings', []):
                finding = IntelligenceFinding(
                    finding_id=f"{self.agent_id}_{datetime.now().strftime('%H%M%S')}_{len(findings)}",
                    agent_id=self.agent_id,
                    finding_type=finding_data.get('type', 'unknown'),
                    content=finding_data.get('content', ''),
                    confidence_score=finding_data.get('confidence', 0.0),
                    priority=finding_data.get('priority', 3),
                    source_urls=finding_data.get('sources', []),
                    timestamp=datetime.now(),
                    tags=finding_data.get('tags', []),
                    metadata={
                        'title': finding_data.get('title', ''),
                        'significance': finding_data.get('significance', ''),
                        'agent_confidence': data.get('agent_confidence', 0.0),
                        'summary': data.get('summary', ''),
                        'recommendations': data.get('recommendations', [])
                    }
                )

                # Only include high-confidence findings
                if finding.confidence_score >= self.confidence_threshold:
                    findings.append(finding)

            logger.info(f"✅ {self.agent_id}: Parsed {len(findings)} high-confidence findings")
            return findings

        except json.JSONDecodeError as e:
            logger.error(f"❌ {self.agent_id}: Failed to parse JSON response: {e}")
            return []
        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Error parsing response: {e}")
            return []

class MarketIntelligenceAgent(BaseIntelligenceAgent):
    """
    Specialized agent for market intelligence, financial trends, and economic indicators
    """

    def __init__(self):
        super().__init__("market_intelligence", "Market Intelligence and Financial Analysis")

    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute market intelligence gathering mission"""
        logger.info(f"📈 {self.agent_id}: Starting market intelligence mission")
        self.is_active = True
        self.current_task = "Market trend analysis"

        try:
            # Build research prompt
            focus_areas = mission_parameters.get('focus_areas', ['market trends', 'economic indicators'])
            research_topic = "Current market developments and economic trends"

            prompt = self._create_claude_prompt(research_topic, focus_areas)

            # Execute research
            response = self._execute_claude_research(prompt)

            # Parse findings
            findings = self._parse_claude_response(response)
            self.findings.extend(findings)

            self.current_task = "Mission completed"
            logger.info(f"✅ {self.agent_id}: Mission completed - {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Mission failed: {e}")
            self.current_task = f"Mission failed: {str(e)}"
            return []
        finally:
            self.is_active = False

    def _get_specialization_guidelines(self) -> str:
        return """
- Focus on market movements, economic indicators, and financial trends
- Monitor earnings reports, regulatory filings, and market sentiment
- Identify emerging market opportunities and risks
- Track currency fluctuations, commodity prices, and sector rotations
- Analyze central bank communications and policy changes
- Monitor geopolitical events affecting markets
- Assess corporate developments and M&A activity
"""

class TechnologySurveillanceAgent(BaseIntelligenceAgent):
    """
    Specialized agent for technology trends, patents, and innovation monitoring
    """

    def __init__(self):
        super().__init__("technology_surveillance", "Technology Surveillance and Innovation Tracking")

    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute technology surveillance mission"""
        logger.info(f"🔬 {self.agent_id}: Starting technology surveillance mission")
        self.is_active = True
        self.current_task = "Technology trend analysis"

        try:
            focus_areas = mission_parameters.get('focus_areas', ['AI developments', 'patent filings', 'tech mergers'])
            research_topic = "Emerging technology trends and innovation developments"

            prompt = self._create_claude_prompt(research_topic, focus_areas)
            response = self._execute_claude_research(prompt)
            findings = self._parse_claude_response(response)
            self.findings.extend(findings)

            self.current_task = "Mission completed"
            logger.info(f"✅ {self.agent_id}: Mission completed - {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Mission failed: {e}")
            self.current_task = f"Mission failed: {str(e)}"
            return []
        finally:
            self.is_active = False

    def _get_specialization_guidelines(self) -> str:
        return """
- Monitor AI/ML breakthroughs and research publications
- Track patent filings and intellectual property developments
- Identify emerging technologies and innovation trends
- Analyze tech company strategies and product roadmaps
- Monitor regulatory changes affecting technology sectors
- Track cybersecurity threats and vulnerabilities
- Assess technology adoption rates and market penetration
"""

class PolicyMonitoringAgent(BaseIntelligenceAgent):
    """
    Specialized agent for policy changes, regulatory developments, and government communications
    """

    def __init__(self):
        super().__init__("policy_monitoring", "Policy Monitoring and Regulatory Analysis")

    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute policy monitoring mission"""
        logger.info(f"🏛️ {self.agent_id}: Starting policy monitoring mission")
        self.is_active = True
        self.current_task = "Policy change analysis"

        try:
            focus_areas = mission_parameters.get('focus_areas', ['regulatory changes', 'policy announcements'])
            research_topic = "Recent policy developments and regulatory changes"

            prompt = self._create_claude_prompt(research_topic, focus_areas)
            response = self._execute_claude_research(prompt)
            findings = self._parse_claude_response(response)
            self.findings.extend(findings)

            self.current_task = "Mission completed"
            logger.info(f"✅ {self.agent_id}: Mission completed - {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Mission failed: {e}")
            self.current_task = f"Mission failed: {str(e)}"
            return []
        finally:
            self.is_active = False

    def _get_specialization_guidelines(self) -> str:
        return """
- Monitor government policy announcements and regulatory changes
- Track legislative developments and congressional activities
- Analyze central bank and federal agency communications
- Identify compliance requirements and regulatory deadlines
- Monitor international policy developments and trade agreements
- Track election developments and political sentiment
- Assess policy impact on various industries and sectors
"""

class OSINTAnalysisAgent(BaseIntelligenceAgent):
    """
    Specialized agent for open source intelligence and social sentiment analysis
    """

    def __init__(self):
        super().__init__("osint_analysis", "Open Source Intelligence and Social Analysis")

    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute OSINT analysis mission"""
        logger.info(f"🔍 {self.agent_id}: Starting OSINT analysis mission")
        self.is_active = True
        self.current_task = "Social intelligence gathering"

        try:
            focus_areas = mission_parameters.get('focus_areas', ['social sentiment', 'information trends'])
            research_topic = "Open source intelligence and social media trends"

            prompt = self._create_claude_prompt(research_topic, focus_areas)
            response = self._execute_claude_research(prompt)
            findings = self._parse_claude_response(response)
            self.findings.extend(findings)

            self.current_task = "Mission completed"
            logger.info(f"✅ {self.agent_id}: Mission completed - {len(findings)} findings")
            return findings

        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Mission failed: {e}")
            self.current_task = f"Mission failed: {str(e)}"
            return []
        finally:
            self.is_active = False

    def _get_specialization_guidelines(self) -> str:
        return """
- Monitor social media trends and sentiment analysis
- Track information flow and narrative patterns
- Identify emerging topics and viral content
- Analyze public opinion and social movements
- Monitor online communities and forums
- Track disinformation and misinformation campaigns
- Assess social impact of news and events
"""

class SynthesisAgent(BaseIntelligenceAgent):
    """
    Specialized agent for cross-domain synthesis and pattern recognition
    """

    def __init__(self):
        super().__init__("synthesis_agent", "Cross-Domain Intelligence Synthesis")

    async def execute_intelligence_mission(self, mission_parameters: Dict[str, Any]) -> List[IntelligenceFinding]:
        """Execute cross-domain synthesis mission"""
        logger.info(f"🧠 {self.agent_id}: Starting cross-domain synthesis mission")
        self.is_active = True
        self.current_task = "Pattern synthesis analysis"

        try:
            # Get findings from other agents (passed via mission parameters)
            other_findings = mission_parameters.get('other_agent_findings', [])

            if not other_findings:
                logger.warning(f"⚠️ {self.agent_id}: No other agent findings to synthesize")
                return []

            focus_areas = mission_parameters.get('focus_areas', ['pattern recognition', 'cross-domain analysis'])

            # Create synthesis prompt
            findings_summary = "\n".join([
                f"- {finding.get('content', '')} (Confidence: {finding.get('confidence', 0):.2f})"
                for finding in other_findings[:10]  # Limit to prevent prompt overflow
            ])

            research_topic = f"Cross-domain pattern analysis based on these intelligence findings:\n{findings_summary}"

            prompt = self._create_claude_prompt(research_topic, focus_areas)
            response = self._execute_claude_research(prompt)
            findings = self._parse_claude_response(response)
            self.findings.extend(findings)

            self.current_task = "Mission completed"
            logger.info(f"✅ {self.agent_id}: Mission completed - {len(findings)} synthesis findings")
            return findings

        except Exception as e:
            logger.error(f"❌ {self.agent_id}: Mission failed: {e}")
            self.current_task = f"Mission failed: {str(e)}"
            return []
        finally:
            self.is_active = False

    def _get_specialization_guidelines(self) -> str:
        return """
- Identify patterns and connections across different intelligence domains
- Synthesize findings from market, technology, policy, and social intelligence
- Detect correlations and causal relationships between different events
- Generate meta-insights and strategic implications
- Identify contradictions or inconsistencies in intelligence
- Assess systemic risks and opportunities
- Provide holistic analysis and recommendations
"""

class IntelligenceAgentFactory:
    """Factory for creating specialized intelligence agents"""

    @staticmethod
    def create_agent(agent_type: str) -> BaseIntelligenceAgent:
        """Create a specialized intelligence agent"""
        agents = {
            "market_intelligence": MarketIntelligenceAgent,
            "technology_surveillance": TechnologySurveillanceAgent,
            "policy_monitoring": PolicyMonitoringAgent,
            "osint_analysis": OSINTAnalysisAgent,
            "synthesis_agent": SynthesisAgent
        }

        if agent_type not in agents:
            raise ValueError(f"Unknown agent type: {agent_type}")

        return agents[agent_type]()

    @staticmethod
    def get_available_agent_types() -> List[str]:
        """Get list of available agent types"""
        return [
            "market_intelligence",
            "technology_surveillance",
            "policy_monitoring",
            "osint_analysis",
            "synthesis_agent"
        ]

# Testing function
async def test_intelligence_agents():
    """Test the intelligence agents system"""
    logger.info("🧪 Testing Intelligence Agents system...")

    # Create test agents
    market_agent = IntelligenceAgentFactory.create_agent("market_intelligence")
    tech_agent = IntelligenceAgentFactory.create_agent("technology_surveillance")

    # Test mission parameters
    mission_params = {
        "focus_areas": ["AI developments", "market trends"],
        "burst_intensity": 7,
        "max_findings": 5
    }

    # Execute missions
    try:
        market_findings = await market_agent.execute_intelligence_mission(mission_params)
        tech_findings = await tech_agent.execute_intelligence_mission(mission_params)

        logger.info(f"Market findings: {len(market_findings)}")
        logger.info(f"Tech findings: {len(tech_findings)}")

        # Test synthesis
        synthesis_params = mission_params.copy()
        synthesis_params["other_agent_findings"] = [
            finding.__dict__ for finding in market_findings + tech_findings
        ]

        synthesis_agent = IntelligenceAgentFactory.create_agent("synthesis_agent")
        synthesis_findings = await synthesis_agent.execute_intelligence_mission(synthesis_params)

        logger.info(f"Synthesis findings: {len(synthesis_findings)}")

    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_intelligence_agents())