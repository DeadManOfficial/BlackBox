"""
Mission Commander - Orchestrator Agent for Intelligence Operations
NASA Systems Engineering inspired autonomous research coordination
"""

import asyncio
import logging
import sqlite3
import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class MissionParameters:
    burst_intensity: int = 5  # 1-10 scale
    alert_threshold: float = 0.7  # 0.1-1.0 confidence threshold
    focus_areas: List[str] = None  # Which agent types to activate
    max_burst_duration: int = 15 * 60  # 15 minutes in seconds
    burst_interval: int = 2 * 60 * 60  # 2 hours in seconds

    def __post_init__(self):
        if self.focus_areas is None:
            self.focus_areas = ["market_intelligence", "technology_surveillance"]

@dataclass
class MissionCycle:
    cycle_id: str
    start_time: datetime
    end_time: Optional[datetime]
    status: str  # planning, executing, completed, failed
    intelligence_count: int
    parameters: MissionParameters

@dataclass
class AgentTelemetry:
    agent_id: str
    status: str  # idle, active, completed, failed
    current_task: str
    confidence: float
    progress: int  # 0-100
    last_active: datetime
    findings_count: int

class MissionCommander:
    """
    Mission Commander - Central orchestrator for intelligence operations
    Implements NASA systems engineering principles for autonomous coordination
    """

    def __init__(self, db_path: str = "mission_control.db"):
        self.db_path = db_path
        self.mission_active = False
        self.current_cycle: Optional[MissionCycle] = None
        self.agents_status: Dict[str, AgentTelemetry] = {}
        self.mission_parameters: Optional[MissionParameters] = None
        self.intelligence_findings = []

        self.initialize_database()
        self.initialize_agents()

    def initialize_database(self):
        """Initialize mission control database schema"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Mission cycles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS mission_cycles (
                    cycle_id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    intelligence_count INTEGER DEFAULT 0,
                    parameters TEXT NOT NULL
                )
            ''')

            # Agent telemetry table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cycle_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_task TEXT,
                    confidence REAL,
                    progress INTEGER,
                    timestamp TEXT NOT NULL,
                    findings_count INTEGER DEFAULT 0,
                    FOREIGN KEY (cycle_id) REFERENCES mission_cycles (cycle_id)
                )
            ''')

            # Intelligence findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS intelligence_findings (
                    finding_id TEXT PRIMARY KEY,
                    cycle_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    priority INTEGER NOT NULL,
                    source_urls TEXT,
                    timestamp TEXT NOT NULL,
                    tags TEXT,
                    metadata TEXT,
                    FOREIGN KEY (cycle_id) REFERENCES mission_cycles (cycle_id)
                )
            ''')

            conn.commit()
            conn.close()
            logger.info("✅ Mission database initialized")

        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise

    def initialize_agents(self):
        """Initialize agent telemetry tracking"""
        agent_types = [
            "market_intelligence",
            "technology_surveillance",
            "policy_monitoring",
            "osint_analysis",
            "synthesis_agent"
        ]

        for agent_id in agent_types:
            self.agents_status[agent_id] = AgentTelemetry(
                agent_id=agent_id,
                status="idle",
                current_task="Standby",
                confidence=0.0,
                progress=0,
                last_active=datetime.now(),
                findings_count=0
            )

        logger.info(f"🤖 Initialized {len(agent_types)} intelligence agents")

    async def start_mission(self, parameters: MissionParameters):
        """Start a new intelligence gathering mission"""
        if self.mission_active:
            raise Exception("Mission already active")

        try:
            logger.info("🚀 Mission Commander: Starting intelligence operations")

            self.mission_active = True
            self.mission_parameters = parameters

            # Create new mission cycle
            cycle_id = f"MISSION_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.current_cycle = MissionCycle(
                cycle_id=cycle_id,
                start_time=datetime.now(),
                end_time=None,
                status="executing",
                intelligence_count=0,
                parameters=parameters
            )

            # Store mission cycle in database
            self._store_mission_cycle(self.current_cycle)

            logger.info(f"📋 Mission Cycle {cycle_id} initiated")
            logger.info(f"🎯 Focus Areas: {', '.join(parameters.focus_areas)}")
            logger.info(f"⚡ Burst Intensity: {parameters.burst_intensity}/10")

            # Start mission loop
            await self._execute_mission_loop()

        except Exception as e:
            logger.error(f"❌ Mission start failed: {e}")
            self.mission_active = False
            if self.current_cycle:
                self.current_cycle.status = "failed"
                self._store_mission_cycle(self.current_cycle)
            raise

    async def stop_mission(self):
        """Stop the active mission"""
        if not self.mission_active:
            return

        logger.info("🛑 Mission Commander: Terminating operations")

        self.mission_active = False

        if self.current_cycle:
            self.current_cycle.end_time = datetime.now()
            self.current_cycle.status = "completed"
            self._store_mission_cycle(self.current_cycle)

        # Reset agent statuses
        for agent_id in self.agents_status:
            self.agents_status[agent_id].status = "idle"
            self.agents_status[agent_id].current_task = "Standby"
            self.agents_status[agent_id].progress = 0

        logger.info("✅ Mission terminated successfully")

    async def _execute_mission_loop(self):
        """Main mission execution loop with 15-minute bursts every 2 hours"""
        try:
            while self.mission_active:
                logger.info("🔥 Initiating intelligence burst...")

                # Execute intelligence burst
                await self._execute_intelligence_burst()

                if not self.mission_active:
                    break

                # Wait for next burst (2 hours)
                logger.info(f"⏰ Next burst in {self.mission_parameters.burst_interval // 3600} hours")

                # Sleep in small intervals to allow for mission termination
                elapsed = 0
                while elapsed < self.mission_parameters.burst_interval and self.mission_active:
                    await asyncio.sleep(60)  # Check every minute
                    elapsed += 60

        except Exception as e:
            logger.error(f"❌ Mission loop failed: {e}")
            self.mission_active = False
            if self.current_cycle:
                self.current_cycle.status = "failed"
                self._store_mission_cycle(self.current_cycle)

    async def _execute_intelligence_burst(self):
        """Execute a 15-minute intelligence gathering burst"""
        logger.info("🚨 Intelligence burst commencing...")
        burst_start = time.time()

        try:
            # Import agent factory here to avoid circular imports
            from intelligence_agents import IntelligenceAgentFactory

            # Create mission parameters for agents
            mission_params = {
                "focus_areas": self.mission_parameters.focus_areas,
                "burst_intensity": self.mission_parameters.burst_intensity,
                "max_findings": 10,
                "confidence_threshold": self.mission_parameters.alert_threshold
            }

            # Execute specialized agents in parallel
            active_agents = []
            for agent_type in self.mission_parameters.focus_areas:
                if agent_type in self.agents_status:
                    # Update agent status
                    self.agents_status[agent_type].status = "active"
                    self.agents_status[agent_type].current_task = "Intelligence gathering"
                    self.agents_status[agent_type].progress = 10
                    self.agents_status[agent_type].last_active = datetime.now()

                    # Create and execute agent
                    try:
                        agent = IntelligenceAgentFactory.create_agent(agent_type)
                        task = asyncio.create_task(agent.execute_intelligence_mission(mission_params))
                        active_agents.append((agent_type, task))

                        logger.info(f"🤖 {agent_type} agent activated")
                    except Exception as e:
                        logger.error(f"❌ Failed to activate {agent_type}: {e}")
                        self.agents_status[agent_type].status = "failed"
                        self.agents_status[agent_type].current_task = f"Failed: {str(e)}"

            # Monitor agents and collect findings
            all_findings = []
            completed_agents = 0

            while active_agents and (time.time() - burst_start) < self.mission_parameters.max_burst_duration:
                # Check for completed agents
                for i, (agent_type, task) in enumerate(active_agents[:]):
                    if task.done():
                        try:
                            findings = await task
                            all_findings.extend(findings)

                            # Update agent status
                            self.agents_status[agent_type].status = "completed"
                            self.agents_status[agent_type].current_task = "Mission completed"
                            self.agents_status[agent_type].progress = 100
                            self.agents_status[agent_type].findings_count = len(findings)
                            self.agents_status[agent_type].confidence = (
                                sum(f.confidence_score for f in findings) / len(findings)
                                if findings else 0.0
                            )

                            completed_agents += 1
                            active_agents.remove((agent_type, task))

                            logger.info(f"✅ {agent_type} completed - {len(findings)} findings")

                        except Exception as e:
                            logger.error(f"❌ {agent_type} failed: {e}")
                            self.agents_status[agent_type].status = "failed"
                            self.agents_status[agent_type].current_task = f"Failed: {str(e)}"
                            active_agents.remove((agent_type, task))

                # Update progress for active agents
                for agent_type, task in active_agents:
                    elapsed_pct = min(90, int(((time.time() - burst_start) / self.mission_parameters.max_burst_duration) * 90))
                    self.agents_status[agent_type].progress = elapsed_pct

                await asyncio.sleep(5)  # Check every 5 seconds

            # Cancel any remaining agents if burst time exceeded
            for agent_type, task in active_agents:
                if not task.done():
                    task.cancel()
                    self.agents_status[agent_type].status = "timeout"
                    self.agents_status[agent_type].current_task = "Burst timeout"
                    logger.warning(f"⏰ {agent_type} timed out")

            # Execute synthesis if we have findings from multiple agents
            if len(all_findings) > 1:
                logger.info("🧠 Executing cross-domain synthesis...")
                await self._execute_synthesis(all_findings, mission_params)

            # Store findings in database
            for finding in all_findings:
                self._store_intelligence_finding(finding)

            # Update mission cycle
            if self.current_cycle:
                self.current_cycle.intelligence_count += len(all_findings)
                self._store_mission_cycle(self.current_cycle)

            burst_duration = time.time() - burst_start
            logger.info(f"🎯 Burst completed - {len(all_findings)} total findings in {burst_duration:.1f}s")

        except Exception as e:
            logger.error(f"❌ Intelligence burst failed: {e}")

    async def _execute_synthesis(self, findings: List, mission_params: Dict):
        """Execute synthesis agent to find cross-domain patterns"""
        try:
            from intelligence_agents import IntelligenceAgentFactory

            synthesis_params = mission_params.copy()
            synthesis_params["other_agent_findings"] = [
                {
                    "content": finding.content,
                    "confidence": finding.confidence_score,
                    "agent_id": finding.agent_id,
                    "finding_type": finding.finding_type
                }
                for finding in findings[:10]  # Limit to prevent prompt overflow
            ]

            # Update synthesis agent status
            self.agents_status["synthesis_agent"].status = "active"
            self.agents_status["synthesis_agent"].current_task = "Cross-domain analysis"
            self.agents_status["synthesis_agent"].progress = 50

            synthesis_agent = IntelligenceAgentFactory.create_agent("synthesis_agent")
            synthesis_findings = await synthesis_agent.execute_intelligence_mission(synthesis_params)

            # Update synthesis agent completion
            self.agents_status["synthesis_agent"].status = "completed"
            self.agents_status["synthesis_agent"].current_task = "Synthesis completed"
            self.agents_status["synthesis_agent"].progress = 100
            self.agents_status["synthesis_agent"].findings_count = len(synthesis_findings)

            # Store synthesis findings
            for finding in synthesis_findings:
                self._store_intelligence_finding(finding)

            logger.info(f"🧠 Synthesis completed - {len(synthesis_findings)} meta-insights")

        except Exception as e:
            logger.error(f"❌ Synthesis failed: {e}")
            self.agents_status["synthesis_agent"].status = "failed"
            self.agents_status["synthesis_agent"].current_task = f"Failed: {str(e)}"

    async def execute_emergency_burst(self):
        """Execute immediate intelligence burst for emergency situations"""
        logger.info("🚨 Emergency intelligence burst initiated")
        await self._execute_intelligence_burst()

    def get_mission_status(self) -> Dict[str, Any]:
        """Get current mission status for API/UI"""
        if not self.current_cycle:
            return {
                "mission_active": False,
                "phase": "DORMANT",
                "intelligence_count": 0,
                "agents": {}
            }

        return {
            "mission_active": self.mission_active,
            "phase": self.current_cycle.status.upper(),
            "cycle_id": self.current_cycle.cycle_id,
            "intelligence_count": self.current_cycle.intelligence_count,
            "start_time": self.current_cycle.start_time.isoformat(),
            "agents": {agent_id: asdict(telemetry) for agent_id, telemetry in self.agents_status.items()}
        }

    def get_agents_status(self) -> Dict[str, Dict]:
        """Get status of all intelligence agents"""
        return {agent_id: asdict(telemetry) for agent_id, telemetry in self.agents_status.items()}

    def update_parameters(self, new_params: Dict[str, Any]):
        """Update mission parameters during active operation"""
        if self.mission_parameters:
            if "burst_intensity" in new_params:
                self.mission_parameters.burst_intensity = new_params["burst_intensity"]
            if "alert_threshold" in new_params:
                self.mission_parameters.alert_threshold = new_params["alert_threshold"]
            if "focus_areas" in new_params:
                self.mission_parameters.focus_areas = new_params["focus_areas"]

            logger.info("🔧 Mission parameters updated")

    def export_mission_data(self) -> Dict[str, Any]:
        """Export complete mission data for analysis"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get mission cycles
            cursor.execute("SELECT * FROM mission_cycles")
            cycles = cursor.fetchall()

            # Get intelligence findings
            cursor.execute("SELECT * FROM intelligence_findings")
            findings = cursor.fetchall()

            # Get agent telemetry
            cursor.execute("SELECT * FROM agent_telemetry")
            telemetry = cursor.fetchall()

            conn.close()

            return {
                "export_timestamp": datetime.now().isoformat(),
                "mission_cycles": cycles,
                "intelligence_findings": findings,
                "agent_telemetry": telemetry,
                "current_status": self.get_mission_status()
            }

        except Exception as e:
            logger.error(f"❌ Export failed: {e}")
            return {"error": str(e)}

    def _store_mission_cycle(self, cycle: MissionCycle):
        """Store mission cycle in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO mission_cycles
                (cycle_id, start_time, end_time, status, intelligence_count, parameters)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                cycle.cycle_id,
                cycle.start_time.isoformat(),
                cycle.end_time.isoformat() if cycle.end_time else None,
                cycle.status,
                cycle.intelligence_count,
                json.dumps(asdict(cycle.parameters))
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"❌ Failed to store mission cycle: {e}")

    def _store_intelligence_finding(self, finding):
        """Store intelligence finding in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO intelligence_findings
                (finding_id, cycle_id, agent_id, finding_type, content, confidence_score,
                 priority, source_urls, timestamp, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding.finding_id,
                self.current_cycle.cycle_id if self.current_cycle else "UNKNOWN",
                finding.agent_id,
                finding.finding_type,
                finding.content,
                finding.confidence_score,
                finding.priority,
                json.dumps(finding.source_urls),
                finding.timestamp.isoformat(),
                json.dumps(finding.tags),
                json.dumps(finding.metadata)
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            logger.error(f"❌ Failed to store finding: {e}")

# Testing function
async def test_mission_commander():
    """Test the mission commander system"""
    logger.info("🧪 Testing Mission Commander...")

    commander = MissionCommander()

    # Test mission parameters
    params = MissionParameters(
        burst_intensity=7,
        alert_threshold=0.8,
        focus_areas=["market_intelligence", "technology_surveillance"],
        max_burst_duration=5 * 60,  # 5 minutes for testing
        burst_interval=10 * 60  # 10 minutes for testing
    )

    try:
        # Start mission
        await commander.start_mission(params)

        # Let it run for a bit
        await asyncio.sleep(30)

        # Check status
        status = commander.get_mission_status()
        logger.info(f"Mission status: {status}")

        # Stop mission
        await commander.stop_mission()

        logger.info("✅ Mission Commander test completed")

    except Exception as e:
        logger.error(f"❌ Test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_mission_commander())