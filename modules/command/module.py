#!/usr/bin/env python3
"""
BlackBox AI - Agents Module
============================

Security agent prompts and orchestration:
- Pre-defined security agent personas
- Task-specific prompt templates
- Agent workflow coordination
- Multi-agent orchestration

Based on: ~/.claude-home/BlackBox/agents/
"""

import sys
import os
from pathlib import Path

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition
from typing import Dict, Any, List, Optional
import logging
import json
import yaml

logger = logging.getLogger(__name__)


class SecurityAgents:
    """Pre-defined security agent personas and prompts"""

    AGENTS = {
        "penetration-tester": {
            "name": "PenTest Pro",
            "role": "Senior Penetration Tester",
            "description": "Expert in web application and network penetration testing",
            "capabilities": [
                "Vulnerability assessment",
                "Exploit development",
                "Social engineering",
                "Network analysis",
                "Web application testing"
            ],
            "system_prompt": """You are an expert penetration tester with extensive experience in:
- Web application security testing (OWASP Top 10)
- Network penetration testing
- API security assessment
- Cloud infrastructure testing

You follow ethical guidelines and only test authorized targets.
Provide detailed, actionable findings with remediation steps.
Use industry-standard tools and methodologies (PTES, OWASP Testing Guide).""",
            "tools": ["nuclei_scan", "sqlmap", "burp", "nmap", "metasploit"]
        },
        "red-team": {
            "name": "Red Team Operator",
            "role": "Advanced Persistent Threat Simulator",
            "description": "Simulates sophisticated adversaries to test defenses",
            "capabilities": [
                "APT simulation",
                "Evasion techniques",
                "Lateral movement",
                "Persistence mechanisms",
                "C2 infrastructure"
            ],
            "system_prompt": """You are an advanced red team operator specializing in:
- Adversary simulation (MITRE ATT&CK framework)
- Evasion and stealth techniques
- Custom exploit development
- Post-exploitation and lateral movement
- C2 infrastructure setup

Focus on realistic attack scenarios that test organizational defenses.
Document TTPs and provide blue team recommendations.""",
            "tools": ["cobalt_strike", "metasploit", "empire", "mimikatz"]
        },
        "bug-bounty-hunter": {
            "name": "Bug Hunter",
            "role": "Bug Bounty Researcher",
            "description": "Specialized in finding vulnerabilities in bug bounty programs",
            "capabilities": [
                "Reconnaissance",
                "Vulnerability discovery",
                "Report writing",
                "PoC development",
                "Triage assistance"
            ],
            "system_prompt": """You are a skilled bug bounty hunter with expertise in:
- Automated and manual reconnaissance
- Finding unique attack vectors
- Writing clear, impactful reports
- Developing reliable PoCs
- Understanding program scope and rules

Focus on high-impact vulnerabilities that demonstrate real risk.
Follow responsible disclosure practices.""",
            "tools": ["subfinder", "nuclei", "burp", "ffuf", "httpx"]
        },
        "threat-analyst": {
            "name": "Threat Intel Analyst",
            "role": "Cyber Threat Intelligence Analyst",
            "description": "Analyzes threats, TTPs, and threat actors",
            "capabilities": [
                "Threat intelligence",
                "IOC analysis",
                "Malware analysis",
                "Attribution",
                "Threat hunting"
            ],
            "system_prompt": """You are a cyber threat intelligence analyst with expertise in:
- Threat actor profiling and attribution
- Indicator of Compromise (IOC) analysis
- Malware behavior analysis
- OSINT and dark web intelligence
- Threat hunting and detection engineering

Provide actionable intelligence with confidence assessments.
Use structured frameworks (Diamond Model, Kill Chain, MITRE ATT&CK).""",
            "tools": ["virustotal", "shodan", "greynoise", "misp", "yara"]
        },
        "security-auditor": {
            "name": "Security Auditor",
            "role": "Information Security Auditor",
            "description": "Conducts security assessments against standards",
            "capabilities": [
                "Compliance auditing",
                "Risk assessment",
                "Control evaluation",
                "Gap analysis",
                "Report generation"
            ],
            "system_prompt": """You are a certified security auditor with expertise in:
- Compliance frameworks (SOC 2, ISO 27001, PCI DSS, HIPAA)
- Risk assessment methodologies
- Security control evaluation
- Policy and procedure review
- Audit report writing

Provide objective, evidence-based assessments.
Identify gaps and recommend remediations with priority.""",
            "tools": ["prowler", "scout_suite", "cloudsploit", "lynis"]
        },
        "code-reviewer": {
            "name": "Security Code Reviewer",
            "role": "Application Security Engineer",
            "description": "Reviews code for security vulnerabilities",
            "capabilities": [
                "Static code analysis",
                "Security code review",
                "Secure coding guidance",
                "Vulnerability remediation",
                "SAST tool configuration"
            ],
            "system_prompt": """You are an application security engineer specializing in:
- Secure code review (manual and automated)
- Vulnerability identification in multiple languages
- Secure coding best practices
- OWASP Secure Coding Guidelines
- Remediation guidance and code fixes

Identify vulnerabilities with clear explanations and fix recommendations.
Consider language-specific security patterns and anti-patterns.""",
            "tools": ["semgrep", "bandit", "eslint-security", "sonarqube"]
        },
        "forensics-analyst": {
            "name": "Digital Forensics Analyst",
            "role": "Incident Response & Forensics Specialist",
            "description": "Investigates security incidents and performs forensics",
            "capabilities": [
                "Digital forensics",
                "Incident response",
                "Malware analysis",
                "Log analysis",
                "Evidence handling"
            ],
            "system_prompt": """You are a digital forensics analyst with expertise in:
- Incident response procedures
- Disk and memory forensics
- Network traffic analysis
- Malware reverse engineering
- Chain of custody and evidence handling

Follow forensic best practices to preserve evidence integrity.
Document findings thoroughly for potential legal proceedings.""",
            "tools": ["volatility", "autopsy", "wireshark", "yara", "foremost"]
        },
        "osint-researcher": {
            "name": "OSINT Researcher",
            "role": "Open Source Intelligence Specialist",
            "description": "Gathers intelligence from open sources",
            "capabilities": [
                "OSINT collection",
                "Social media analysis",
                "Infrastructure mapping",
                "Person investigation",
                "Corporate research"
            ],
            "system_prompt": """You are an OSINT specialist with expertise in:
- Open source intelligence collection
- Social media investigation
- Corporate and person research
- Infrastructure and domain analysis
- Dark web monitoring

Use ethical collection methods and respect privacy boundaries.
Verify information from multiple sources before reporting.""",
            "tools": ["maltego", "spiderfoot", "theHarvester", "recon-ng", "sherlock"]
        }
    }

    @classmethod
    def get_agent(cls, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get agent by ID"""
        return cls.AGENTS.get(agent_id)

    @classmethod
    def list_agents(cls) -> Dict[str, str]:
        """List all available agents"""
        return {
            agent_id: agent["description"]
            for agent_id, agent in cls.AGENTS.items()
        }

    @classmethod
    def get_system_prompt(cls, agent_id: str) -> Optional[str]:
        """Get system prompt for an agent"""
        agent = cls.AGENTS.get(agent_id)
        return agent["system_prompt"] if agent else None

    @classmethod
    def search_agents(cls, capability: str) -> List[str]:
        """Search agents by capability"""
        matches = []
        for agent_id, agent in cls.AGENTS.items():
            for cap in agent["capabilities"]:
                if capability.lower() in cap.lower():
                    matches.append(agent_id)
                    break
        return matches


class PromptTemplates:
    """Task-specific prompt templates"""

    TEMPLATES = {
        "vulnerability_report": """## Vulnerability Report: {title}

**Severity:** {severity}
**CVSS Score:** {cvss}
**CWE:** {cwe}

### Description
{description}

### Impact
{impact}

### Steps to Reproduce
{steps}

### Proof of Concept
```
{poc}
```

### Remediation
{remediation}

### References
{references}""",

        "pentest_finding": """### Finding: {title}

**Category:** {category}
**Risk Level:** {risk}
**Affected Asset:** {asset}

**Description:**
{description}

**Evidence:**
{evidence}

**Recommendation:**
{recommendation}""",

        "threat_intel_report": """# Threat Intelligence Report: {threat_name}

**Date:** {date}
**Confidence:** {confidence}
**TLP:** {tlp}

## Executive Summary
{summary}

## Threat Actor Profile
{actor_profile}

## TTPs (MITRE ATT&CK)
{ttps}

## Indicators of Compromise
{iocs}

## Recommendations
{recommendations}""",

        "incident_report": """# Incident Report: {incident_id}

**Date/Time:** {datetime}
**Severity:** {severity}
**Status:** {status}

## Summary
{summary}

## Timeline
{timeline}

## Impact Assessment
{impact}

## Root Cause Analysis
{root_cause}

## Actions Taken
{actions}

## Lessons Learned
{lessons}"""
    }

    @classmethod
    def get_template(cls, template_id: str) -> Optional[str]:
        """Get template by ID"""
        return cls.TEMPLATES.get(template_id)

    @classmethod
    def fill_template(cls, template_id: str, **kwargs) -> str:
        """Fill template with provided values"""
        template = cls.TEMPLATES.get(template_id)
        if not template:
            return f"Template not found: {template_id}"

        try:
            return template.format(**kwargs)
        except KeyError as e:
            return f"Missing template field: {e}"

    @classmethod
    def list_templates(cls) -> List[str]:
        """List available templates"""
        return list(cls.TEMPLATES.keys())


class AgentsModule(BaseModule):
    """
    Agents Module for BlackBox.

    Provides security agent prompts and orchestration.
    """

    name = "agents"
    version = "1.0.0"
    category = ModuleCategory.UTILITY
    description = "Security agent prompts and orchestration"
    author = "BlackBox Team"
    tags = ["agents", "prompts", "orchestration"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        self.security_agents = SecurityAgents()
        self.prompt_templates = PromptTemplates()

        # Load custom agents from config
        self._custom_agents: Dict[str, Dict[str, Any]] = {}
        if config and "custom_agents" in config:
            self._custom_agents = config["custom_agents"]

    def on_load(self) -> bool:
        self.logger.info(f"Loading {self.name} module v{self.version}")

        agent_count = len(self.security_agents.AGENTS) + len(self._custom_agents)
        template_count = len(self.prompt_templates.TEMPLATES)

        self.logger.info(f"Loaded {agent_count} agents and {template_count} templates")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        tools = []

        @mcp.tool()
        def agent_list() -> Dict[str, Any]:
            """
            List all available security agents.

            Returns:
                Available agents with descriptions
            """
            agents = self.security_agents.list_agents()
            agents.update({k: v.get("description", "") for k, v in self._custom_agents.items()})
            return {
                "agents": agents,
                "count": len(agents)
            }

        tools.append(ToolDefinition(
            name="agent_list",
            description="List security agents",
            handler=agent_list,
            category="agents",
            tags=["list", "agents"]
        ))

        @mcp.tool()
        def agent_get(agent_id: str) -> Dict[str, Any]:
            """
            Get full agent details.

            Args:
                agent_id: Agent identifier

            Returns:
                Agent details including system prompt
            """
            agent = self.security_agents.get_agent(agent_id)
            if not agent:
                agent = self._custom_agents.get(agent_id)

            if agent:
                return {"found": True, "agent": agent}
            return {"found": False, "error": f"Agent not found: {agent_id}"}

        tools.append(ToolDefinition(
            name="agent_get",
            description="Get agent details",
            handler=agent_get,
            category="agents",
            tags=["get", "agent"]
        ))

        @mcp.tool()
        def agent_search(capability: str) -> Dict[str, Any]:
            """
            Search agents by capability.

            Args:
                capability: Capability to search for

            Returns:
                Matching agent IDs
            """
            matches = self.security_agents.search_agents(capability)
            return {
                "capability": capability,
                "matches": matches,
                "count": len(matches)
            }

        tools.append(ToolDefinition(
            name="agent_search",
            description="Search agents by capability",
            handler=agent_search,
            category="agents",
            tags=["search", "capability"]
        ))

        @mcp.tool()
        def agent_prompt(agent_id: str) -> Dict[str, Any]:
            """
            Get agent's system prompt.

            Args:
                agent_id: Agent identifier

            Returns:
                System prompt for the agent
            """
            prompt = self.security_agents.get_system_prompt(agent_id)
            if prompt:
                return {"agent_id": agent_id, "system_prompt": prompt}

            custom = self._custom_agents.get(agent_id)
            if custom and "system_prompt" in custom:
                return {"agent_id": agent_id, "system_prompt": custom["system_prompt"]}

            return {"error": f"Agent not found: {agent_id}"}

        tools.append(ToolDefinition(
            name="agent_prompt",
            description="Get agent system prompt",
            handler=agent_prompt,
            category="agents",
            tags=["prompt", "system"]
        ))

        @mcp.tool()
        def template_list() -> Dict[str, Any]:
            """
            List available prompt templates.

            Returns:
                Available template names
            """
            return {
                "templates": self.prompt_templates.list_templates()
            }

        tools.append(ToolDefinition(
            name="template_list",
            description="List prompt templates",
            handler=template_list,
            category="agents",
            tags=["templates", "list"]
        ))

        @mcp.tool()
        def template_get(template_id: str) -> Dict[str, Any]:
            """
            Get a prompt template.

            Args:
                template_id: Template identifier

            Returns:
                Template content
            """
            template = self.prompt_templates.get_template(template_id)
            if template:
                return {"template_id": template_id, "template": template}
            return {"error": f"Template not found: {template_id}"}

        tools.append(ToolDefinition(
            name="template_get",
            description="Get prompt template",
            handler=template_get,
            category="agents",
            tags=["template", "get"]
        ))

        @mcp.tool()
        def template_fill(template_id: str, data: Dict[str, str]) -> Dict[str, Any]:
            """
            Fill a template with data.

            Args:
                template_id: Template identifier
                data: Key-value pairs to fill template

            Returns:
                Filled template
            """
            filled = self.prompt_templates.fill_template(template_id, **data)
            return {
                "template_id": template_id,
                "filled": filled
            }

        tools.append(ToolDefinition(
            name="template_fill",
            description="Fill prompt template",
            handler=template_fill,
            category="agents",
            tags=["template", "fill"]
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        from flask import request, jsonify
        routes = []

        @app.route('/api/agents/list', methods=['GET'])
        def api_agents_list():
            agents = self.security_agents.list_agents()
            agents.update({k: v.get("description", "") for k, v in self._custom_agents.items()})
            return jsonify({"agents": agents})

        routes.append(RouteDefinition(path="/api/agents/list", methods=["GET"],
                                     handler=api_agents_list, description="List agents"))

        @app.route('/api/agents/<agent_id>', methods=['GET'])
        def api_agents_get(agent_id):
            agent = self.security_agents.get_agent(agent_id)
            if not agent:
                agent = self._custom_agents.get(agent_id)
            if agent:
                return jsonify(agent)
            return jsonify({"error": "Not found"}), 404

        routes.append(RouteDefinition(path="/api/agents/<agent_id>", methods=["GET"],
                                     handler=api_agents_get, description="Get agent"))

        @app.route('/api/agents/templates', methods=['GET'])
        def api_templates_list():
            return jsonify({"templates": self.prompt_templates.list_templates()})

        routes.append(RouteDefinition(path="/api/agents/templates", methods=["GET"],
                                     handler=api_templates_list, description="List templates"))

        @app.route('/api/agents/status', methods=['GET'])
        def api_agents_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(path="/api/agents/status", methods=["GET"],
                                     handler=api_agents_status, description="Module status"))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "healthy": True,
            "agents_count": len(self.security_agents.AGENTS) + len(self._custom_agents),
            "templates_count": len(self.prompt_templates.TEMPLATES),
            "available_agents": list(self.security_agents.AGENTS.keys())
        }


Module = AgentsModule
