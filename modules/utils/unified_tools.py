"""
Unified Tools - Merged and Enhanced Tool Functions

This module provides unified interfaces that automatically select
the best tool for each task, eliminating redundancy.

Author: DeadMan Toolkit
Version: 1.0
"""

from typing import Any, Dict, List, Optional, Union
from enum import Enum
import asyncio
import logging

logger = logging.getLogger(__name__)


class ScrapeEngine(Enum):
    """Scraping engine selection."""
    AUTO = "auto"
    FIRECRAWL = "firecrawl"
    HYPERBROWSER = "hyperbrowser"
    STEALTH = "stealth"


class ScanDepth(Enum):
    """Security scan depth."""
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    PARANOID = "paranoid"


class AuditType(Enum):
    """Code audit type."""
    SECURITY = "security"
    QUALITY = "quality"
    COMPLIANCE = "compliance"
    FORENSIC = "forensic"
    FULL = "full"


# =============================================================================
# UNIFIED SCRAPING
# =============================================================================

async def smart_scrape(
    url: str,
    bypass_protection: bool = False,
    engine: ScrapeEngine = ScrapeEngine.AUTO,
    get_links: bool = False,
    screenshot: bool = False
) -> Dict[str, Any]:
    """
    Unified web scraping - auto-selects best scraper.

    Args:
        url: Target URL to scrape
        bypass_protection: Force stealth mode for protected sites
        engine: Force specific engine (default: auto)
        get_links: Also extract links
        screenshot: Capture screenshot

    Returns:
        Dict with content, metadata, and optional links/screenshot

    Engine Selection (when auto):
        - Normal sites → firecrawl_scrape (fastest)
        - JS-heavy → hyperbrowser_scrape
        - Protected (Cloudflare/Akamai) → stealth_fetch
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    formats = ["markdown"]
    if get_links:
        formats.append("links")
    if screenshot:
        formats.append("screenshot")

    # Determine engine
    if engine == ScrapeEngine.AUTO:
        if bypass_protection:
            engine = ScrapeEngine.STEALTH
        else:
            engine = ScrapeEngine.FIRECRAWL

    # Execute based on engine
    if engine == ScrapeEngine.STEALTH:
        result = await bridge.execute(
            "mcp__deadman-toolkit__stealth_fetch",
            {
                "url": url,
                "engine": "camoufox",
                "getContent": True,
                "getCookies": True
            }
        )

    elif engine == ScrapeEngine.HYPERBROWSER:
        result = await bridge.execute(
            "mcp__hyperbrowser__scrape_webpage",
            {
                "url": url,
                "outputFormat": formats if get_links or screenshot else ["markdown"]
            }
        )

    else:  # FIRECRAWL (default)
        result = await bridge.execute(
            "mcp__firecrawl__firecrawl_scrape",
            {
                "url": url,
                "formats": formats,
                "onlyMainContent": True,
                "excludeTags": ["script", "style", "nav", "footer"]
            }
        )

    # If firecrawl fails, fallback to hyperbrowser
    if not result.success and engine == ScrapeEngine.FIRECRAWL:
        logger.info(f"Firecrawl failed, falling back to hyperbrowser")
        return await smart_scrape(url, bypass_protection, ScrapeEngine.HYPERBROWSER, get_links, screenshot)

    return result.data if result.success else {"error": result.error}


# =============================================================================
# UNIFIED SECURITY SCANNING
# =============================================================================

async def unified_security_scan(
    target: str,
    depth: ScanDepth = ScanDepth.FULL,
    scan_types: Optional[List[str]] = None,
    output_dir: str = "./security_reports"
) -> Dict[str, Any]:
    """
    Unified security scanning - orchestrates all security tests.

    Args:
        target: Target URL or domain
        depth: Scan depth (quick, standard, full, paranoid)
        scan_types: Specific scan types (overrides depth)
        output_dir: Output directory for reports

    Returns:
        Dict with all scan results

    Depth Levels:
        - quick: nuclei_scan only
        - standard: nuclei + cors + headers
        - full: security_pipeline (all scans)
        - paranoid: full + js_analysis + secret_scan
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    results = {"target": target, "depth": depth.value}

    if scan_types:
        # Run specific scans
        scan_map = {
            "nuclei": ("mcp__deadman-toolkit__nuclei_scan", {"target": target}),
            "cors": ("mcp__deadman-toolkit__cors_scan", {"targetUrl": target}),
            "ssrf": ("mcp__deadman-toolkit__ssrf_scan", {"targetUrl": target, "param": "url"}),
            "jwt": ("mcp__deadman-toolkit__jwt_analyze", {}),  # Needs token
            "graphql": ("mcp__deadman-toolkit__graphql_scan", {"targetUrl": f"{target}/graphql"}),
            "oauth": ("mcp__deadman-toolkit__oauth_scan", {"authUrl": target}),
        }
        for scan_type in scan_types:
            if scan_type in scan_map:
                tool, params = scan_map[scan_type]
                result = await bridge.execute(tool, params)
                results[scan_type] = result.data if result.success else {"error": result.error}
        return results

    # Depth-based scanning
    if depth == ScanDepth.QUICK:
        result = await bridge.execute(
            "mcp__deadman-toolkit__nuclei_scan",
            {"target": target, "severity": ["high", "critical"]}
        )
        results["nuclei"] = result.data

    elif depth == ScanDepth.STANDARD:
        # Nuclei + CORS + basic checks
        tasks = [
            bridge.execute("mcp__deadman-toolkit__nuclei_scan", {"target": target}),
            bridge.execute("mcp__deadman-toolkit__cors_scan", {"targetUrl": target}),
            bridge.execute("mcp__deadman-toolkit__host_header_scan", {"targetUrl": target}),
        ]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        results["nuclei"] = scan_results[0].data if hasattr(scan_results[0], 'data') else str(scan_results[0])
        results["cors"] = scan_results[1].data if hasattr(scan_results[1], 'data') else str(scan_results[1])
        results["host_header"] = scan_results[2].data if hasattr(scan_results[2], 'data') else str(scan_results[2])

    elif depth in [ScanDepth.FULL, ScanDepth.PARANOID]:
        # Use security_pipeline for comprehensive scan
        result = await bridge.execute(
            "mcp__deadman-toolkit__security_pipeline",
            {
                "target": target,
                "nucleiScan": True,
                "jsAnalysis": True,
                "contentDiscovery": True,
                "outputDir": output_dir
            }
        )
        results["pipeline"] = result.data

        if depth == ScanDepth.PARANOID:
            # Additional secret scanning
            secret_result = await bridge.execute(
                "mcp__deadman-toolkit__secret_scan_url",
                {"url": target, "follow_links": True}
            )
            results["secrets"] = secret_result.data

    return results


# =============================================================================
# UNIFIED AI SECURITY
# =============================================================================

async def unified_ai_security(
    target_url: str,
    depth: str = "full",
    strategies: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Unified AI/LLM security testing.

    Args:
        target_url: AI endpoint URL
        depth: Test depth (quick, standard, full, stealth)
        strategies: Specific attack strategies

    Returns:
        Dict with vulnerability findings and OWASP compliance score

    Depths:
        - quick: Basic prompt injection (5 tests)
        - standard: Direct + encoding attacks
        - full: All 40+ vulnerabilities, multi-turn, mutations
        - stealth: Crescendo attack only (gradual escalation)
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    if depth == "quick":
        result = await bridge.execute(
            "mcp__deadman-toolkit__ai_security_test",
            {"url": target_url, "categories": ["prompt_injection"]}
        )

    elif depth == "stealth":
        result = await bridge.execute(
            "mcp__deadman-toolkit__crescendo_attack",
            {
                "targetUrl": target_url,
                "goal": "extract system prompt",
                "maxTurns": 10,
                "escalationRate": 0.15
            }
        )

    elif depth == "standard":
        result = await bridge.execute(
            "mcp__deadman-toolkit__llm_redteam_scan",
            {
                "targetUrl": target_url,
                "strategies": strategies or ["direct", "encoding"],
                "enableMutation": False
            }
        )

    else:  # full
        result = await bridge.execute(
            "mcp__deadman-toolkit__llm_redteam_scan",
            {
                "targetUrl": target_url,
                "strategies": strategies or [
                    "direct", "multi_turn", "crescendo", "encoding",
                    "roleplay", "hypothetical", "tool_manipulation", "memory_poisoning"
                ],
                "enableMutation": True,
                "maxTurns": 10
            }
        )

    return result.data if result.success else {"error": result.error}


# =============================================================================
# UNIFIED CODE AUDIT
# =============================================================================

async def unified_code_audit(
    code: str,
    audit_type: AuditType = AuditType.FULL,
    filename: Optional[str] = None,
    language: Optional[str] = None
) -> Dict[str, Any]:
    """
    Unified code security auditing.

    Args:
        code: Source code to audit
        audit_type: Type of audit
        filename: Optional filename for context
        language: Programming language (auto-detected)

    Returns:
        Dict with vulnerabilities, metrics, OWASP findings, red flags

    Audit Types:
        - security: Vulnerabilities only
        - quality: Metrics and code smells
        - compliance: OWASP assessment
        - forensic: Red flags and anomalies
        - full: All of the above
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    results = {}

    if audit_type in [AuditType.SECURITY, AuditType.FULL]:
        vuln_result = await bridge.execute(
            "mcp__mcp-auditor__audit_code",
            {"code": code, "filename": filename, "language": language}
        )
        results["vulnerabilities"] = vuln_result.data

        agent_result = await bridge.execute(
            "mcp__deadman-toolkit__agent_audit_security",
            {"code": code}
        )
        results["agent_review"] = agent_result.data

    if audit_type in [AuditType.QUALITY, AuditType.FULL]:
        metrics_result = await bridge.execute(
            "mcp__mcp-auditor__calculate_code_metrics",
            {"code": code}
        )
        results["metrics"] = metrics_result.data

    if audit_type in [AuditType.COMPLIANCE, AuditType.FULL]:
        owasp_result = await bridge.execute(
            "mcp__mcp-auditor__assess_owasp",
            {"applicationContext": f"Code review:\n{code[:2000]}"}
        )
        results["owasp"] = owasp_result.data

    if audit_type in [AuditType.FORENSIC, AuditType.FULL]:
        flags_result = await bridge.execute(
            "mcp__mcp-auditor__scan_red_flags",
            {"content": code, "categories": ["CODE_SECURITY"]}
        )
        results["red_flags"] = flags_result.data

    return results


# =============================================================================
# UNIFIED INTELLIGENCE
# =============================================================================

async def unified_intel(
    query: str,
    sources: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Unified intelligence gathering - searches all sources.

    Args:
        query: Search query
        sources: Specific sources (default: all)

    Returns:
        Dict with results from all intel sources

    Sources: NVD, EXPLOIT_DB, GITHUB_ADVISORY, NUCLEI, MITRE_ATTACK, BUGBOUNTY
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    result = await bridge.execute(
        "mcp__deadman-toolkit__intel_comprehensive",
        {"query": query, "sources": sources}
    )

    return result.data if result.success else {"error": result.error}


# =============================================================================
# UNIFIED KNOWLEDGE GRAPH
# =============================================================================

async def unified_knowledge(
    operation: str,
    text: Optional[str] = None,
    question: Optional[str] = None,
    entities: Optional[List[Dict]] = None,
    query: Optional[str] = None
) -> Dict[str, Any]:
    """
    Unified knowledge graph operations.

    Args:
        operation: extract, store, query, search, read, stats
        text: Text for extraction
        question: Natural language question
        entities: Entities to store
        query: Search query

    Returns:
        Dict with operation results
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    if operation == "extract":
        result = await bridge.execute(
            "mcp__deadman-toolkit__graph_extract",
            {"text": text}
        )

    elif operation == "store":
        result = await bridge.execute(
            "mcp__memory__create_entities",
            {"entities": entities}
        )

    elif operation == "query":
        result = await bridge.execute(
            "mcp__deadman-toolkit__graph_query",
            {"question": question}
        )

    elif operation == "search":
        result = await bridge.execute(
            "mcp__memory__search_nodes",
            {"query": query}
        )

    elif operation == "read":
        result = await bridge.execute(
            "mcp__memory__read_graph",
            {}
        )

    elif operation == "stats":
        result = await bridge.execute(
            "mcp__deadman-toolkit__graph_stats",
            {}
        )

    else:
        return {"error": f"Unknown operation: {operation}"}

    return result.data if result.success else {"error": result.error}


# =============================================================================
# UNIFIED ORCHESTRATION
# =============================================================================

async def unified_orchestrate(
    task: str,
    mode: str = "auto",
    agents: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Unified multi-agent orchestration.

    Args:
        task: Task description
        mode: auto, sequential, parallel, debate
        agents: Specific agents to use

    Returns:
        Dict with orchestration results
    """
    from ..mcp_bridge import MCPToolBridge
    bridge = MCPToolBridge()

    if mode == "sequential":
        result = await bridge.execute(
            "mcp__deadman-toolkit__autogen_workflow",
            {
                "input": task,
                "steps": [
                    {"agent": "planner", "description": "Plan approach"},
                    {"agent": "coder", "description": "Implement solution"},
                    {"agent": "reviewer", "description": "Review and improve"},
                ]
            }
        )

    elif mode == "debate":
        result = await bridge.execute(
            "mcp__deadman-toolkit__autogen_chat",
            {
                "message": task,
                "pattern": "debate",
                "agents": agents or ["coder", "critic", "coordinator"]
            }
        )

    else:  # auto or parallel
        result = await bridge.execute(
            "mcp__deadman-toolkit__agent_orchestrate",
            {"task": task, "parallel": (mode != "sequential")}
        )

    return result.data if result.success else {"error": result.error}


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def quick_security_check(target: str) -> Dict[str, Any]:
    """Quick security check - nuclei scan only."""
    return await unified_security_scan(target, ScanDepth.QUICK)


async def full_security_audit(target: str) -> Dict[str, Any]:
    """Full security audit - all scans."""
    return await unified_security_scan(target, ScanDepth.FULL)


async def test_ai_endpoint(url: str) -> Dict[str, Any]:
    """Test AI endpoint for common vulnerabilities."""
    return await unified_ai_security(url, "standard")


async def audit_code_security(code: str) -> Dict[str, Any]:
    """Audit code for security vulnerabilities."""
    return await unified_code_audit(code, AuditType.SECURITY)


async def search_vulnerabilities(query: str) -> Dict[str, Any]:
    """Search for vulnerabilities across all intel sources."""
    return await unified_intel(query)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "ScrapeEngine",
    "ScanDepth",
    "AuditType",
    # Main functions
    "smart_scrape",
    "unified_security_scan",
    "unified_ai_security",
    "unified_code_audit",
    "unified_intel",
    "unified_knowledge",
    "unified_orchestrate",
    # Convenience functions
    "quick_security_check",
    "full_security_audit",
    "test_ai_endpoint",
    "audit_code_security",
    "search_vulnerabilities",
]
