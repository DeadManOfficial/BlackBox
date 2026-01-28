"""
BlackBox Tools - Unified Security Tool Interface
================================================

ALL security tools consolidated in one location.
No MCP dependency - tools work standalone or via MCP transport.

Directory Structure:
    tools/
    ├── scanners/    # nuclei, js_analyze, secret_scan
    ├── attacks/     # ssrf, cors, ssti, xxe, sqli, etc.
    ├── recon/       # api_enumerate, subdomain, fingerprint
    ├── ai/          # llm_redteam, ai_security, prompt_inject
    ├── intel/       # cve_search, exploit_search, mitre
    ├── audit/       # code_audit, compliance, owasp
    ├── stealth/     # waf_bypass, stealth_fetch
    └── pentest/     # autonomous pentest, attack_path

Usage:
    from blackbox.tools import scanner, attacks, recon, ai, intel

    # Run a scan
    results = scanner.nuclei_scan(target="example.com")

    # Check for SSRF
    results = attacks.ssrf_scan(url="https://example.com/api", param="url")
"""

__version__ = "1.0.0"
__author__ = "DeadManOfficial"

# Tool categories
TOOL_CATEGORIES = {
    "scanners": [
        "nuclei_scan", "nuclei_templates",
        "js_analyze", "js_analyze_batch", "js_patterns",
        "secret_scan_git", "secret_scan_files", "secret_scan_url",
        "secret_patterns", "secret_entropy_check"
    ],
    "attacks": [
        "ssrf_scan", "cors_scan", "ssti_scan", "xxe_scan",
        "host_header_scan", "path_traversal_scan", "command_injection_scan",
        "crlf_scan", "graphql_scan", "websocket_scan",
        "http_smuggling_scan", "cache_poisoning_scan", "subdomain_takeover_scan",
        "race_condition_scan", "race_condition_batch"
    ],
    "recon": [
        "api_enumerate", "subdomain_enum", "tech_fingerprint"
    ],
    "ai": [
        "ai_security_test", "ai_security_categories",
        "llm_redteam_scan", "llm_redteam_categories", "llm_redteam_payloads",
        "indirect_injection_test", "indirect_injection_methods",
        "crescendo_attack"
    ],
    "intel": [
        "intel_cve_search", "intel_exploit_search", "intel_github_advisory",
        "intel_nuclei_templates", "intel_bugbounty", "intel_mitre_attack",
        "intel_comprehensive", "intel_tech_vulns", "intel_sources"
    ],
    "audit": [
        "audit_code", "scan_red_flags", "analyze_dependencies",
        "assess_owasp", "assess_compliance"
    ],
    "stealth": [
        "stealth_fetch", "stealth_session", "stealth_engines",
        "waf_bypass_scan", "waf_bypass_request"
    ],
    "pentest": [
        "pentest_run", "pentest_attack_path", "pentest_tools"
    ],
    "auth": [
        "jwt_analyze", "oauth_scan",
        "auth_flow_attack", "idor_scan", "db_error_exploit",
        "payment_security_test"
    ]
}

# Import all submodules for easy access
from . import scanners
from . import attacks
from . import recon
from . import ai
from . import intel
from . import audit
from . import stealth
from . import pentest
from . import auth

# Total tool count
TOTAL_TOOLS = sum(len(tools) for tools in TOOL_CATEGORIES.values())

def list_tools(category=None):
    """List available tools, optionally filtered by category."""
    if category:
        return TOOL_CATEGORIES.get(category, [])
    return TOOL_CATEGORIES

def get_tool_count():
    """Get total number of tools."""
    return TOTAL_TOOLS
