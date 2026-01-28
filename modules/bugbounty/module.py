#!/usr/bin/env python3
"""
BlackBox AI - Bug Bounty Module
================================

Manages bug bounty targets, projects, scope, and findings.
Integrates with BlackBox scanning and reconnaissance tools.
"""

import json
import os
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from modules.base import BaseModule, ModuleCategory, ToolDefinition, RouteDefinition


class BugBountyModule(BaseModule):
    """Bug bounty target and project management module"""

    name = "bugbounty"
    version = "1.0.0"
    category = ModuleCategory.WORKFLOW
    description = "Bug bounty target management, scope tracking, and findings"
    author = "DeadMan Security Research"
    tags = ["bugbounty", "targets", "scope", "findings", "projects"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.projects_path = Path(self.config.get("projects_path", "projects"))
        self.projects_path.mkdir(parents=True, exist_ok=True)

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        """Register bug bounty MCP tools"""
        self._mcp = mcp
        self._client = client

        @mcp.tool()
        def bounty_init_target(
            name: str,
            domains: str,
            platform: str = "hackerone",
            program_url: str = ""
        ) -> str:
            """
            Initialize a new bug bounty target project.

            Args:
                name: Target name (e.g., "acme-corp")
                domains: Comma-separated in-scope domains (e.g., "*.acme.com,api.acme.com")
                platform: Bug bounty platform (hackerone, bugcrowd, intigriti, direct)
                program_url: URL to the bug bounty program page

            Returns:
                JSON with project initialization status
            """
            return self._init_target(name, domains.split(","), platform, program_url)

        @mcp.tool()
        def bounty_list_targets() -> str:
            """
            List all bug bounty target projects.

            Returns:
                JSON list of all configured targets
            """
            return self._list_targets()

        @mcp.tool()
        def bounty_get_scope(target: str) -> str:
            """
            Get the scope configuration for a target.

            Args:
                target: Target project name

            Returns:
                JSON with in-scope and out-of-scope domains
            """
            return self._get_scope(target)

        @mcp.tool()
        def bounty_check_scope(target: str, domain: str) -> str:
            """
            Check if a domain is in scope for a target.

            Args:
                target: Target project name
                domain: Domain to check

            Returns:
                JSON with scope status (in_scope: true/false)
            """
            return self._check_scope(target, domain)

        @mcp.tool()
        def bounty_add_finding(
            target: str,
            title: str,
            severity: str,
            vulnerability_type: str,
            description: str,
            endpoint: str = "",
            evidence: str = ""
        ) -> str:
            """
            Add a new finding to a target project.

            Args:
                target: Target project name
                title: Finding title
                severity: Severity (critical, high, medium, low, info)
                vulnerability_type: Type (xss, sqli, idor, ssrf, etc.)
                description: Detailed description
                endpoint: Affected endpoint/URL
                evidence: Evidence or reproduction steps

            Returns:
                JSON with finding ID and status
            """
            return self._add_finding(target, title, severity, vulnerability_type,
                                    description, endpoint, evidence)

        @mcp.tool()
        def bounty_list_findings(target: str, severity: str = "") -> str:
            """
            List findings for a target.

            Args:
                target: Target project name
                severity: Optional filter by severity

            Returns:
                JSON list of findings
            """
            return self._list_findings(target, severity)

        @mcp.tool()
        def bounty_get_stats(target: str) -> str:
            """
            Get statistics for a target project.

            Args:
                target: Target project name

            Returns:
                JSON with finding counts by severity, status, etc.
            """
            return self._get_stats(target)

        @mcp.tool()
        def bounty_update_finding(
            target: str,
            finding_id: str,
            status: str = "",
            notes: str = ""
        ) -> str:
            """
            Update a finding's status or add notes.

            Args:
                target: Target project name
                finding_id: Finding ID
                status: New status (new, triaged, submitted, accepted, resolved, duplicate)
                notes: Additional notes

            Returns:
                JSON with update status
            """
            return self._update_finding(target, finding_id, status, notes)

        # Track registered tools
        tools = [
            ToolDefinition("bounty_init_target", "Initialize new bug bounty target", bounty_init_target),
            ToolDefinition("bounty_list_targets", "List all targets", bounty_list_targets),
            ToolDefinition("bounty_get_scope", "Get target scope", bounty_get_scope),
            ToolDefinition("bounty_check_scope", "Check if domain is in scope", bounty_check_scope),
            ToolDefinition("bounty_add_finding", "Add new finding", bounty_add_finding),
            ToolDefinition("bounty_list_findings", "List findings", bounty_list_findings),
            ToolDefinition("bounty_get_stats", "Get project statistics", bounty_get_stats),
            ToolDefinition("bounty_update_finding", "Update finding", bounty_update_finding),
        ]
        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        """Register bug bounty API routes"""
        self._app = app
        from flask import request, jsonify

        @app.route('/api/bounty/targets', methods=['GET'])
        def api_list_targets():
            """List all bug bounty targets"""
            result = json.loads(self._list_targets())
            return jsonify(result)

        @app.route('/api/bounty/targets', methods=['POST'])
        def api_init_target():
            """Initialize new target"""
            data = request.json
            result = json.loads(self._init_target(
                data.get('name'),
                data.get('domains', []),
                data.get('platform', 'hackerone'),
                data.get('program_url', '')
            ))
            return jsonify(result)

        @app.route('/api/bounty/targets/<target>/scope', methods=['GET'])
        def api_get_scope(target):
            """Get target scope"""
            result = json.loads(self._get_scope(target))
            return jsonify(result)

        @app.route('/api/bounty/targets/<target>/findings', methods=['GET'])
        def api_list_findings(target):
            """List target findings"""
            severity = request.args.get('severity', '')
            result = json.loads(self._list_findings(target, severity))
            return jsonify(result)

        @app.route('/api/bounty/targets/<target>/findings', methods=['POST'])
        def api_add_finding(target):
            """Add new finding"""
            data = request.json
            result = json.loads(self._add_finding(
                target,
                data.get('title'),
                data.get('severity'),
                data.get('vulnerability_type'),
                data.get('description'),
                data.get('endpoint', ''),
                data.get('evidence', '')
            ))
            return jsonify(result)

        @app.route('/api/bounty/targets/<target>/stats', methods=['GET'])
        def api_get_stats(target):
            """Get target statistics"""
            result = json.loads(self._get_stats(target))
            return jsonify(result)

        routes = [
            RouteDefinition('/api/bounty/targets', ['GET'], api_list_targets, "List all targets"),
            RouteDefinition('/api/bounty/targets', ['POST'], api_init_target, "Initialize target"),
            RouteDefinition('/api/bounty/targets/<target>/scope', ['GET'], api_get_scope, "Get scope"),
            RouteDefinition('/api/bounty/targets/<target>/findings', ['GET'], api_list_findings, "List findings"),
            RouteDefinition('/api/bounty/targets/<target>/findings', ['POST'], api_add_finding, "Add finding"),
            RouteDefinition('/api/bounty/targets/<target>/stats', ['GET'], api_get_stats, "Get stats"),
        ]
        self._routes = routes
        return routes

    def _init_target(self, name: str, domains: List[str], platform: str, program_url: str) -> str:
        """Initialize a new target project"""
        target_path = self.projects_path / name

        if target_path.exists():
            return json.dumps({"error": f"Target '{name}' already exists", "success": False})

        # Create directory structure
        dirs = ["config", "recon", "vulnscan", "reports", "evidence", "notes"]
        for d in dirs:
            (target_path / d).mkdir(parents=True, exist_ok=True)

        # Create scope.yaml
        scope = {
            "target": {
                "name": name,
                "platform": platform,
                "program_url": program_url,
                "created": datetime.now().isoformat()
            },
            "scope": {
                "in_scope": [d.strip() for d in domains],
                "out_of_scope": []
            },
            "authorization": {
                "type": "public" if platform in ["hackerone", "bugcrowd", "intigriti"] else "private",
                "verified": False,
                "date": datetime.now().strftime("%Y-%m-%d")
            }
        }
        with open(target_path / "config" / "scope.yaml", "w") as f:
            yaml.dump(scope, f, default_flow_style=False)

        # Create empty findings.json
        findings = {"findings": [], "metadata": {"created": datetime.now().isoformat()}}
        with open(target_path / "findings.json", "w") as f:
            json.dump(findings, f, indent=2)

        # Create README
        readme = f"""# {name} - Bug Bounty Project

**Platform:** {platform}
**Program URL:** {program_url or "N/A"}
**Created:** {datetime.now().strftime("%Y-%m-%d")}

## Scope

### In-Scope
{chr(10).join(f"- {d}" for d in domains)}

### Out-of-Scope
(None defined)

## Structure

- `config/` - Scope and configuration
- `recon/` - Reconnaissance data
- `vulnscan/` - Vulnerability scan results
- `reports/` - Generated reports
- `evidence/` - Screenshots, logs, PoCs
- `notes/` - Research notes
"""
        with open(target_path / "README.md", "w") as f:
            f.write(readme)

        return json.dumps({
            "success": True,
            "target": name,
            "path": str(target_path),
            "domains": domains,
            "platform": platform
        })

    def _list_targets(self) -> str:
        """List all target projects"""
        targets = []
        if self.projects_path.exists():
            for p in self.projects_path.iterdir():
                if p.is_dir() and (p / "config" / "scope.yaml").exists():
                    scope_file = p / "config" / "scope.yaml"
                    with open(scope_file) as f:
                        scope = yaml.safe_load(f)
                    targets.append({
                        "name": p.name,
                        "platform": scope.get("target", {}).get("platform", "unknown"),
                        "domains": scope.get("scope", {}).get("in_scope", []),
                        "created": scope.get("target", {}).get("created", "unknown")
                    })
        return json.dumps({"targets": targets, "count": len(targets)})

    def _get_scope(self, target: str) -> str:
        """Get scope for a target"""
        scope_file = self.projects_path / target / "config" / "scope.yaml"
        if not scope_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(scope_file) as f:
            scope = yaml.safe_load(f)

        return json.dumps(scope)

    def _check_scope(self, target: str, domain: str) -> str:
        """Check if domain is in scope"""
        import fnmatch

        scope_file = self.projects_path / target / "config" / "scope.yaml"
        if not scope_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(scope_file) as f:
            scope = yaml.safe_load(f)

        in_scope = scope.get("scope", {}).get("in_scope", [])
        out_of_scope = scope.get("scope", {}).get("out_of_scope", [])

        # Check out-of-scope first
        for pattern in out_of_scope:
            if fnmatch.fnmatch(domain, pattern):
                return json.dumps({"domain": domain, "in_scope": False, "reason": f"Matches exclusion: {pattern}"})

        # Check in-scope
        for pattern in in_scope:
            if fnmatch.fnmatch(domain, pattern):
                return json.dumps({"domain": domain, "in_scope": True, "matched": pattern})

        return json.dumps({"domain": domain, "in_scope": False, "reason": "No matching scope pattern"})

    def _add_finding(self, target: str, title: str, severity: str, vuln_type: str,
                     description: str, endpoint: str, evidence: str) -> str:
        """Add a new finding"""
        findings_file = self.projects_path / target / "findings.json"
        if not findings_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(findings_file) as f:
            data = json.load(f)

        # Generate finding ID
        finding_id = f"FIND-{len(data['findings']) + 1:04d}"

        finding = {
            "id": finding_id,
            "title": title,
            "severity": severity.lower(),
            "type": vuln_type,
            "description": description,
            "endpoint": endpoint,
            "evidence": evidence,
            "status": "new",
            "created": datetime.now().isoformat(),
            "updated": datetime.now().isoformat(),
            "notes": []
        }

        data["findings"].append(finding)

        with open(findings_file, "w") as f:
            json.dump(data, f, indent=2)

        return json.dumps({"success": True, "finding_id": finding_id, "finding": finding})

    def _list_findings(self, target: str, severity: str = "") -> str:
        """List findings for a target"""
        findings_file = self.projects_path / target / "findings.json"
        if not findings_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(findings_file) as f:
            data = json.load(f)

        findings = data.get("findings", [])

        if severity:
            findings = [f for f in findings if f.get("severity") == severity.lower()]

        return json.dumps({"findings": findings, "count": len(findings)})

    def _get_stats(self, target: str) -> str:
        """Get statistics for a target"""
        findings_file = self.projects_path / target / "findings.json"
        if not findings_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(findings_file) as f:
            data = json.load(f)

        findings = data.get("findings", [])

        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_status": {},
            "by_type": {}
        }

        for f in findings:
            sev = f.get("severity", "unknown")
            status = f.get("status", "unknown")
            vtype = f.get("type", "unknown")

            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            stats["by_type"][vtype] = stats["by_type"].get(vtype, 0) + 1

        return json.dumps({"target": target, "stats": stats})

    def _update_finding(self, target: str, finding_id: str, status: str, notes: str) -> str:
        """Update a finding"""
        findings_file = self.projects_path / target / "findings.json"
        if not findings_file.exists():
            return json.dumps({"error": f"Target '{target}' not found"})

        with open(findings_file) as f:
            data = json.load(f)

        for finding in data.get("findings", []):
            if finding.get("id") == finding_id:
                if status:
                    finding["status"] = status
                if notes:
                    finding["notes"].append({
                        "text": notes,
                        "timestamp": datetime.now().isoformat()
                    })
                finding["updated"] = datetime.now().isoformat()

                with open(findings_file, "w") as f:
                    json.dump(data, f, indent=2)

                return json.dumps({"success": True, "finding": finding})

        return json.dumps({"error": f"Finding '{finding_id}' not found"})

    def get_config_schema(self) -> Dict[str, Any]:
        """Return configuration schema"""
        return {
            "type": "object",
            "properties": {
                "projects_path": {
                    "type": "string",
                    "description": "Path to store project directories",
                    "default": "projects"
                }
            }
        }
