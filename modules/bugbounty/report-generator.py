#!/usr/bin/env python3
"""
Report Generator
Generates formatted vulnerability reports from scan results

Usage:
    ./report-generator.py --project tiktok --format markdown
    ./report-generator.py --project uber --format html --output final-report.html
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
PROJECTS_DIR = FRAMEWORK_DIR / "projects"
TEMPLATES_DIR = FRAMEWORK_DIR / "templates" / "report-templates"


def parse_args():
    parser = argparse.ArgumentParser(description="Generate vulnerability reports")
    parser.add_argument("--project", "-p", required=True, help="Project name")
    parser.add_argument(
        "--format", "-f",
        choices=["markdown", "html", "json"],
        default="markdown",
        help="Output format"
    )
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--include-evidence", action="store_true", help="Include evidence in report")
    parser.add_argument("--executive-only", action="store_true", help="Generate executive summary only")
    return parser.parse_args()


def load_findings(project_dir):
    """Load all findings from project scan results"""
    findings = []

    # Load nuclei results
    nuclei_dir = project_dir / "vulnscan" / "nuclei"
    if nuclei_dir.exists():
        for result_file in nuclei_dir.glob("*.json"):
            try:
                with open(result_file) as f:
                    for line in f:
                        if line.strip():
                            findings.append(json.loads(line))
            except:
                pass

    # Load manual findings
    findings_dir = project_dir / "reports" / "findings"
    if findings_dir.exists():
        for finding_file in findings_dir.glob("*.json"):
            try:
                with open(finding_file) as f:
                    findings.append(json.load(f))
            except:
                pass

    return findings


def categorize_findings(findings):
    """Categorize findings by severity"""
    categories = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }

    for finding in findings:
        severity = finding.get("info", {}).get("severity", "info").lower()
        if severity in categories:
            categories[severity].append(finding)
        else:
            categories["info"].append(finding)

    return categories


def generate_markdown_report(project_name, categories, executive_only=False):
    """Generate markdown format report"""
    report = []

    # Header
    report.append(f"# Security Assessment Report")
    report.append(f"## {project_name.title()}")
    report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"\n---\n")

    # Executive Summary
    report.append("## Executive Summary\n")
    total = sum(len(v) for v in categories.values())
    report.append(f"Total vulnerabilities identified: **{total}**\n")
    report.append("| Severity | Count |")
    report.append("|----------|-------|")
    for sev in ["critical", "high", "medium", "low", "info"]:
        report.append(f"| {sev.title()} | {len(categories[sev])} |")
    report.append("")

    if executive_only:
        return "\n".join(report)

    # Detailed Findings
    report.append("\n---\n")
    report.append("## Detailed Findings\n")

    for severity in ["critical", "high", "medium", "low", "info"]:
        if categories[severity]:
            report.append(f"\n### {severity.title()} Severity\n")

            for i, finding in enumerate(categories[severity], 1):
                info = finding.get("info", {})
                report.append(f"#### {i}. {info.get('name', 'Unknown')}\n")
                report.append(f"- **Severity:** {severity.title()}")
                report.append(f"- **Host:** {finding.get('host', 'N/A')}")
                report.append(f"- **Matched At:** {finding.get('matched-at', 'N/A')}")

                if info.get("description"):
                    report.append(f"\n**Description:**\n{info.get('description')}\n")

                if finding.get("curl-command"):
                    report.append(f"\n**PoC:**\n```\n{finding.get('curl-command')}\n```\n")

                report.append("")

    # Recommendations
    report.append("\n---\n")
    report.append("## Recommendations\n")
    report.append("1. Prioritize remediation of Critical and High severity findings")
    report.append("2. Implement security headers where missing")
    report.append("3. Review and rotate any exposed secrets")
    report.append("4. Conduct follow-up testing after remediation")

    return "\n".join(report)


def generate_html_report(project_name, categories):
    """Generate HTML format report"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {project_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .info {{ color: #1976d2; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <h2>{project_name.title()}</h2>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

    <h2>Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""

    for sev in ["critical", "high", "medium", "low", "info"]:
        html += f"        <tr><td class='{sev}'>{sev.title()}</td><td>{len(categories[sev])}</td></tr>\n"

    html += """    </table>

    <h2>Findings</h2>
"""

    for severity in ["critical", "high", "medium", "low"]:
        if categories[severity]:
            html += f"    <h3 class='{severity}'>{severity.title()} Severity</h3>\n"
            for finding in categories[severity]:
                info = finding.get("info", {})
                html += f"""    <div class="finding">
        <h4>{info.get('name', 'Unknown')}</h4>
        <p><strong>Host:</strong> {finding.get('host', 'N/A')}</p>
        <p>{info.get('description', '')}</p>
    </div>
"""

    html += """</body>
</html>"""

    return html


def main():
    args = parse_args()

    # Validate project
    project_dir = PROJECTS_DIR / args.project
    if not project_dir.exists():
        print(f"[!] Project not found: {args.project}")
        sys.exit(1)

    print(f"[*] Generating report for: {args.project}")

    # Load and categorize findings
    findings = load_findings(project_dir)
    categories = categorize_findings(findings)

    print(f"[*] Loaded {sum(len(v) for v in categories.values())} findings")

    # Generate report
    if args.format == "markdown":
        report = generate_markdown_report(args.project, categories, args.executive_only)
        ext = ".md"
    elif args.format == "html":
        report = generate_html_report(args.project, categories)
        ext = ".html"
    else:  # json
        report = json.dumps({"project": args.project, "findings": categories}, indent=2)
        ext = ".json"

    # Output
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = project_dir / "reports" / "final" / f"report-{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report)

    print(f"[+] Report saved to: {output_path}")


if __name__ == "__main__":
    main()
