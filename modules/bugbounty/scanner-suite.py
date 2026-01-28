#!/usr/bin/env python3
"""
Universal Vulnerability Scanner Suite
Runs comprehensive scanning against target with configurable options

Usage:
    ./scanner-suite.py --project tiktok --scan-type full
    ./scanner-suite.py --project uber --scan-type quick
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

FRAMEWORK_DIR = Path(__file__).parent.parent
PROJECTS_DIR = FRAMEWORK_DIR / "projects"


def parse_args():
    parser = argparse.ArgumentParser(description="Run vulnerability scans on target project")
    parser.add_argument("--project", "-p", required=True, help="Project name")
    parser.add_argument(
        "--scan-type",
        choices=["quick", "standard", "full", "custom"],
        default="standard",
        help="Scan intensity level"
    )
    parser.add_argument("--targets-file", help="Custom targets file (default: recon/live-hosts.txt)")
    parser.add_argument("--nuclei-templates", nargs="+", help="Specific nuclei templates to use")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip nuclei scanning")
    parser.add_argument("--skip-js", action="store_true", help="Skip JavaScript analysis")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--output", "-o", help="Output directory (default: vulnscan/)")
    return parser.parse_args()


def get_project_dir(project_name):
    """Get and validate project directory"""
    project_dir = PROJECTS_DIR / project_name
    if not project_dir.exists():
        print(f"[!] Project not found: {project_name}")
        print(f"    Available projects: {[p.name for p in PROJECTS_DIR.iterdir() if p.is_dir()]}")
        sys.exit(1)
    return project_dir


def get_targets(project_dir, targets_file=None):
    """Load target URLs from project"""
    if targets_file:
        targets_path = Path(targets_file)
    else:
        targets_path = project_dir / "recon" / "live-hosts.txt"

    if not targets_path.exists():
        print(f"[!] Targets file not found: {targets_path}")
        print("    Run recon first or specify --targets-file")
        sys.exit(1)

    targets = targets_path.read_text().strip().split("\n")
    return [t.strip() for t in targets if t.strip()]


def run_nuclei_scan(targets, output_dir, scan_type="standard", templates=None):
    """Run nuclei vulnerability scanner"""
    print(f"\n[*] Running Nuclei scan ({scan_type})...")

    results_file = output_dir / "nuclei" / f"nuclei-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)

    # Build nuclei command
    cmd = [
        "nuclei",
        "-json-export", str(results_file),
        "-silent"
    ]

    # Add targets
    targets_file = output_dir / "nuclei" / "targets.txt"
    targets_file.write_text("\n".join(targets))
    cmd.extend(["-l", str(targets_file)])

    # Configure based on scan type
    if scan_type == "quick":
        cmd.extend(["-severity", "critical,high", "-rate-limit", "100"])
    elif scan_type == "standard":
        cmd.extend(["-severity", "medium,high,critical", "-rate-limit", "150"])
    elif scan_type == "full":
        cmd.extend(["-severity", "low,medium,high,critical", "-rate-limit", "50"])

    # Add specific templates if provided
    if templates:
        for t in templates:
            cmd.extend(["-t", t])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if results_file.exists():
            with open(results_file) as f:
                findings = [json.loads(line) for line in f if line.strip()]
            print(f"    [+] Found {len(findings)} potential vulnerabilities")
            return findings
    except subprocess.TimeoutExpired:
        print("    [-] Nuclei scan timed out")
    except FileNotFoundError:
        print("    [-] Nuclei not installed")

    return []


def run_js_analysis(targets, output_dir):
    """Analyze JavaScript files from targets"""
    print(f"\n[*] Running JavaScript analysis...")

    js_dir = output_dir.parent / "analysis" / "js"
    js_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "endpoints": [],
        "secrets": [],
        "urls": []
    }

    # Patterns to search for
    patterns = {
        "api_endpoint": r'["\']\/api\/[^"\']+["\']',
        "secret": r'["\']?(api[_-]?key|secret|token|password)["\']?\s*[:=]\s*["\'][^"\']+["\']',
        "url": r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s"\'<>]*'
    }

    for target in targets[:20]:  # Limit to prevent overload
        try:
            # Fetch and analyze JS
            result = subprocess.run(
                ["curl", "-s", "-L", target],
                capture_output=True, text=True, timeout=30
            )
            content = result.stdout

            # Extract JS file URLs
            import re
            js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', content)

            for js_url in js_urls[:10]:
                if not js_url.startswith("http"):
                    js_url = target.rstrip("/") + "/" + js_url.lstrip("/")

                try:
                    js_result = subprocess.run(
                        ["curl", "-s", "-L", js_url],
                        capture_output=True, text=True, timeout=30
                    )
                    js_content = js_result.stdout

                    # Search for patterns
                    for pattern_name, pattern in patterns.items():
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        if matches:
                            results[pattern_name if pattern_name in results else "secrets"].extend(
                                [{"match": m, "source": js_url} for m in matches[:50]]
                            )
                except:
                    pass

        except Exception as e:
            pass

    # Save results
    results_file = js_dir / f"js-analysis-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"    [+] Found {len(results.get('endpoints', []))} endpoints")
    print(f"    [+] Found {len(results.get('secrets', []))} potential secrets")

    return results


def run_header_check(targets, output_dir):
    """Check security headers on targets"""
    print(f"\n[*] Checking security headers...")

    results = []
    important_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    for target in targets[:50]:
        try:
            result = subprocess.run(
                ["curl", "-s", "-I", "-L", target],
                capture_output=True, text=True, timeout=15
            )
            headers = result.stdout.lower()

            missing = []
            for header in important_headers:
                if header.lower() not in headers:
                    missing.append(header)

            if missing:
                results.append({
                    "url": target,
                    "missing_headers": missing
                })
        except:
            pass

    print(f"    [+] {len(results)} targets missing security headers")

    # Save results
    results_file = output_dir / "manual" / f"headers-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    return results


def generate_report(project_dir, nuclei_results, js_results, header_results):
    """Generate scan summary report"""
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "nuclei_findings": len(nuclei_results),
            "js_endpoints": len(js_results.get("endpoints", [])),
            "js_secrets": len(js_results.get("secrets", [])),
            "header_issues": len(header_results)
        },
        "severity_breakdown": {},
        "recommendations": []
    }

    # Count severities
    for finding in nuclei_results:
        sev = finding.get("info", {}).get("severity", "unknown")
        report["severity_breakdown"][sev] = report["severity_breakdown"].get(sev, 0) + 1

    # Save report
    report_file = project_dir / "vulnscan" / f"scan-summary-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    return report


def print_summary(report):
    """Print scan summary"""
    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Nuclei Findings: {report['summary']['nuclei_findings']}")
    print(f"JS Endpoints:    {report['summary']['js_endpoints']}")
    print(f"JS Secrets:      {report['summary']['js_secrets']}")
    print(f"Header Issues:   {report['summary']['header_issues']}")

    if report["severity_breakdown"]:
        print("\nSeverity Breakdown:")
        for sev, count in sorted(report["severity_breakdown"].items()):
            print(f"  {sev}: {count}")

    print("=" * 60)


def main():
    args = parse_args()

    # Setup
    project_dir = get_project_dir(args.project)
    output_dir = project_dir / (args.output or "vulnscan")
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Scanning project: {args.project}")
    print(f"[*] Scan type: {args.scan_type}")

    # Get targets
    targets = get_targets(project_dir, args.targets_file)
    print(f"[*] Loaded {len(targets)} targets")

    # Run scans
    nuclei_results = []
    js_results = {"endpoints": [], "secrets": []}
    header_results = []

    if not args.skip_nuclei:
        nuclei_results = run_nuclei_scan(targets, output_dir, args.scan_type, args.nuclei_templates)

    if not args.skip_js:
        js_results = run_js_analysis(targets, output_dir)

    header_results = run_header_check(targets, output_dir)

    # Generate report
    report = generate_report(project_dir, nuclei_results, js_results, header_results)
    print_summary(report)


if __name__ == "__main__":
    main()
