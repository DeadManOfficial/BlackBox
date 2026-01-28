#!/usr/bin/env python3
"""
Target Initialization Script
Creates a new bug bounty project with full configuration and auto-recon

Usage:
    ./target-init.py --name "company" --platform "hackerone" \
                     --domains "*.example.com,api.example.com" \
                     --exclude "blog.example.com" --auto-recon
"""

import argparse
import os
import sys
import yaml
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from string import Template

FRAMEWORK_DIR = Path(__file__).parent.parent
PROJECTS_DIR = FRAMEWORK_DIR / "projects"
TEMPLATES_DIR = FRAMEWORK_DIR / "templates"
CONFIG_DIR = FRAMEWORK_DIR / "config"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Initialize a new bug bounty target project"
    )
    parser.add_argument(
        "--name", "-n",
        required=True,
        help="Target company/project name"
    )
    parser.add_argument(
        "--platform", "-p",
        choices=["hackerone", "bugcrowd", "intigriti", "synack", "direct", "private"],
        default="direct",
        help="Bug bounty platform"
    )
    parser.add_argument(
        "--program-url",
        default="",
        help="Bug bounty program URL"
    )
    parser.add_argument(
        "--domains", "-d",
        required=True,
        help="Comma-separated list of in-scope domains (supports wildcards)"
    )
    parser.add_argument(
        "--exclude", "-e",
        default="",
        help="Comma-separated list of out-of-scope domains"
    )
    parser.add_argument(
        "--auth-type",
        choices=["public", "private", "invited"],
        default="public",
        help="Authorization type"
    )
    parser.add_argument(
        "--auto-recon",
        action="store_true",
        help="Run automatic reconnaissance after setup"
    )
    parser.add_argument(
        "--special-rules",
        default="",
        help="Any target-specific rules or notes"
    )
    return parser.parse_args()


def sanitize_name(name):
    """Create a safe directory name from target name"""
    return name.lower().replace(" ", "-").replace(".", "-")


def load_manifest():
    """Load the directory structure manifest"""
    manifest_path = TEMPLATES_DIR / "directory-structure" / "manifest.yaml"
    with open(manifest_path) as f:
        return yaml.safe_load(f)


def create_directory_structure(project_dir, manifest):
    """Create all directories from manifest"""
    print(f"[*] Creating directory structure...")
    for directory in manifest.get("directories", []):
        dir_path = project_dir / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        print(f"    [+] Created: {directory}/")


def process_template(template_content, variables):
    """Replace template variables with actual values"""
    for key, value in variables.items():
        template_content = template_content.replace(f"{{{{{key}}}}}", str(value))
    return template_content


def create_files(project_dir, manifest, variables):
    """Create all files from manifest with variable substitution"""
    print(f"[*] Creating project files...")

    for file_spec in manifest.get("files", []):
        file_path = project_dir / file_spec["path"]

        if "template" in file_spec:
            # Load from template file
            template_path = TEMPLATES_DIR / file_spec["template"]
            if template_path.exists():
                content = template_path.read_text()
            else:
                print(f"    [-] Template not found: {file_spec['template']}")
                continue
        else:
            content = file_spec.get("content", "")

        # Process variables
        content = process_template(content, variables)

        # Write file
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        print(f"    [+] Created: {file_spec['path']}")


def run_auto_recon(project_dir, domains, exclude):
    """Run automatic reconnaissance on target domains"""
    print(f"\n[*] Starting automatic reconnaissance...")

    recon_dir = project_dir / "recon"
    results = {
        "timestamp": datetime.now().isoformat(),
        "domains": domains,
        "excluded": exclude,
        "subdomains": [],
        "live_hosts": [],
        "technologies": []
    }

    # Parse domains
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    base_domains = [d.replace("*.", "") for d in domain_list]

    # Subdomain enumeration
    print(f"    [*] Enumerating subdomains...")
    all_subdomains = set()

    for domain in base_domains:
        try:
            # Try subfinder
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                subs = result.stdout.strip().split("\n")
                all_subdomains.update([s for s in subs if s])
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            # Try amass (passive)
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", domain],
                capture_output=True, text=True, timeout=180
            )
            if result.returncode == 0:
                subs = result.stdout.strip().split("\n")
                all_subdomains.update([s for s in subs if s])
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Filter excluded domains
    exclude_list = [e.strip() for e in exclude.split(",") if e.strip()]
    for excl in exclude_list:
        all_subdomains = {s for s in all_subdomains if excl not in s}

    results["subdomains"] = sorted(list(all_subdomains))
    print(f"    [+] Found {len(results['subdomains'])} subdomains")

    # Save subdomain list
    subdomain_file = recon_dir / "subdomains" / "all-subdomains.txt"
    subdomain_file.write_text("\n".join(results["subdomains"]))

    # HTTP probing
    print(f"    [*] Probing for live hosts...")
    if results["subdomains"]:
        try:
            result = subprocess.run(
                ["httpx", "-l", str(subdomain_file), "-silent", "-status-code", "-tech-detect", "-json"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            host_data = json.loads(line)
                            results["live_hosts"].append(host_data)
                        except json.JSONDecodeError:
                            pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    print(f"    [+] Found {len(results['live_hosts'])} live hosts")

    # Save results
    results_file = recon_dir / "initial-recon.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"    [+] Results saved to: recon/initial-recon.json")

    # Generate live hosts list
    live_file = recon_dir / "live-hosts.txt"
    live_urls = [h.get("url", h.get("input", "")) for h in results["live_hosts"]]
    live_file.write_text("\n".join(live_urls))

    return results


def print_summary(project_dir, variables, recon_results=None):
    """Print project setup summary"""
    print("\n" + "=" * 60)
    print("PROJECT INITIALIZED SUCCESSFULLY")
    print("=" * 60)
    print(f"Target:     {variables['TARGET_NAME']}")
    print(f"Platform:   {variables['PLATFORM']}")
    print(f"Location:   {project_dir}")
    print(f"Date:       {variables['DATE']}")

    if recon_results:
        print(f"\nRecon Results:")
        print(f"  Subdomains: {len(recon_results.get('subdomains', []))}")
        print(f"  Live Hosts: {len(recon_results.get('live_hosts', []))}")

    print(f"\nNext Steps:")
    print(f"  1. Review scope: {project_dir}/config/scope.yaml")
    print(f"  2. Check authorization: {project_dir}/AUTHORIZATION.md")
    print(f"  3. Review recon results: {project_dir}/recon/")
    print(f"  4. Start vulnerability scanning")
    print("=" * 60)


def main():
    args = parse_args()

    # Setup paths
    project_name = sanitize_name(args.name)
    project_dir = PROJECTS_DIR / project_name

    # Check if project exists
    if project_dir.exists():
        print(f"[!] Project already exists: {project_dir}")
        response = input("Overwrite? (y/N): ")
        if response.lower() != "y":
            print("Aborted.")
            sys.exit(1)
        shutil.rmtree(project_dir)

    # Create project directory
    project_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] Creating project: {project_name}")

    # Prepare variables
    domains_list = [d.strip() for d in args.domains.split(",") if d.strip()]
    exclude_list = [e.strip() for e in args.exclude.split(",") if e.strip()]

    variables = {
        "TARGET_NAME": args.name,
        "PLATFORM": args.platform,
        "PROGRAM_URL": args.program_url or f"https://{args.platform}.com/{project_name}",
        "DATE": datetime.now().strftime("%Y-%m-%d"),
        "AUTH_TYPE": args.auth_type,
        "IN_SCOPE": "\n".join([f"- {d}" for d in domains_list]),
        "OUT_OF_SCOPE": "\n".join([f"- {e}" for e in exclude_list]) if exclude_list else "- None specified",
        "IN_SCOPE_YAML": "\n".join([f"      - \"{d}\"" for d in domains_list]),
        "OUT_OF_SCOPE_YAML": "\n".join([f"      - \"{e}\"" for e in exclude_list]) if exclude_list else "      - # None specified",
        "DOMAINS_YAML": "\n".join([f"  - \"{d}\"" for d in domains_list]),
        "SPECIAL_RULES": args.special_rules or "No target-specific rules defined.",
    }

    # Load manifest and create structure
    manifest = load_manifest()
    create_directory_structure(project_dir, manifest)
    create_files(project_dir, manifest, variables)

    # Run auto-recon if requested
    recon_results = None
    if args.auto_recon:
        recon_results = run_auto_recon(project_dir, args.domains, args.exclude)

    # Print summary
    print_summary(project_dir, variables, recon_results)


if __name__ == "__main__":
    main()
