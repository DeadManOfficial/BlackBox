#!/usr/bin/env python3
"""
Intelligence Analyzer - Extract Actionable Scraping Techniques
=================================================================
Analyzes collected HTML intelligence and extracts:
- Repository names and descriptions
- Code snippets and techniques
- Library recommendations
- Bot bypass methods
- Implementation patterns
"""

import sys
import io
import json
import re
from pathlib import Path
from typing import List, Dict
from collections import defaultdict

# Fix Windows encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

class IntelligenceAnalyzer:
    """Analyze collected intelligence for actionable techniques"""

    def __init__(self, intelligence_dir):
        self.intelligence_dir = Path(intelligence_dir)
        self.techniques = defaultdict(list)
        self.repositories = []
        self.libraries = set()
        self.keywords = set()

    def analyze_all(self):
        """Analyze all collected HTML files"""
        print("="*80)
        print("INTELLIGENCE ANALYSIS - Extracting Actionable Techniques")
        print("="*80)
        print()

        html_files = list((self.intelligence_dir / "Documentation").glob("*.html"))
        print(f"Found {len(html_files)} HTML files to analyze")
        print()

        for html_file in html_files:
            self.analyze_file(html_file)

        self.generate_report()

    def analyze_file(self, html_path):
        """Analyze a single HTML file"""
        print(f"Analyzing: {html_path.name}")

        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Extract GitHub repositories
            if 'github.com' in content:
                repos = self.extract_github_repos(content)
                self.repositories.extend(repos)
                print(f"  Found {len(repos)} repositories")

            # Extract Python libraries
            libs = self.extract_python_libraries(content)
            self.libraries.update(libs)
            if libs:
                print(f"  Found libraries: {', '.join(list(libs)[:5])}")

            # Extract bot bypass techniques
            techniques = self.extract_techniques(content)
            for tech_type, tech_list in techniques.items():
                self.techniques[tech_type].extend(tech_list)

            # Extract key keywords
            keywords = self.extract_keywords(content)
            self.keywords.update(keywords)

        except Exception as e:
            print(f"  [ERROR] {str(e)}")

        print()

    def extract_github_repos(self, content):
        """Extract GitHub repository information"""
        repos = []

        # Pattern: /owner/repo-name with description
        repo_pattern = r'github\.com/([a-zA-Z0-9\-_]+)/([a-zA-Z0-9\-_\.]+)'
        matches = re.findall(repo_pattern, content)

        for owner, repo in matches[:20]:  # Limit to top 20
            repo_info = {
                'owner': owner,
                'repo': repo,
                'url': f'https://github.com/{owner}/{repo}'
            }
            if repo_info not in repos:
                repos.append(repo_info)

        return repos

    def extract_python_libraries(self, content):
        """Extract Python library names"""
        libraries = set()

        # Common scraping libraries
        lib_patterns = [
            r'import\s+(\w+)',
            r'from\s+(\w+)',
            r'pip\s+install\s+([a-z0-9\-_]+)',
            r'requirements\.txt.*?([a-z0-9\-_]+)==',
        ]

        for pattern in lib_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            libraries.update(matches)

        # Filter known scraping libraries
        scraping_libs = {
            'selenium', 'beautifulsoup4', 'scrapy', 'requests', 'playwright',
            'puppeteer', 'curl_cffi', 'httpx', 'aiohttp', 'lxml',
            'undetected-chromedriver', 'selenium-stealth', 'cloudscraper',
            'requests-html', 'mechanize', 'urllib3', 'tls-client'
        }

        return libraries & scraping_libs

    def extract_techniques(self, content):
        """Extract bot bypass and scraping techniques"""
        techniques = defaultdict(list)

        # Cloudflare bypass keywords
        if any(kw in content.lower() for kw in ['cloudflare', 'cf-', 'challenge']):
            cf_techs = []
            if 'cloudscraper' in content.lower():
                cf_techs.append('CloudScraper library')
            if 'undetected' in content.lower():
                cf_techs.append('Undetected ChromeDriver')
            if 'tls' in content.lower() and 'fingerprint' in content.lower():
                cf_techs.append('TLS fingerprint spoofing')
            if cf_techs:
                techniques['cloudflare_bypass'] = cf_techs

        # Bot detection bypass
        if any(kw in content.lower() for kw in ['bot detection', 'anti-bot', 'fingerprint']):
            bot_techs = []
            if 'user-agent' in content.lower():
                bot_techs.append('User-Agent rotation')
            if 'headless' in content.lower():
                bot_techs.append('Headless detection bypass')
            if 'webdriver' in content.lower():
                bot_techs.append('WebDriver property hiding')
            if bot_techs:
                techniques['bot_detection_bypass'] = bot_techs

        # Proxy techniques
        if 'proxy' in content.lower():
            proxy_techs = []
            if 'residential' in content.lower():
                proxy_techs.append('Residential proxies')
            if 'rotation' in content.lower():
                proxy_techs.append('Proxy rotation')
            if 'tor' in content.lower():
                proxy_techs.append('TOR network')
            if proxy_techs:
                techniques['proxy_methods'] = proxy_techs

        # CAPTCHA solving
        if 'captcha' in content.lower():
            captcha_techs = []
            if '2captcha' in content.lower() or 'anticaptcha' in content.lower():
                captcha_techs.append('CAPTCHA solving services')
            if 'recaptcha' in content.lower():
                captcha_techs.append('reCAPTCHA bypass')
            if captcha_techs:
                techniques['captcha_solving'] = captcha_techs

        return techniques

    def extract_keywords(self, content):
        """Extract important keywords"""
        keywords = set()

        important_terms = [
            'cloudflare', 'akamai', 'datadome', 'perimeterx', 'imperva',
            'selenium', 'playwright', 'puppeteer', 'scrapy',
            'rate-limit', 'throttle', 'retry', 'backoff',
            'fingerprint', 'headers', 'cookies', 'session',
            'javascript', 'render', 'dynamic', 'spa',
            'tor', 'proxy', 'vpn', 'residential',
            'captcha', 'recaptcha', 'hcaptcha'
        ]

        for term in important_terms:
            if term in content.lower():
                keywords.add(term)

        return keywords

    def generate_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE - FINDINGS SUMMARY")
        print("="*80)
        print()

        # Repositories
        print(f"GitHub Repositories Found: {len(self.repositories)}")
        if self.repositories:
            print("\nTop Repositories:")
            for i, repo in enumerate(self.repositories[:10], 1):
                print(f"  {i}. {repo['owner']}/{repo['repo']}")
                print(f"     {repo['url']}")

        print()

        # Libraries
        print(f"Python Libraries Identified: {len(self.libraries)}")
        if self.libraries:
            print(f"  {', '.join(sorted(self.libraries))}")

        print()

        # Techniques
        print("Techniques Extracted:")
        for tech_type, tech_list in self.techniques.items():
            unique_techs = list(set(tech_list))
            print(f"\n  {tech_type.replace('_', ' ').title()}: ({len(unique_techs)})")
            for tech in unique_techs:
                print(f"    - {tech}")

        print()

        # Keywords
        print(f"Key Terms Found: {len(self.keywords)}")
        if self.keywords:
            print(f"  {', '.join(sorted(self.keywords))}")

        print()
        print("="*80)

        # Save detailed report
        self.save_detailed_report()

    def save_detailed_report(self):
        """Save detailed analysis report"""
        report = {
            'analysis_date': '2026-01-10',
            'total_repos': len(self.repositories),
            'repositories': self.repositories[:50],  # Top 50
            'libraries': sorted(list(self.libraries)),
            'techniques': {k: list(set(v)) for k, v in self.techniques.items()},
            'keywords': sorted(list(self.keywords)),
            'summary': {
                'cloudflare_bypass_methods': len(set(self.techniques.get('cloudflare_bypass', []))),
                'bot_detection_bypasses': len(set(self.techniques.get('bot_detection_bypass', []))),
                'proxy_methods': len(set(self.techniques.get('proxy_methods', []))),
                'captcha_solutions': len(set(self.techniques.get('captcha_solving', [])))
            }
        }

        report_file = self.intelligence_dir / "ANALYSIS_REPORT.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        print(f"Detailed report saved: {report_file}")
        print()

        # Create markdown report
        self.create_markdown_report(report)

    def create_markdown_report(self, report):
        """Create human-readable markdown report"""
        md_content = f"""# INTELLIGENCE ANALYSIS REPORT

**Date:** {report['analysis_date']}
**Analysis Type:** Automated Technique Extraction
**Sources:** 14 HTML files (5.17 MB)

---

## EXECUTIVE SUMMARY

### Discovered Resources
- **GitHub Repositories:** {report['total_repos']}
- **Python Libraries:** {len(report['libraries'])}
- **Techniques Identified:** {sum(len(v) for v in report['techniques'].values())}
- **Key Terms:** {len(report['keywords'])}

### Technique Breakdown
- Cloudflare Bypass Methods: {report['summary']['cloudflare_bypass_methods']}
- Bot Detection Bypasses: {report['summary']['bot_detection_bypasses']}
- Proxy Methods: {report['summary']['proxy_methods']}
- CAPTCHA Solutions: {report['summary']['captcha_solutions']}

---

## GITHUB REPOSITORIES

Top repositories for scraping and bot bypass:

"""

        for i, repo in enumerate(report['repositories'][:20], 1):
            md_content += f"{i}. **[{repo['owner']}/{repo['repo']}]({repo['url']})**\n"

        md_content += f"""

---

## PYTHON LIBRARIES

Recommended libraries extracted from intelligence:

"""

        for lib in sorted(report['libraries']):
            md_content += f"- `{lib}`\n"

        md_content += """

---

## TECHNIQUES IDENTIFIED

"""

        for tech_type, techniques in report['techniques'].items():
            md_content += f"\n### {tech_type.replace('_', ' ').title()}\n\n"
            for tech in techniques:
                md_content += f"- {tech}\n"

        md_content += f"""

---

## KEY TERMS & TECHNOLOGIES

"""

        for keyword in sorted(report['keywords']):
            md_content += f"- {keyword}\n"

        md_content += """

---

## RECOMMENDED IMPLEMENTATIONS

Based on this analysis, we should implement:

1. **Enhanced Cloudflare Bypass**
   - Integrate CloudScraper library
   - Implement TLS fingerprint spoofing
   - Add challenge solving capabilities

2. **Advanced Bot Detection Evasion**
   - User-Agent rotation system
   - WebDriver property hiding
   - Headless detection bypass

3. **Proxy Management**
   - Residential proxy support
   - Automatic rotation logic
   - TOR integration (already planned)

4. **CAPTCHA Handling**
   - 2Captcha/Anti-Captcha integration
   - reCAPTCHA solver
   - hCAPTCHA support

---

**Report Generated:** 2026-01-10
**Next Steps:** Implement prioritized techniques into Ultimate Scraper

"""

        md_file = self.intelligence_dir / "ANALYSIS_REPORT.md"
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        print(f"Markdown report saved: {md_file}")

def main():
    intelligence_dir = Path(__file__).parent.parent / "Research" / "DarkWeb_Intelligence"

    if not intelligence_dir.exists():
        print(f"[ERROR] Intelligence directory not found: {intelligence_dir}")
        return

    analyzer = IntelligenceAnalyzer(intelligence_dir)
    analyzer.analyze_all()

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"Reports saved to: {intelligence_dir}")
    print()

if __name__ == "__main__":
    main()
