# DeadMan Pentest Suite - External Tools Integration

53 external tools integrated as Python wrappers across 14 modules.

**Note:** Dark web tools (Robin, Darker, TorBot, etc.) have been merged into a single `dark_web.py` module.

## NEW: Enhanced Penetration Testing (v3.1.0)

Advanced reconnaissance and dynamic testing capabilities:

```python
from tools.tools import (
    # Advanced Recon
    AdvancedRecon, JSDeepAnalyzer, GraphQLTester,
    SubdomainEnumerator, AuthTester, CloudAssetDiscovery,

    # Dynamic Testing
    DynamicTester, APITester, XSSPayloads, SQLiPayloads
)

# Full automated scan
recon = AdvancedRecon()
results = recon.full_scan("target.com", include_subdomains=True, include_cloud=True)

# Subdomain enumeration (CT logs, Wayback, DNS brute force)
enumerator = SubdomainEnumerator()
subs = enumerator.enumerate("target.com")  # Returns live subs + takeover candidates

# Deep JavaScript analysis (source maps, secrets, endpoints)
js_analyzer = JSDeepAnalyzer()
findings = js_analyzer.analyze_url("https://target.com/app.js")

# GraphQL security testing
gql_tester = GraphQLTester()
vulns = gql_tester.test_endpoint("https://target.com/graphql")

# Cloud asset discovery (S3, Azure, GCP)
cloud = CloudAssetDiscovery()
buckets = cloud.discover("target.com")

# Dynamic SPA testing (requires Playwright)
async with DynamicTester() as tester:
    await tester.init_browser()
    results = await tester.test_url("https://spa-app.com")

# API security testing (IDOR, mass assignment, verb tampering)
api_tester = APITester()
idor_results = api_tester.test_idor(
    url_template="https://api.target.com/users/{id}",
    id_param="id",
    valid_id="1",
    test_ids=["2", "3", "100"]
)
```

## Quick Start

```python
from tools.integrations import (
    # Dark Web
    DarkWebToolkit, ScrapeGraphAI, AIScrapingToolkit,

    # Security
    SecurityToolkit, ExegolEnvironment, FaradayIDE,

    # OSINT
    SpeedyDorkScanner, DataSploitOSINT,

    # AI Pentesting
    ShannonAIPentester,

    # Web Scraping
    WebScrapingToolkit, BeautifulSoupScraper, ScrapyRunner,

    # Resources
    ResourceToolkit, BlackHatArsenal
)

# Create unified toolkits
from tools.integrations import create_toolkit

all_toolkits = create_toolkit("all")
darkweb = create_toolkit("darkweb")
security = create_toolkit("security")
scraping = create_toolkit("scraping")
```

## Modules

### Dark Web OSINT

| Tool | Stars | Description |
|------|-------|-------------|
| Robin | 3,729 | AI-powered dark web investigation |
| Darker | - | Meta-searcher (14 engines) |
| TorBot | 3,700 | Dark web crawler with visualization |
| Darkdump | ~500 | Ahmia.fi OSINT extractor |
| Zilbers Dashboard | - | Full-stack monitoring (React + Elasticsearch) |
| Forum Scrapers | 62 | Scrapy-based forum scrapers |
| dark-web-scraper | - | PyPI package for .onion scraping |

```python
from tools.integrations import DarkWebToolkit

toolkit = DarkWebToolkit()

# Meta-search 14 engines
results = toolkit.search("ransomware")

# Crawl .onion site
pages = toolkit.crawl("http://example.onion", depth=2)

# Start monitoring dashboard
toolkit.start_dashboard()
```

### AI-Powered Scraping

| Tool | Stars | Description |
|------|-------|-------------|
| ScrapeGraphAI | 22,400 | LLM-powered scraping (natural language) |
| ai-context | 149 | Generate LLM context from any source |

```python
from tools.integrations import ScrapeGraphAI, AIContext

# Natural language scraping
scraper = ScrapeGraphAI(provider="ollama", model="llama3.1")
result = scraper.scrape(
    "https://target.com",
    "Extract all product names and prices"
)

# Generate context from GitHub repo
ctx = AIContext()
context = ctx.from_github("https://github.com/user/repo")
```

### AI Pentesting

| Tool | Stars | Description |
|------|-------|-------------|
| Shannon | 4,000 | Autonomous AI pentester (96.15% success) |

```python
from tools.integrations import ShannonAIPentester

shannon = ShannonAIPentester()
report = await shannon.run_pentest("https://target.com")
```

### Security Environments

| Tool | Description |
|------|-------------|
| Exegol | Pentest Docker environment (100+ tools) |
| Faraday | Collaborative pentest IDE (80+ integrations) |
| Merlin | Post-exploitation C2 framework |
| ArcherySec | Vulnerability management dashboard |
| Anbu | CLI security toolkit |

```python
from tools.integrations import SecurityToolkit

toolkit = SecurityToolkit()

# Start Exegol container
toolkit.exegol.start_container("pentest-project", image="full")

# Execute command
output = toolkit.exegol.execute("nmap -sV target.com")

# Import results to Faraday
toolkit.faraday.import_scan("project", "nmap.xml")

# View vulnerabilities
vulns = toolkit.faraday.get_vulnerabilities("project")
```

### MCP Tools

| Tool | Description |
|------|-------------|
| 5ire | MCP client with multi-provider LLM support |
| MCP-Kali-Server | Kali Linux tools via MCP |
| mcpsvr | MCP server directory/registry |

```python
from tools.integrations import MCPToolkit

toolkit = MCPToolkit()

# Setup recommended MCP servers
toolkit.setup_recommended_servers()

# Export configuration
toolkit.export_all_configs("mcp-config.json")

# Run Kali scan
result = toolkit.kali.nmap_scan("192.168.1.0/24")
```

### Resource Collections

| Tool | Stars | Description |
|------|-------|-------------|
| LinkHub | 21 | Curated security resource collection |
| blackhat-arsenal-tools | - | Black Hat Arsenal registry |
| dark-web-osint-tools | 1,566 | Dark web OSINT collection |
| containerized-security-toolkit | 16 | Docker security environments |

```python
from tools.integrations import ResourceToolkit

toolkit = ResourceToolkit()

# Search across all collections
results = toolkit.search("sql injection")

# Get Arsenal tools by year/category
tools_2024 = toolkit.arsenal.get_tools_by_year(2024)
web_tools = toolkit.arsenal.get_tools_by_category("web")
```

### Web Scraping

| Tool | Stars | Description |
|------|-------|-------------|
| Scrapy | 46k+ | Industrial-strength web crawling framework |
| BeautifulSoup | - | Fast HTML/XML parsing (no JS) |
| Puppeteer | 88k+ | Headless Chrome automation (Node.js) |
| Playwright | 60k+ | Multi-browser automation (Chromium, Firefox, WebKit) |
| Requests-HTML | - | HTTP library with JavaScript rendering |

```python
from tools.integrations import WebScrapingToolkit, quick_scrape, extract_links

# Unified toolkit
toolkit = WebScrapingToolkit()

# Quick scrape (static pages, no JS)
result = toolkit.quick_scrape("https://example.com", {
    "title": "h1",
    "links": "a::attr(href)"
})

# Scrape with JavaScript rendering
import asyncio
result = asyncio.run(toolkit.js_scrape("https://spa-app.com", {
    "products": ".product-name",
    "prices": ".price"
}))

# Full website crawl
from tools.integrations import CrawlConfig
config = CrawlConfig(
    start_urls=["https://example.com"],
    max_depth=3,
    max_pages=50
)
result = toolkit.crawl(config, {"title": "h1", "content": "p"})

# Convenience functions
links = extract_links("https://example.com")
tables = extract_tables("https://example.com/data")
```

### OSINT Tools

| Tool | Description |
|------|-------------|
| SpeedyDork | Google dorking automation |
| DataSploit | OSINT framework (domain, email, username) |
| PastebinMonitor | Credential leak monitoring |

### Mobile Security

| Tool | Description |
|------|-------------|
| Objection | Frida-based mobile exploitation |
| MobSF | Mobile static/dynamic analysis |

### Cloud Security

| Tool | Description |
|------|-------------|
| Prowler | AWS/Azure/GCP/K8s scanner (300+ checks) |

### Vulnerability Intelligence

| Tool | Stars | Description |
|------|-------|-------------|
| vFeed | 1,100 | Correlated CVE database |

### CTF & Training

| Tool | Stars | Description |
|------|-------|-------------|
| XBOW Platform | 76 | AI-driven CTF competitions |
| validation-benchmarks | 451 | 104 CTF challenges |

## Unified Factory

```python
from tools.integrations import create_toolkit, list_all_integrations, get_integration_count

# Get all toolkits
all_tools = create_toolkit("all")

# Get specific toolkit
darkweb = create_toolkit("darkweb")
security = create_toolkit("security")
mcp = create_toolkit("mcp")
resources = create_toolkit("resources")
ai = create_toolkit("ai")
scraping = create_toolkit("scraping")

# List all integrations
integrations = list_all_integrations()
count = get_integration_count()  # 43 tools
```

## External Tools Directory

All external tools are located in `BlackBox/external-tools\`:

```
external-tools/
├── robin/                    # AI dark web OSINT
├── darker/                   # Meta-searcher
├── TorBot/                   # Dark web crawler
├── darkdump/                 # Ahmia.fi scraper
├── zilbers-dark-web-scraper/ # Full-stack dashboard
├── Dark_Web_Scraping/        # Forum scrapers
├── dark-web-scraper/         # PyPI package
├── Scrapegraph-ai/           # LLM scraping
├── ai-context/               # Context generator
├── shannon/                  # AI pentester
├── Exegol/                   # Docker pentest env
├── faraday/                  # Collaborative IDE
├── merlin/                   # C2 framework
├── archerysec/               # Vuln management
├── anbu/                     # CLI toolkit
├── 5ire/                     # MCP client
├── MCP-Kali-Server/          # Kali MCP
├── mcpsvr/                   # MCP directory
├── link-hub/                 # Resource collection
├── blackhat-arsenal-tools/   # Arsenal registry
├── dark-web-osint-tools/     # OSINT collection
├── containerized-security-toolkit/
├── vFeed/                    # CVE database
├── prowler/                  # Cloud security
├── objection/                # Mobile exploitation
├── mobsf/                    # Mobile analysis
├── SpeedyDork/               # Google dorking
├── datasploit/               # OSINT framework
├── validation-benchmarks/    # CTF challenges
├── ez-xbow-platform-mcp/     # CTF platform
└── xbow-competition/         # CTF agent
```

## Version

Integration Layer: v2.1.0
Core Tools: v3.3.0
Main Package: v6.2.1
MCP Server: v9.1 (176 tools)

## Audit Status

Last audit: 2026-01-22
- All 14 integration modules verified
- All 53 external tool integrations tested
- Core security tools import paths fixed
- All exports properly aliased
- Bare except blocks fixed (13 → 0)
- jsbeautifier dependency installed
- All 66 tools passing verification tests
- 6 unified toolkits operational

## Enhanced Recon Capabilities (NEW)

| Capability | Before | After |
|------------|--------|-------|
| Secret Patterns | 5 | 25+ |
| Subdomain Sources | 0 | 3 (CT, Wayback, DNS) |
| Cloud Providers | 0 | 3 (AWS, Azure, GCP) |
| Auth Tests | 0 | 4 |
| GraphQL Tests | 0 | 4 |
| XSS Payloads | 0 | 50+ |
| SQLi Payloads | 0 | 20+ |
| Dynamic Tests | 0 | 7 |
| New Tool Classes | 0 | 10 |

### New Classes

```
Advanced Recon (advanced_recon.py):
- JSDeepAnalyzer      - Source map recovery, 25+ secret patterns
- GraphQLTester       - Introspection, batching, field suggestions
- SubdomainEnumerator - CT logs, Wayback, DNS brute force, takeover
- AuthTester          - Username enum, rate limiting, session security
- CloudAssetDiscovery - S3, Azure Blob, GCP bucket enumeration
- AdvancedRecon       - Unified reconnaissance toolkit

Dynamic Testing (dynamic_tester.py):
- DynamicTester       - Playwright-based SPA testing
- APITester           - IDOR, mass assignment, verb tampering
- XSSPayloads         - 50+ context-aware XSS payloads
- SQLiPayloads        - Error, time, and boolean-based payloads
```
