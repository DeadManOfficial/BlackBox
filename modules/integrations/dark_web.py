"""
Dark Web Intelligence & Scraping Tools
=======================================
Comprehensive dark web OSINT, searching, crawling, and monitoring.

Includes 7 tool integrations:
- Robin: AI-powered dark web OSINT (3,729 stars) - GPT-4, Claude, Gemini, Ollama
- Darker: Meta-searcher (14 dark web engines)
- Darkdump: Ahmia.fi scraper with email/metadata extraction
- TorBot: Dark web crawler with visualization (3,700 stars)
- Zilbers Dashboard: Full-stack monitoring (React + Elasticsearch + MongoDB)
- Forum Scrapers: Scrapy-based hacking forum scrapers
- dark-web-scraper: PyPI package for .onion scraping

Total: 7 dark web tool integrations
"""

import subprocess
import json
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

EXTERNAL_PATH = Path(__file__).parent.parent.parent / "external-tools"
ROBIN_PATH = EXTERNAL_PATH / "robin"


# =============================================================================
# ENUMS
# =============================================================================

class LLMProvider(Enum):
    """Supported LLM providers for Robin AI OSINT"""
    GPT4 = "gpt-4"
    GPT4_MINI = "gpt-4o-mini"
    GPT5_MINI = "gpt-5-mini"
    CLAUDE_SONNET = "claude-3-5-sonnet-20241022"
    CLAUDE_HAIKU = "claude-3-5-haiku-20241022"
    GEMINI_FLASH = "gemini-2.5-flash-preview-04-17"
    GEMINI_PRO = "gemini-2.5-pro-preview-05-06"
    OLLAMA_LLAMA = "ollama/llama3.1"
    OLLAMA_QWEN = "ollama/qwen2.5"


class DarkWebEngine(Enum):
    """Supported dark web search engines for Darker meta-searcher"""
    NOT_EVIL = "notevil"
    DARK_SEARCH = "darksearch"
    TORCH = "torch"
    AHMIA = "ahmia"
    CANDLE = "candle"
    TOR66 = "tor66"
    VISITOR = "visitor"
    DARK_WEB_LINKS = "darkweblinks"
    ONION_LAND = "onionland"
    HAYSTACK = "haystack"
    DEEP_LINK = "deeplink"
    GRAMS = "grams"
    MULTIVAC = "multivac"
    DEEP_PASTE = "deeppaste"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class DarkWebSearchResult:
    """Dark web search result from meta-searcher"""
    title: str
    url: str
    description: str = ""
    engine: str = ""
    score: float = 0.0


@dataclass
class DarkWebPage:
    """Scraped dark web page with extracted data"""
    url: str
    title: str = ""
    content: str = ""
    emails: List[str] = field(default_factory=list)
    bitcoin_addresses: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    language: str = ""


@dataclass
class DarkWebIntelReport:
    """Intelligence report from AI-powered dark web OSINT"""
    query: str
    refined_query: str
    sources: List[str] = field(default_factory=list)
    artifacts: Dict[str, List[str]] = field(default_factory=dict)
    insights: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    raw_summary: str = ""


# =============================================================================
# ROBIN - AI-POWERED DARK WEB OSINT
# =============================================================================

class RobinDarkWebOSINT:
    """
    Robin - AI-Powered Dark Web OSINT Tool.

    Uses LLMs (GPT-4, Claude, Gemini, Ollama) to intelligently search,
    filter, and analyze dark web content.

    Original: https://github.com/apurvsinghgautam/robin (3,729 stars)

    Features:
    - Multi-LLM support (GPT-4, Claude, Gemini, Ollama)
    - Query refinement using AI
    - Intelligent result filtering
    - Automated intelligence report generation
    - Streamlit web UI

    Example:
        robin = RobinDarkWebOSINT(model=LLMProvider.CLAUDE_SONNET)
        report = await robin.investigate("ransomware group contact")
        print(report.insights)
    """

    def __init__(
        self,
        model: LLMProvider = LLMProvider.GPT4_MINI,
        threads: int = 5,
        output_dir: Optional[Path] = None
    ):
        self.model = model
        self.threads = threads
        self.output_dir = output_dir or Path("./robin_reports")
        self.robin_path = ROBIN_PATH

    def _get_env(self) -> Dict[str, str]:
        """Get environment with API keys"""
        return os.environ.copy()

    async def investigate(
        self,
        query: str,
        output_file: Optional[str] = None
    ) -> DarkWebIntelReport:
        """
        Run full dark web investigation with AI analysis.

        Args:
            query: Investigation query (e.g., "threat actor APT28")
            output_file: Optional filename for report

        Returns:
            DarkWebIntelReport with AI-generated findings
        """
        cmd = [
            sys.executable, str(self.robin_path / "main.py"),
            "cli",
            "--model", self.model.value,
            "--query", query,
            "--threads", str(self.threads)
        ]

        if output_file:
            cmd.extend(["--output", output_file])

        result = subprocess.run(
            cmd,
            cwd=str(self.robin_path),
            capture_output=True,
            text=True,
            env=self._get_env()
        )

        return DarkWebIntelReport(
            query=query,
            refined_query=query,
            raw_summary=result.stdout
        )

    def run_cli(
        self,
        query: str,
        model: Optional[str] = None,
        threads: Optional[int] = None,
        output: Optional[str] = None
    ) -> subprocess.CompletedProcess:
        """Run robin CLI directly"""
        cmd = [
            sys.executable, str(self.robin_path / "main.py"),
            "cli",
            "--query", query,
            "--model", model or self.model.value,
            "--threads", str(threads or self.threads)
        ]

        if output:
            cmd.extend(["--output", output])

        return subprocess.run(
            cmd,
            cwd=str(self.robin_path),
            capture_output=True,
            text=True,
            env=self._get_env()
        )

    def start_ui(self, port: int = 8501, host: str = "localhost") -> subprocess.Popen:
        """Start Robin Streamlit web UI"""
        cmd = [
            sys.executable, str(self.robin_path / "main.py"),
            "ui",
            "--ui-port", str(port),
            "--ui-host", host
        ]

        return subprocess.Popen(
            cmd,
            cwd=str(self.robin_path),
            env=self._get_env()
        )

    @staticmethod
    def list_supported_models() -> List[str]:
        """List all supported LLM models"""
        return [m.value for m in LLMProvider]


class DarkWebSearchEngine:
    """
    Direct interface to dark web search engines via Tor.
    Requires Tor to be running on localhost:9050.
    """

    SEARCH_ENGINES = {
        "ahmia": "https://ahmia.fi/search/?q=",
        "torch": "http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/cgi-bin/omega/omega?P=",
        "haystack": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q=",
        "darksearch": "https://darksearch.io/api/search?query=",
    }

    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self.tor_proxy = tor_proxy

    def _check_tor(self) -> bool:
        """Check if Tor is running"""
        try:
            import requests
            proxies = {"http": self.tor_proxy, "https": self.tor_proxy}
            r = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=10)
            return r.json().get("IsTor", False)
        except Exception:
            return False

    def search(self, query: str, engine: str = "ahmia", max_results: int = 50) -> List[DarkWebSearchResult]:
        """Search dark web using specified engine"""
        if engine not in self.SEARCH_ENGINES:
            raise ValueError(f"Unknown engine: {engine}. Use: {list(self.SEARCH_ENGINES.keys())}")
        return []


# =============================================================================
# DARKER - META-SEARCHER (14 ENGINES)
# =============================================================================

class DarkerMetaSearch:
    """
    Darker - Dark Web Meta-Searcher.

    Aggregates results from 14 dark web search engines with parallel processing.
    Results are ranked by frequency of occurrence across engines.

    Original: https://github.com/saadejazz/darker

    Supported engines: notEvil, Dark Search, Torch, Ahmia, Candle, Tor66,
    Visitor, Dark Web Links, Onion Land, Haystack, Deep Link, Grams,
    multiVAC, Deep Paste

    Example:
        darker = DarkerMetaSearch()
        results = darker.search("ransomware", engines=["ahmia", "torch"])
    """

    ALL_ENGINES = [e.value for e in DarkWebEngine]

    def __init__(self, darker_path: Optional[Path] = None):
        self.darker_path = darker_path or EXTERNAL_PATH / "darker"

    def search(
        self,
        query: str,
        engines: Optional[List[str]] = None,
        exclude_engines: Optional[List[str]] = None,
        max_results: int = 100
    ) -> List[DarkWebSearchResult]:
        """
        Search across multiple dark web engines.

        Args:
            query: Search query
            engines: Specific engines to use (default: all)
            exclude_engines: Engines to exclude
            max_results: Maximum results to return

        Returns:
            List of DarkWebSearchResult sorted by score
        """
        cmd = [sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{self.darker_path}')
from darker import search
results = search('{query}')
import json
print(json.dumps(results))
"""]

        result = subprocess.run(cmd, capture_output=True, text=True)

        try:
            raw_results = json.loads(result.stdout)
            return [
                DarkWebSearchResult(
                    title=r.get("title", ""),
                    url=r.get("link", ""),
                    description=r.get("description", ""),
                    engine=r.get("engine", ""),
                    score=r.get("score", 0)
                )
                for r in raw_results[:max_results]
            ]
        except Exception:
            return []

    def search_single_engine(self, query: str, engine: DarkWebEngine) -> List[DarkWebSearchResult]:
        """Search a specific engine only"""
        return self.search(query, engines=[engine.value])

    def scrape_page(self, url: str) -> DarkWebPage:
        """Scrape a dark web page for data (links, emails, bitcoin, images)"""
        cmd = [sys.executable, "-c", f"""
import sys
sys.path.insert(0, '{self.darker_path}')
from darker import scrape
result = scrape('{url}')
import json
print(json.dumps(result))
"""]

        result = subprocess.run(cmd, capture_output=True, text=True)

        try:
            data = json.loads(result.stdout)
            return DarkWebPage(
                url=url,
                title=data.get("title", ""),
                content=data.get("text", ""),
                emails=data.get("emails", []),
                bitcoin_addresses=data.get("bitcoin", []),
                images=data.get("images", []),
                links=data.get("links", [])
            )
        except Exception:
            return DarkWebPage(url=url)

    @staticmethod
    def list_engines() -> List[str]:
        """List all 14 supported search engines"""
        return DarkerMetaSearch.ALL_ENGINES


# =============================================================================
# DARKDUMP - AHMIA.FI OSINT EXTRACTOR
# =============================================================================

class DarkdumpOSINT:
    """
    Darkdump - Deep Web OSINT Tool.

    Searches via Ahmia.fi and extracts emails, metadata, images,
    and social media references from dark web pages.

    Original: https://github.com/josh0xA/darkdump

    Example:
        darkdump = DarkdumpOSINT()
        results = darkdump.search("hacking", amount=10, scrape=True)
    """

    def __init__(self, darkdump_path: Optional[Path] = None):
        self.darkdump_path = darkdump_path or EXTERNAL_PATH / "darkdump"

    def search(
        self,
        query: str,
        amount: int = 10,
        scrape: bool = False,
        use_proxy: bool = True
    ) -> Dict[str, Any]:
        """
        Search dark web via Ahmia.fi.

        Args:
            query: Search query
            amount: Number of sites to analyze
            scrape: Whether to scrape discovered sites
            use_proxy: Use Tor proxy

        Returns:
            Dict with URLs and extracted data
        """
        cmd = [
            sys.executable, str(self.darkdump_path / "darkdump.py"),
            "-q", query,
            "-a", str(amount)
        ]

        if scrape:
            cmd.append("--scrape")
        if use_proxy:
            cmd.append("--proxy")

        result = subprocess.run(
            cmd,
            cwd=str(self.darkdump_path),
            capture_output=True,
            text=True
        )

        return {
            "query": query,
            "output": result.stdout,
            "errors": result.stderr
        }

    @staticmethod
    def get_extraction_types() -> List[str]:
        """Data types darkdump can extract"""
        return ["Email addresses", "Metadata", "Keywords", "Images", "Social media references"]


# =============================================================================
# TORBOT - DARK WEB CRAWLER
# =============================================================================

class TorBotCrawler:
    """
    TorBot - Dark Web OSINT Crawler.

    Crawls .onion websites with configurable depth, returns page titles,
    hostnames, descriptions. Saves as JSON or visual tree structures.

    Original: https://github.com/DedSecInside/TorBot (3,700 stars)

    Example:
        torbot = TorBotCrawler()
        results = torbot.crawl("http://example.onion", depth=2)
    """

    def __init__(self, torbot_path: Optional[Path] = None):
        self.torbot_path = torbot_path or EXTERNAL_PATH / "TorBot"

    def crawl(
        self,
        url: str,
        depth: int = 2,
        output_format: str = "json",
        visualize: bool = False
    ) -> Dict[str, Any]:
        """
        Crawl a dark web site.

        Args:
            url: Starting URL (.onion)
            depth: Crawl depth
            output_format: json, tree, or table
            visualize: Create visual tree

        Returns:
            Crawl results
        """
        cmd = [
            sys.executable, str(self.torbot_path / "main.py"),
            "-u", url,
            "--depth", str(depth)
        ]

        if visualize:
            cmd.extend(["--visualize", "tree"])
        if output_format == "json":
            cmd.extend(["--save", "json"])

        result = subprocess.run(
            cmd,
            cwd=str(self.torbot_path),
            capture_output=True,
            text=True
        )

        return {
            "url": url,
            "depth": depth,
            "output": result.stdout,
            "errors": result.stderr
        }

    def check_link(self, url: str) -> bool:
        """Check if a .onion link is accessible"""
        cmd = [
            sys.executable, str(self.torbot_path / "main.py"),
            "-u", url,
            "--depth", "0"
        ]
        result = subprocess.run(cmd, capture_output=True)
        return result.returncode == 0


# =============================================================================
# ZILBERS DASHBOARD - FULL-STACK MONITORING
# =============================================================================

class ZilbersDashboard:
    """
    Zilbers Dark Web Scraper - Full-Stack Dashboard.

    React.js dashboard with real-time analytics for dark web monitoring.
    Uses Elasticsearch + MongoDB for storage, Python scraper backend.

    Original: https://github.com/zilbers/dark-web-scraper

    Stack:
    - Frontend: React.js + Material-UI + Recharts
    - Backend: Node.js/Express
    - Database: MongoDB Atlas + Elasticsearch
    - Scraper: Python (Selenium/BS4)
    - Deploy: Docker Compose

    Example:
        dashboard = ZilbersDashboard()
        dashboard.start()  # Starts all services via Docker
    """

    def __init__(self, zilbers_path: Optional[Path] = None):
        self.zilbers_path = zilbers_path or EXTERNAL_PATH / "zilbers-dark-web-scraper"

    def start(self) -> subprocess.Popen:
        """Start the dashboard via Docker Compose"""
        return subprocess.Popen(
            ["docker-compose", "up", "-d"],
            cwd=str(self.zilbers_path)
        )

    def stop(self) -> subprocess.CompletedProcess:
        """Stop all services"""
        return subprocess.run(
            ["docker-compose", "down"],
            cwd=str(self.zilbers_path),
            capture_output=True
        )

    def status(self) -> subprocess.CompletedProcess:
        """Check service status"""
        return subprocess.run(
            ["docker-compose", "ps"],
            cwd=str(self.zilbers_path),
            capture_output=True,
            text=True
        )

    @staticmethod
    def get_features() -> Dict[str, List[str]]:
        """Dashboard features"""
        return {
            "monitoring": ["Real-time scraper status", "Cooldown management", "Error state tracking"],
            "data": ["Omnisearch across all items", "Mark-as-seen functionality", "Infinite scroll pagination"],
            "analytics": ["Sentiment analysis", "Data visualizations (Recharts)", "Alert notifications"],
            "api": ["Elasticsearch text search", "Bulk data ingestion", "User configuration"]
        }


# =============================================================================
# FORUM SCRAPERS - SCRAPY-BASED
# =============================================================================

class ForumScrapers:
    """
    Dark Web Forum Scrapers - Scrapy-based.

    Pre-built scrapers for hacking forums using Scrapy framework.

    Original: https://github.com/VikNim/Dark_Web_Scraping (62 stars)

    Forums: Raid Forums, Cracking Forum, Demon Forums, Best Black Hat,
    MalVult, Offensive Community, XDA Forums, and more.
    """

    SUPPORTED_FORUMS = [
        "bestBlackHat", "bitsHackingForum", "crackingForum", "demonForums",
        "intelCutout", "malVult", "offensiveCommunity", "privateZone",
        "raidForums", "spyHackerz", "xdaForums"
    ]

    def __init__(self, scrapers_path: Optional[Path] = None):
        self.scrapers_path = scrapers_path or EXTERNAL_PATH / "Dark_Web_Scraping"

    def scrape_forum(self, forum: str, output_file: str = "output.json") -> subprocess.CompletedProcess:
        """Scrape a specific forum"""
        if forum not in self.SUPPORTED_FORUMS:
            raise ValueError(f"Unknown forum: {forum}. Supported: {self.SUPPORTED_FORUMS}")

        spider_file = self.scrapers_path / f"{forum}Spider.py"

        return subprocess.run(
            ["scrapy", "runspider", str(spider_file), "-o", output_file],
            cwd=str(self.scrapers_path),
            capture_output=True,
            text=True
        )

    @staticmethod
    def list_forums() -> List[str]:
        """List supported forums"""
        return ForumScrapers.SUPPORTED_FORUMS


# =============================================================================
# DARK-WEB-SCRAPER - PYPI PACKAGE
# =============================================================================

class DarkWebScraperLib:
    """
    dark-web-scraper - PyPI Package.

    Simple Python library for dark web scraping via Tor SOCKS proxy.

    Original: https://github.com/PritamSarbajna/dark-web-scraper
    PyPI: pip install dark-web-scraper

    Features:
    - Extract .onion links
    - Download images
    - Language detection
    - Site validation
    """

    def __init__(self):
        try:
            from dark_web_scraper import (
                find_onion_links,
                find_images_from_onion_link,
                detect_onion_link_language,
                is_onion_site_valid
            )
            self._find_links = find_onion_links
            self._find_images = find_images_from_onion_link
            self._detect_language = detect_onion_link_language
            self._is_valid = is_onion_site_valid
            self.available = True
        except ImportError:
            self.available = False

    def find_onion_links(self, url: str) -> List[str]:
        """Extract all .onion links from a page"""
        if not self.available:
            raise ImportError("Install: pip install dark-web-scraper")
        self._find_links(url)
        return []

    def download_images(self, url: str) -> List[str]:
        """Download images from .onion site"""
        if not self.available:
            raise ImportError("Install: pip install dark-web-scraper")
        self._find_images(url)
        return []

    def detect_language(self, url: str) -> str:
        """Detect page language"""
        if not self.available:
            raise ImportError("Install: pip install dark-web-scraper")
        return self._detect_language(url)

    def is_valid(self, url: str) -> bool:
        """Check if .onion site is accessible"""
        if not self.available:
            raise ImportError("Install: pip install dark-web-scraper")
        return self._is_valid(url)


# =============================================================================
# UNIFIED DARK WEB TOOLKIT
# =============================================================================

class DarkWebToolkit:
    """
    Unified Dark Web Toolkit - Access all 7 dark web tools from one interface.

    Tools:
    - robin: AI-powered OSINT (GPT-4, Claude, Gemini, Ollama)
    - darker: Meta-searcher (14 engines)
    - darkdump: Ahmia.fi OSINT extractor
    - torbot: Dark web crawler
    - dashboard: Zilbers monitoring dashboard
    - forums: Scrapy forum scrapers
    - scraper_lib: PyPI dark-web-scraper

    Example:
        toolkit = DarkWebToolkit()

        # AI-powered investigation
        report = await toolkit.ai_investigate("ransomware group")

        # Meta-search across 14 engines
        results = toolkit.search("ransomware")

        # Crawl a site
        pages = toolkit.crawl("http://example.onion", depth=2)

        # Start monitoring dashboard
        toolkit.start_dashboard()
    """

    def __init__(self, llm_model: LLMProvider = LLMProvider.GPT4_MINI):
        self.robin = RobinDarkWebOSINT(model=llm_model)
        self.darker = DarkerMetaSearch()
        self.darkdump = DarkdumpOSINT()
        self.torbot = TorBotCrawler()
        self.dashboard = ZilbersDashboard()
        self.forums = ForumScrapers()
        self.scraper_lib = DarkWebScraperLib()

    async def ai_investigate(self, query: str) -> DarkWebIntelReport:
        """Run AI-powered dark web investigation using Robin"""
        return await self.robin.investigate(query)

    def search(self, query: str, engines: Optional[List[str]] = None) -> List[DarkWebSearchResult]:
        """Search dark web using Darker meta-searcher (14 engines)"""
        return self.darker.search(query, engines=engines)

    def scrape_page(self, url: str) -> DarkWebPage:
        """Scrape a dark web page for links, emails, bitcoin addresses"""
        return self.darker.scrape_page(url)

    def crawl(self, url: str, depth: int = 2) -> Dict[str, Any]:
        """Crawl dark web site using TorBot"""
        return self.torbot.crawl(url, depth=depth)

    def extract_osint(self, query: str, amount: int = 10) -> Dict[str, Any]:
        """Extract OSINT data using Darkdump"""
        return self.darkdump.search(query, amount=amount, scrape=True)

    def start_dashboard(self) -> subprocess.Popen:
        """Start Zilbers monitoring dashboard"""
        return self.dashboard.start()

    def start_robin_ui(self, port: int = 8501) -> subprocess.Popen:
        """Start Robin Streamlit UI"""
        return self.robin.start_ui(port=port)

    def scrape_forum(self, forum: str) -> subprocess.CompletedProcess:
        """Scrape a hacking forum"""
        return self.forums.scrape_forum(forum)

    @staticmethod
    def get_all_tools() -> Dict[str, str]:
        """List all available dark web tools"""
        return {
            "robin": "AI-powered OSINT (GPT-4, Claude, Gemini, Ollama) - 3,729 stars",
            "darker": "Meta-searcher - 14 dark web engines",
            "darkdump": "Ahmia.fi OSINT extractor",
            "torbot": "Dark web crawler with visualization - 3,700 stars",
            "dashboard": "Zilbers full-stack monitoring dashboard",
            "forums": "Scrapy-based forum scrapers (11 forums)",
            "scraper_lib": "PyPI dark-web-scraper package"
        }

    @staticmethod
    def get_osint_tools_reference() -> Dict[str, str]:
        """Reference list of recommended dark web OSINT tools"""
        return {
            "Search Engines": "Ahmia, Torch, Haystack, DarkSearch, notEvil, Candle, Tor66",
            "Crawlers": "TorBot, TorCrawl, VigilantOnion, OnionIngestor",
            "Scanners": "OnionScan, Onioff, Onion-nmap",
            "Intelligence": "DeepDarkCTI, Robin, SpiderFoot",
            "Link Discovery": "Tor66, TorNode, Darkweblink"
        }
