"""
AI-Powered Scraping Tools Integration
=====================================
LLM-powered web scraping and context generation tools.

Includes:
- ScrapeGraphAI: LLM-powered scraper (22,400 stars) - just describe what you want
- ai-context: Generate LLM context from code, GitHub, YouTube, webpages (149 stars)

Total: 2 AI scraping tool integrations
"""

import subprocess
import json
import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
from dataclasses import dataclass, field
from enum import Enum

EXTERNAL_PATH = Path(__file__).parent.parent.parent / "external-tools"


class LLMProvider(Enum):
    """Supported LLM providers for ScrapeGraphAI"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GROQ = "groq"
    AZURE = "azure"
    GEMINI = "gemini"
    OLLAMA = "ollama"


class GraphType(Enum):
    """ScrapeGraphAI graph types"""
    SMART_SCRAPER = "SmartScraperGraph"
    SEARCH = "SearchGraph"
    SPEECH = "SpeechGraph"
    SCRIPT_CREATOR = "ScriptCreatorGraph"


@dataclass
class ScrapeResult:
    """Result from AI-powered scraping"""
    source: str
    prompt: str
    data: Dict[str, Any]
    model_used: str
    success: bool = True
    error: str = ""


@dataclass
class ContextFile:
    """Generated context file for LLM"""
    source: str
    source_type: str  # repo, url, youtube, local
    content: str
    file_path: str
    tokens_estimate: int = 0


class ScrapeGraphAI:
    """
    ScrapeGraphAI - LLM-Powered Web Scraper.

    Just describe what you want to extract - the LLM does the rest.
    No CSS selectors, no XPath - pure natural language scraping.

    Original: https://github.com/ScrapeGraphAI/Scrapegraph-ai (22,400 stars)

    Supports: OpenAI, Groq, Azure, Gemini, Ollama (local)

    Graph Types:
    - SmartScraperGraph: Single page scraping with prompt
    - SearchGraph: Multi-page from search results
    - SpeechGraph: Scrape + text-to-speech
    - ScriptCreatorGraph: Generate Python scraping script

    Example:
        scraper = ScrapeGraphAI(provider=LLMProvider.OLLAMA, model="llama3.1")
        result = scraper.scrape(
            url="https://target.com",
            prompt="Extract all product names and prices"
        )
    """

    def __init__(
        self,
        provider: LLMProvider = LLMProvider.OPENAI,
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        scrapegraph_path: Optional[Path] = None
    ):
        self.provider = provider
        self.model = model
        self.api_key = api_key or os.environ.get(f"{provider.value.upper()}_API_KEY")
        self.scrapegraph_path = scrapegraph_path or EXTERNAL_PATH / "Scrapegraph-ai"

    def _get_config(self) -> Dict[str, Any]:
        """Generate config for ScrapeGraphAI"""
        config = {
            "llm": {
                "model": f"{self.provider.value}/{self.model}",
            },
            "verbose": True,
            "headless": True
        }

        if self.api_key:
            config["llm"]["api_key"] = self.api_key

        if self.provider == LLMProvider.OLLAMA:
            config["llm"]["model"] = f"ollama/{self.model}"
            config["llm"]["base_url"] = "http://localhost:11434"

        return config

    def scrape(
        self,
        source: str,
        prompt: str,
        graph_type: GraphType = GraphType.SMART_SCRAPER
    ) -> ScrapeResult:
        """
        Scrape using natural language prompt.

        Args:
            source: URL or local file path
            prompt: What to extract (e.g., "Extract all product names and prices")
            graph_type: Type of scraping graph to use

        Returns:
            ScrapeResult with extracted data
        """
        config = self._get_config()

        # Generate Python code to execute
        code = f'''
import sys
sys.path.insert(0, r"{self.scrapegraph_path}")

from scrapegraphai.graphs import {graph_type.value}

config = {json.dumps(config)}

scraper = {graph_type.value}(
    prompt="""{prompt}""",
    source="{source}",
    config=config
)

result = scraper.run()
import json
print(json.dumps(result))
'''

        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, f"{self.provider.value.upper()}_API_KEY": self.api_key or ""}
        )

        try:
            data = json.loads(result.stdout)
            return ScrapeResult(
                source=source,
                prompt=prompt,
                data=data,
                model_used=f"{self.provider.value}/{self.model}",
                success=True
            )
        except Exception:
            return ScrapeResult(
                source=source,
                prompt=prompt,
                data={},
                model_used=f"{self.provider.value}/{self.model}",
                success=False,
                error=result.stderr
            )

    def scrape_smart(self, url: str, prompt: str) -> ScrapeResult:
        """Single page smart scraping"""
        return self.scrape(url, prompt, GraphType.SMART_SCRAPER)

    def scrape_search(self, query: str, prompt: str) -> ScrapeResult:
        """Multi-page scraping from search results"""
        return self.scrape(query, prompt, GraphType.SEARCH)

    def generate_script(self, url: str, prompt: str) -> str:
        """Generate a Python scraping script for the URL"""
        result = self.scrape(url, prompt, GraphType.SCRIPT_CREATOR)
        return result.data.get("script", "")

    @staticmethod
    def get_example_prompts() -> Dict[str, str]:
        """Example prompts for common scraping tasks"""
        return {
            "products": "Extract all product names, prices, and descriptions",
            "contacts": "Extract all email addresses, phone numbers, and contact names",
            "articles": "Extract article titles, authors, dates, and summaries",
            "links": "Extract all links with their anchor text and destination URLs",
            "social": "Extract all social media profile links and usernames",
            "threat_intel": "Extract threat actor names, TTPs, IOCs, and malware families",
            "credentials": "Extract any exposed usernames, passwords, or API keys",
            "crypto": "Extract all cryptocurrency wallet addresses"
        }


class AIContext:
    """
    ai-context - LLM Context Generator.

    Generate markdown context files from multiple sources for LLM consumption.
    Perfect for feeding code/docs to Claude, GPT, or local models.

    Original: https://github.com/Tanq16/ai-context (149 stars)

    Sources:
    - Local directories and git repos
    - GitHub repositories (including private with GH_TOKEN)
    - YouTube videos (transcripts with timestamps)
    - Web pages (HTML → markdown with images)

    Example:
        ctx = AIContext()
        ctx.from_github("https://github.com/user/repo")
        ctx.from_youtube("https://youtube.com/watch?v=...")
        ctx.from_url("https://docs.example.com")
    """

    def __init__(self, ai_context_path: Optional[Path] = None, output_dir: str = "./context"):
        self.ai_context_path = ai_context_path or EXTERNAL_PATH / "ai-context"
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _run_ai_context(self, *args) -> subprocess.CompletedProcess:
        """Run ai-context CLI"""
        # Try binary first, then go run
        binary = self.ai_context_path / "ai-context"
        if binary.exists():
            cmd = [str(binary)] + list(args)
        else:
            cmd = ["go", "run", "."] + list(args)

        return subprocess.run(
            cmd,
            cwd=str(self.ai_context_path),
            capture_output=True,
            text=True
        )

    def from_local(
        self,
        path: str,
        ignore_patterns: Optional[List[str]] = None
    ) -> ContextFile:
        """
        Generate context from local directory.

        Args:
            path: Path to local directory
            ignore_patterns: Patterns to ignore (e.g., ["node_modules", "dist"])

        Returns:
            ContextFile with generated content
        """
        args = [path]
        if ignore_patterns:
            args.extend(["-i", ",".join(ignore_patterns)])

        result = self._run_ai_context(*args)

        return ContextFile(
            source=path,
            source_type="local",
            content=result.stdout,
            file_path=str(self.output_dir / f"LOCAL-{Path(path).name}.md")
        )

    def from_github(
        self,
        repo_url: str,
        ignore_patterns: Optional[List[str]] = None
    ) -> ContextFile:
        """
        Generate context from GitHub repository.

        Args:
            repo_url: GitHub repository URL
            ignore_patterns: Patterns to ignore

        Returns:
            ContextFile with generated content
        """
        args = [repo_url]
        if ignore_patterns:
            args.extend(["-i", ",".join(ignore_patterns)])

        result = self._run_ai_context(*args)

        repo_name = repo_url.rstrip("/").split("/")[-1]
        return ContextFile(
            source=repo_url,
            source_type="repo",
            content=result.stdout,
            file_path=str(self.output_dir / f"REPO-{repo_name}.md")
        )

    def from_youtube(self, video_url: str) -> ContextFile:
        """
        Generate context from YouTube video transcript.

        Args:
            video_url: YouTube video URL

        Returns:
            ContextFile with transcript
        """
        result = self._run_ai_context(video_url)

        video_id = video_url.split("v=")[-1].split("&")[0]
        return ContextFile(
            source=video_url,
            source_type="youtube",
            content=result.stdout,
            file_path=str(self.output_dir / f"YOUTUBE-{video_id}.md")
        )

    def from_url(self, url: str) -> ContextFile:
        """
        Generate context from web page.

        Converts HTML to markdown, downloads images locally.

        Args:
            url: Web page URL

        Returns:
            ContextFile with markdown content
        """
        result = self._run_ai_context(url)

        domain = url.split("//")[-1].split("/")[0].replace(".", "-")
        return ContextFile(
            source=url,
            source_type="url",
            content=result.stdout,
            file_path=str(self.output_dir / f"URL-{domain}.md")
        )

    def from_file_list(
        self,
        file_path: str,
        threads: int = 10
    ) -> List[ContextFile]:
        """
        Process multiple URLs from a file.

        Args:
            file_path: Path to file with URLs (one per line)
            threads: Number of concurrent threads

        Returns:
            List of ContextFiles
        """
        result = self._run_ai_context("-f", file_path, "--threads", str(threads))
        # Results are saved to context/ directory
        return []

    def start_web_ui(self, port: int = 8501) -> subprocess.Popen:
        """Start the Streamlit web UI"""
        return subprocess.Popen(
            [self._run_ai_context("serve")],
            cwd=str(self.ai_context_path)
        )

    @staticmethod
    def get_recommended_ignores() -> Dict[str, List[str]]:
        """Recommended ignore patterns by project type"""
        return {
            "node": ["node_modules", "dist", "build", ".next", "coverage"],
            "python": ["__pycache__", ".venv", "venv", "*.pyc", ".pytest_cache"],
            "go": ["vendor", "bin"],
            "general": [".git", ".idea", ".vscode", "*.log", "*.lock"]
        }


# Unified interface
class AIScrapingToolkit:
    """
    Unified AI Scraping Toolkit.

    Combines ScrapeGraphAI's natural language scraping with
    ai-context's LLM context generation.

    Example:
        toolkit = AIScrapingToolkit()

        # Scrape with natural language
        data = toolkit.scrape("https://target.com", "Extract all emails and names")

        # Generate context for LLM analysis
        context = toolkit.generate_context("https://github.com/user/repo")

        # Feed scraped data to LLM via context
        toolkit.scrape_and_contextualize(url, prompt)
    """

    def __init__(
        self,
        llm_provider: LLMProvider = LLMProvider.OLLAMA,
        model: str = "llama3.1"
    ):
        self.scrapegraph = ScrapeGraphAI(provider=llm_provider, model=model)
        self.ai_context = AIContext()

    def scrape(self, url: str, prompt: str) -> ScrapeResult:
        """Scrape using natural language"""
        return self.scrapegraph.scrape_smart(url, prompt)

    def generate_context(self, source: str) -> ContextFile:
        """Generate LLM context from source"""
        if source.startswith("https://github.com"):
            return self.ai_context.from_github(source)
        elif source.startswith("https://youtube.com") or source.startswith("https://www.youtube.com"):
            return self.ai_context.from_youtube(source)
        elif source.startswith("http"):
            return self.ai_context.from_url(source)
        else:
            return self.ai_context.from_local(source)

    def scrape_for_threat_intel(self, url: str) -> ScrapeResult:
        """Scrape specifically for threat intelligence"""
        return self.scrapegraph.scrape_smart(
            url,
            "Extract all threat actor names, malware families, TTPs, IOCs (IPs, domains, hashes), and CVE references"
        )

    def scrape_for_credentials(self, url: str) -> ScrapeResult:
        """Scrape for exposed credentials"""
        return self.scrapegraph.scrape_smart(
            url,
            "Extract any exposed usernames, passwords, API keys, tokens, or authentication credentials"
        )

    def scrape_for_crypto(self, url: str) -> ScrapeResult:
        """Scrape for cryptocurrency addresses"""
        return self.scrapegraph.scrape_smart(
            url,
            "Extract all cryptocurrency wallet addresses (Bitcoin, Ethereum, Monero, etc.)"
        )
