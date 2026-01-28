"""
Web Scraping Tools Integration
==============================
Traditional and advanced web scraping frameworks.

Tools:
- Scrapy: Industrial-strength scraping framework (46k+ stars)
- BeautifulSoup: HTML/XML parsing library
- Puppeteer: Headless Chrome automation (Node.js)
- PlaywrightScraper: Browser automation scraping
- Requests-HTML: Modern HTTP library with JS rendering

ALL FREE FOREVER
"""

import asyncio
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

# Optional imports - graceful degradation
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import scrapy
    from scrapy.crawler import CrawlerProcess
    from scrapy.http import Request, Response
    HAS_SCRAPY = True
except ImportError:
    HAS_SCRAPY = False

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class OutputFormat(Enum):
    """Output format options"""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    JSONLINES = "jsonlines"


class SelectorType(Enum):
    """Selector type for element extraction"""
    CSS = "css"
    XPATH = "xpath"
    REGEX = "regex"


@dataclass
class ScrapedItem:
    """Represents a scraped data item"""
    url: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    selector_used: Optional[str] = None
    page_title: Optional[str] = None


@dataclass
class ScrapingResult:
    """Result of a scraping operation"""
    success: bool
    items: List[ScrapedItem]
    errors: List[str] = field(default_factory=list)
    pages_crawled: int = 0
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CrawlConfig:
    """Configuration for web crawling"""
    start_urls: List[str]
    allowed_domains: Optional[List[str]] = None
    max_depth: int = 2
    max_pages: int = 100
    follow_links: bool = True
    respect_robots_txt: bool = True
    delay_seconds: float = 1.0
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


# =============================================================================
# BEAUTIFULSOUP WRAPPER
# =============================================================================

class BeautifulSoupScraper:
    """
    BeautifulSoup HTML/XML parsing wrapper.

    Features:
    - CSS selector support
    - XPath-like navigation
    - HTML/XML parsing
    - Text extraction
    - Link extraction
    """

    def __init__(self, parser: str = "html.parser"):
        """
        Initialize BeautifulSoup scraper.

        Args:
            parser: Parser to use (html.parser, lxml, html5lib)
        """
        if not HAS_BS4:
            raise ImportError("BeautifulSoup not installed. Run: pip install beautifulsoup4")
        if not HAS_REQUESTS:
            raise ImportError("Requests not installed. Run: pip install requests")

        self.parser = parser
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def fetch(self, url: str, **kwargs) -> BeautifulSoup:
        """Fetch URL and return BeautifulSoup object"""
        response = self.session.get(url, **kwargs)
        response.raise_for_status()
        return BeautifulSoup(response.content, self.parser)

    def parse_html(self, html: str) -> BeautifulSoup:
        """Parse HTML string"""
        return BeautifulSoup(html, self.parser)

    def extract_text(self, url: str, selector: str,
                     selector_type: SelectorType = SelectorType.CSS) -> List[str]:
        """Extract text from elements matching selector"""
        soup = self.fetch(url)

        if selector_type == SelectorType.CSS:
            elements = soup.select(selector)
        else:
            # XPath not directly supported, use CSS approximation
            elements = soup.select(selector)

        return [el.get_text(strip=True) for el in elements]

    def extract_attributes(self, url: str, selector: str,
                          attribute: str) -> List[str]:
        """Extract attribute values from elements"""
        soup = self.fetch(url)
        elements = soup.select(selector)
        return [el.get(attribute) for el in elements if el.get(attribute)]

    def extract_links(self, url: str, absolute: bool = True) -> List[str]:
        """Extract all links from page"""
        soup = self.fetch(url)
        links = []

        for a in soup.find_all('a', href=True):
            href = a['href']
            if absolute:
                href = urljoin(url, href)
            links.append(href)

        return list(set(links))

    def extract_tables(self, url: str) -> List[List[List[str]]]:
        """Extract all tables from page"""
        soup = self.fetch(url)
        tables = []

        for table in soup.find_all('table'):
            rows = []
            for tr in table.find_all('tr'):
                cells = [td.get_text(strip=True)
                        for td in tr.find_all(['td', 'th'])]
                rows.append(cells)
            tables.append(rows)

        return tables

    def extract_structured(self, url: str,
                          selectors: Dict[str, str]) -> ScrapedItem:
        """
        Extract structured data using multiple selectors.

        Args:
            url: URL to scrape
            selectors: Dict mapping field names to CSS selectors

        Returns:
            ScrapedItem with extracted data
        """
        soup = self.fetch(url)
        data = {}

        for field_name, selector in selectors.items():
            elements = soup.select(selector)
            if len(elements) == 1:
                data[field_name] = elements[0].get_text(strip=True)
            elif len(elements) > 1:
                data[field_name] = [el.get_text(strip=True) for el in elements]
            else:
                data[field_name] = None

        title_tag = soup.find('title')
        page_title = title_tag.get_text(strip=True) if title_tag else None

        return ScrapedItem(
            url=url,
            data=data,
            page_title=page_title,
            selector_used=str(selectors)
        )

    def scrape_multiple(self, urls: List[str],
                       selectors: Dict[str, str]) -> ScrapingResult:
        """Scrape multiple URLs with same selectors"""
        items = []
        errors = []
        start_time = datetime.now()

        for url in urls:
            try:
                item = self.extract_structured(url, selectors)
                items.append(item)
            except Exception as e:
                errors.append(f"{url}: {str(e)}")

        duration = (datetime.now() - start_time).total_seconds()

        return ScrapingResult(
            success=len(errors) == 0,
            items=items,
            errors=errors,
            pages_crawled=len(urls),
            duration_seconds=duration
        )


# =============================================================================
# SCRAPY INTEGRATION
# =============================================================================

class ScrapyRunner:
    """
    Scrapy framework integration.

    Features:
    - Industrial-strength crawling
    - Automatic throttling
    - robots.txt compliance
    - Pipeline support
    - Multiple output formats
    """

    def __init__(self, project_dir: Optional[Path] = None):
        """
        Initialize Scrapy runner.

        Args:
            project_dir: Directory for Scrapy projects
        """
        self.project_dir = project_dir or Path(tempfile.mkdtemp())
        self.settings = {
            'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'ROBOTSTXT_OBEY': True,
            'CONCURRENT_REQUESTS': 16,
            'DOWNLOAD_DELAY': 1,
            'COOKIES_ENABLED': True,
            'LOG_LEVEL': 'WARNING',
        }

    def _create_spider_class(self, config: CrawlConfig,
                              selectors: Dict[str, str]) -> type:
        """
        Create Scrapy spider class dynamically using type().

        This is safer than exec() as it doesn't execute arbitrary code strings.
        """
        if not HAS_SCRAPY:
            raise ImportError("Scrapy not installed")

        domains = config.allowed_domains or [
            urlparse(url).netloc for url in config.start_urls
        ]

        # Capture selectors in closure for parse method
        _selectors = dict(selectors)
        _follow_links = config.follow_links

        def parse(self, response):
            """Extract data using configured selectors"""
            data = {}
            for field_name, selector in _selectors.items():
                data[field_name] = response.css(selector).getall()

            yield {
                'url': response.url,
                'data': data,
                'title': response.css('title::text').get()
            }

            if _follow_links:
                for href in response.css('a::attr(href)').getall():
                    yield response.follow(href, self.parse)

        # Create spider class dynamically using type() - no exec() needed
        spider_class = type('DynamicSpider', (scrapy.Spider,), {
            'name': 'dynamic_spider',
            'allowed_domains': domains,
            'start_urls': list(config.start_urls),
            'custom_settings': {
                'DEPTH_LIMIT': config.max_depth,
                'CLOSESPIDER_PAGECOUNT': config.max_pages,
                'DOWNLOAD_DELAY': config.delay_seconds,
            },
            'parse': parse,
        })

        return spider_class

    def _generate_spider_file(self, config: CrawlConfig,
                              selectors: Dict[str, str]) -> str:
        """
        Generate Scrapy spider code as string for file-based execution.

        Used only for subprocess execution where code is written to file
        and executed by scrapy CLI (not exec'd in Python).
        """
        domains = config.allowed_domains or [
            urlparse(url).netloc for url in config.start_urls
        ]

        selector_lines = []
        for field_name, selector in selectors.items():
            # Escape quotes in selector to prevent injection
            safe_field = field_name.replace("'", "\\'")
            safe_selector = selector.replace("'", "\\'")
            selector_lines.append(f"        data['{safe_field}'] = response.css('{safe_selector}').getall()")

        selector_code = '\n'.join(selector_lines)

        return f'''import scrapy

class DynamicSpider(scrapy.Spider):
    name = 'dynamic_spider'
    allowed_domains = {domains!r}
    start_urls = {list(config.start_urls)!r}
    custom_settings = {{
        'DEPTH_LIMIT': {config.max_depth},
        'CLOSESPIDER_PAGECOUNT': {config.max_pages},
        'DOWNLOAD_DELAY': {config.delay_seconds},
    }}

    def parse(self, response):
        data = {{}}
{selector_code}

        yield {{
            'url': response.url,
            'data': data,
            'title': response.css('title::text').get()
        }}

        if {config.follow_links!r}:
            for href in response.css('a::attr(href)').getall():
                yield response.follow(href, self.parse)
'''

    def run_spider(self, config: CrawlConfig,
                   selectors: Dict[str, str],
                   output_format: OutputFormat = OutputFormat.JSON) -> ScrapingResult:
        """
        Run Scrapy spider with configuration.

        Args:
            config: Crawl configuration
            selectors: CSS selectors for data extraction
            output_format: Output format

        Returns:
            ScrapingResult with extracted data
        """
        if not HAS_SCRAPY:
            # Fallback to subprocess execution
            return self._run_via_subprocess(config, selectors, output_format)

        output_file = self.project_dir / f"output.{output_format.value}"
        items = []
        errors = []
        start_time = datetime.now()

        try:
            process = CrawlerProcess(settings={
                **self.settings,
                'FEEDS': {
                    str(output_file): {'format': output_format.value}
                }
            })

            # Create dynamic spider class safely (no exec)
            SpiderClass = self._create_spider_class(config, selectors)

            # Crawl using the dynamically created class
            process.crawl(SpiderClass)
            process.start()

            # Read results
            if output_file.exists():
                with open(output_file) as f:
                    if output_format == OutputFormat.JSON:
                        results = json.load(f)
                    else:
                        results = f.read()

                for item in results:
                    items.append(ScrapedItem(
                        url=item.get('url', ''),
                        data=item.get('data', {}),
                        page_title=item.get('title')
                    ))

        except Exception as e:
            errors.append(str(e))

        duration = (datetime.now() - start_time).total_seconds()

        return ScrapingResult(
            success=len(errors) == 0,
            items=items,
            errors=errors,
            pages_crawled=len(items),
            duration_seconds=duration
        )

    def _run_via_subprocess(self, config: CrawlConfig,
                           selectors: Dict[str, str],
                           output_format: OutputFormat) -> ScrapingResult:
        """Run Scrapy via subprocess if not installed as library"""
        # Generate spider file (written to disk, not exec'd in Python)
        spider_file = self.project_dir / "spider.py"
        spider_code = self._generate_spider_file(config, selectors)

        with open(spider_file, 'w') as f:
            f.write(spider_code)

        output_file = self.project_dir / f"output.{output_format.value}"

        cmd = [
            "scrapy", "runspider", str(spider_file),
            "-o", str(output_file),
            "-t", output_format.value
        ]

        start_time = datetime.now()
        result = subprocess.run(cmd, capture_output=True, text=True)
        duration = (datetime.now() - start_time).total_seconds()

        items = []
        errors = []

        if result.returncode != 0:
            errors.append(result.stderr)
        elif output_file.exists():
            with open(output_file) as f:
                results = json.load(f)
            for item in results:
                items.append(ScrapedItem(
                    url=item.get('url', ''),
                    data=item.get('data', {}),
                    page_title=item.get('title')
                ))

        return ScrapingResult(
            success=len(errors) == 0,
            items=items,
            errors=errors,
            pages_crawled=len(items),
            duration_seconds=duration
        )

    def create_project(self, name: str) -> Path:
        """Create a new Scrapy project"""
        project_path = self.project_dir / name
        subprocess.run(
            ["scrapy", "startproject", name],
            cwd=self.project_dir,
            capture_output=True
        )
        return project_path


# =============================================================================
# PUPPETEER INTEGRATION (Node.js)
# =============================================================================

class PuppeteerScraper:
    """
    Puppeteer headless Chrome automation.

    Features:
    - JavaScript rendering
    - Screenshot capture
    - PDF generation
    - Network interception
    - Cookie management
    """

    def __init__(self, headless: bool = True):
        """
        Initialize Puppeteer scraper.

        Args:
            headless: Run in headless mode
        """
        self.headless = headless
        self.temp_dir = Path(tempfile.mkdtemp())

    def _generate_script(self, url: str, actions: List[Dict[str, Any]]) -> str:
        """Generate Puppeteer script"""
        action_code = self._generate_action_code(actions)

        return f'''
const puppeteer = require('puppeteer');

(async () => {{
    const browser = await puppeteer.launch({{
        headless: {'true' if self.headless else 'false'}
    }});
    const page = await browser.newPage();

    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    await page.goto('{url}', {{ waitUntil: 'networkidle2' }});

    const results = {{}};

    {action_code}

    console.log(JSON.stringify(results));
    await browser.close();
}})();
'''

    def _generate_action_code(self, actions: List[Dict[str, Any]]) -> str:
        """Generate action code for Puppeteer script"""
        lines = []
        for i, action in enumerate(actions):
            action_type = action.get('type')

            if action_type == 'extract':
                selector = action.get('selector')
                name = action.get('name', f'field_{i}')
                lines.append(f'''
    results['{name}'] = await page.$$eval('{selector}', els => els.map(el => el.textContent.trim()));
''')

            elif action_type == 'click':
                selector = action.get('selector')
                lines.append(f"    await page.click('{selector}');")

            elif action_type == 'type':
                selector = action.get('selector')
                text = action.get('text', '')
                lines.append(f"    await page.type('{selector}', '{text}');")

            elif action_type == 'wait':
                selector = action.get('selector')
                lines.append(f"    await page.waitForSelector('{selector}');")

            elif action_type == 'screenshot':
                path = action.get('path', 'screenshot.png')
                lines.append(f"    await page.screenshot({{ path: '{path}', fullPage: true }});")

            elif action_type == 'pdf':
                path = action.get('path', 'page.pdf')
                lines.append(f"    await page.pdf({{ path: '{path}', format: 'A4' }});")

            elif action_type == 'scroll':
                lines.append("    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));")

        return '\n'.join(lines)

    def scrape(self, url: str, selectors: Dict[str, str]) -> ScrapedItem:
        """
        Scrape URL with JavaScript rendering.

        Args:
            url: URL to scrape
            selectors: CSS selectors for extraction

        Returns:
            ScrapedItem with extracted data
        """
        actions = [
            {'type': 'extract', 'selector': selector, 'name': name}
            for name, selector in selectors.items()
        ]

        script = self._generate_script(url, actions)
        script_file = self.temp_dir / "scrape.js"

        with open(script_file, 'w') as f:
            f.write(script)

        result = subprocess.run(
            ["node", str(script_file)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f"Puppeteer error: {result.stderr}")

        data = json.loads(result.stdout)

        return ScrapedItem(
            url=url,
            data=data,
            selector_used=str(selectors)
        )

    def screenshot(self, url: str, output_path: str,
                   full_page: bool = True) -> str:
        """Take screenshot of page"""
        actions = [
            {'type': 'screenshot', 'path': output_path}
        ]

        script = self._generate_script(url, actions)
        script_file = self.temp_dir / "screenshot.js"

        with open(script_file, 'w') as f:
            f.write(script)

        subprocess.run(["node", str(script_file)], capture_output=True)
        return output_path

    def pdf(self, url: str, output_path: str) -> str:
        """Generate PDF of page"""
        actions = [
            {'type': 'pdf', 'path': output_path}
        ]

        script = self._generate_script(url, actions)
        script_file = self.temp_dir / "pdf.js"

        with open(script_file, 'w') as f:
            f.write(script)

        subprocess.run(["node", str(script_file)], capture_output=True)
        return output_path

    def execute_script(self, url: str,
                       actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute custom Puppeteer actions"""
        script = self._generate_script(url, actions)
        script_file = self.temp_dir / "custom.js"

        with open(script_file, 'w') as f:
            f.write(script)

        result = subprocess.run(
            ["node", str(script_file)],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw_output": result.stdout}


# =============================================================================
# PLAYWRIGHT SCRAPER
# =============================================================================

class PlaywrightScraper:
    """
    Playwright browser automation for scraping.

    Features:
    - Multi-browser support (Chromium, Firefox, WebKit)
    - Auto-wait functionality
    - Network interception
    - Mobile emulation
    - Trace recording
    """

    def __init__(self, browser: str = "chromium", headless: bool = True):
        """
        Initialize Playwright scraper.

        Args:
            browser: Browser to use (chromium, firefox, webkit)
            headless: Run in headless mode
        """
        if not HAS_PLAYWRIGHT:
            raise ImportError("Playwright not installed. Run: pip install playwright && playwright install")

        self.browser_type = browser
        self.headless = headless

    async def scrape(self, url: str, selectors: Dict[str, str]) -> ScrapedItem:
        """
        Scrape URL with Playwright.

        Args:
            url: URL to scrape
            selectors: CSS selectors for extraction

        Returns:
            ScrapedItem with extracted data
        """
        async with async_playwright() as p:
            browser_launcher = getattr(p, self.browser_type)
            browser = await browser_launcher.launch(headless=self.headless)
            page = await browser.new_page()

            await page.goto(url, wait_until="networkidle")

            data = {}
            for name, selector in selectors.items():
                elements = await page.query_selector_all(selector)
                texts = [await el.text_content() for el in elements]
                data[name] = [t.strip() for t in texts if t]

            title = await page.title()

            await browser.close()

            return ScrapedItem(
                url=url,
                data=data,
                page_title=title,
                selector_used=str(selectors)
            )

    async def scrape_with_interaction(self, url: str,
                                      interactions: List[Dict[str, Any]],
                                      selectors: Dict[str, str]) -> ScrapedItem:
        """
        Scrape after performing interactions.

        Args:
            url: URL to scrape
            interactions: List of interactions (click, type, scroll, etc.)
            selectors: CSS selectors for extraction

        Returns:
            ScrapedItem with extracted data
        """
        async with async_playwright() as p:
            browser_launcher = getattr(p, self.browser_type)
            browser = await browser_launcher.launch(headless=self.headless)
            page = await browser.new_page()

            await page.goto(url, wait_until="networkidle")

            # Perform interactions
            for action in interactions:
                action_type = action.get('type')

                if action_type == 'click':
                    await page.click(action['selector'])
                elif action_type == 'type':
                    await page.fill(action['selector'], action['text'])
                elif action_type == 'wait':
                    await page.wait_for_selector(action['selector'])
                elif action_type == 'scroll':
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                elif action_type == 'delay':
                    await asyncio.sleep(action.get('seconds', 1))

            # Extract data
            data = {}
            for name, selector in selectors.items():
                elements = await page.query_selector_all(selector)
                texts = [await el.text_content() for el in elements]
                data[name] = [t.strip() for t in texts if t]

            title = await page.title()

            await browser.close()

            return ScrapedItem(
                url=url,
                data=data,
                page_title=title,
                selector_used=str(selectors)
            )

    async def screenshot(self, url: str, output_path: str,
                        full_page: bool = True) -> str:
        """Take screenshot of page"""
        async with async_playwright() as p:
            browser = await getattr(p, self.browser_type).launch(headless=self.headless)
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")
            await page.screenshot(path=output_path, full_page=full_page)
            await browser.close()

        return output_path

    async def pdf(self, url: str, output_path: str) -> str:
        """Generate PDF of page (Chromium only)"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")
            await page.pdf(path=output_path, format="A4")
            await browser.close()

        return output_path

    async def extract_links(self, url: str,
                           filter_pattern: Optional[str] = None) -> List[str]:
        """Extract all links from page"""
        async with async_playwright() as p:
            browser = await getattr(p, self.browser_type).launch(headless=self.headless)
            page = await browser.new_page()
            await page.goto(url, wait_until="networkidle")

            links = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href.startsWith('http'));
            }''')

            await browser.close()

            if filter_pattern:
                import re
                pattern = re.compile(filter_pattern)
                links = [l for l in links if pattern.search(l)]

            return list(set(links))


# =============================================================================
# REQUESTS-HTML INTEGRATION
# =============================================================================

class RequestsHTMLScraper:
    """
    Requests-HTML integration for JavaScript rendering.

    Features:
    - JavaScript rendering via Chromium
    - CSS selector support
    - XPath support
    - Async support
    """

    def __init__(self):
        """Initialize Requests-HTML scraper"""
        try:
            from requests_html import HTMLSession, AsyncHTMLSession
            self.HTMLSession = HTMLSession
            self.AsyncHTMLSession = AsyncHTMLSession
            self.has_requests_html = True
        except ImportError:
            self.has_requests_html = False

    def scrape(self, url: str, selectors: Dict[str, str],
               render_js: bool = False) -> ScrapedItem:
        """
        Scrape URL with optional JS rendering.

        Args:
            url: URL to scrape
            selectors: CSS selectors
            render_js: Whether to render JavaScript

        Returns:
            ScrapedItem with extracted data
        """
        if not self.has_requests_html:
            raise ImportError("requests-html not installed. Run: pip install requests-html")

        session = self.HTMLSession()
        response = session.get(url)

        if render_js:
            response.html.render(timeout=30)

        data = {}
        for name, selector in selectors.items():
            elements = response.html.find(selector)
            data[name] = [el.text for el in elements]

        return ScrapedItem(
            url=url,
            data=data,
            page_title=response.html.find('title', first=True).text if response.html.find('title') else None,
            selector_used=str(selectors)
        )

    async def scrape_async(self, urls: List[str],
                          selectors: Dict[str, str],
                          render_js: bool = False) -> List[ScrapedItem]:
        """Scrape multiple URLs asynchronously"""
        if not self.has_requests_html:
            raise ImportError("requests-html not installed")

        session = self.AsyncHTMLSession()
        items = []

        async def fetch_one(url):
            response = await session.get(url)
            if render_js:
                await response.html.arender(timeout=30)

            data = {}
            for name, selector in selectors.items():
                elements = response.html.find(selector)
                data[name] = [el.text for el in elements]

            return ScrapedItem(url=url, data=data)

        tasks = [fetch_one(url) for url in urls]
        items = await asyncio.gather(*tasks, return_exceptions=True)

        return [i for i in items if isinstance(i, ScrapedItem)]


# =============================================================================
# UNIFIED WEB SCRAPING TOOLKIT
# =============================================================================

class WebScrapingToolkit:
    """
    Unified interface for all web scraping tools.

    Combines:
    - BeautifulSoup (fast HTML parsing)
    - Scrapy (industrial crawling)
    - Puppeteer (JS rendering via Node.js)
    - Playwright (multi-browser automation)
    - Requests-HTML (simple JS rendering)
    """

    def __init__(self):
        """Initialize all available scrapers"""
        self.beautifulsoup = None
        self.scrapy = None
        self.puppeteer = None
        self.playwright = None
        self.requests_html = None

        # Initialize available scrapers
        try:
            self.beautifulsoup = BeautifulSoupScraper()
        except ImportError:
            pass

        try:
            self.scrapy = ScrapyRunner()
        except Exception:
            pass

        try:
            self.puppeteer = PuppeteerScraper()
        except Exception:
            pass

        try:
            self.playwright = PlaywrightScraper()
        except ImportError:
            pass

        try:
            self.requests_html = RequestsHTMLScraper()
        except Exception:
            pass

    def quick_scrape(self, url: str, selectors: Dict[str, str]) -> ScrapedItem:
        """
        Quick scrape using BeautifulSoup (no JS).
        Best for: Static pages, speed
        """
        if self.beautifulsoup:
            return self.beautifulsoup.extract_structured(url, selectors)
        raise RuntimeError("BeautifulSoup not available")

    async def js_scrape(self, url: str, selectors: Dict[str, str]) -> ScrapedItem:
        """
        Scrape with JavaScript rendering using Playwright.
        Best for: Dynamic pages, SPAs
        """
        if self.playwright:
            return await self.playwright.scrape(url, selectors)
        raise RuntimeError("Playwright not available")

    def node_scrape(self, url: str, selectors: Dict[str, str]) -> ScrapedItem:
        """
        Scrape using Puppeteer (Node.js).
        Best for: Complex interactions, screenshots
        """
        if self.puppeteer:
            return self.puppeteer.scrape(url, selectors)
        raise RuntimeError("Puppeteer not available")

    def crawl(self, config: CrawlConfig,
              selectors: Dict[str, str]) -> ScrapingResult:
        """
        Full website crawl using Scrapy.
        Best for: Multi-page scraping, following links
        """
        if self.scrapy:
            return self.scrapy.run_spider(config, selectors)
        raise RuntimeError("Scrapy not available")

    def extract_links(self, url: str) -> List[str]:
        """Extract all links from a page"""
        if self.beautifulsoup:
            return self.beautifulsoup.extract_links(url)
        raise RuntimeError("BeautifulSoup not available")

    def extract_tables(self, url: str) -> List[List[List[str]]]:
        """Extract all tables from a page"""
        if self.beautifulsoup:
            return self.beautifulsoup.extract_tables(url)
        raise RuntimeError("BeautifulSoup not available")

    def screenshot(self, url: str, output_path: str) -> str:
        """Take screenshot of page"""
        if self.puppeteer:
            return self.puppeteer.screenshot(url, output_path)
        raise RuntimeError("Puppeteer not available")

    def get_available_tools(self) -> Dict[str, bool]:
        """Get availability status of all tools"""
        return {
            "beautifulsoup": self.beautifulsoup is not None,
            "scrapy": self.scrapy is not None,
            "puppeteer": self.puppeteer is not None,
            "playwright": self.playwright is not None,
            "requests_html": self.requests_html is not None,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def quick_scrape(url: str, selectors: Dict[str, str]) -> ScrapedItem:
    """Quick scrape without toolkit initialization"""
    scraper = BeautifulSoupScraper()
    return scraper.extract_structured(url, selectors)


def extract_text(url: str, selector: str) -> List[str]:
    """Extract text from elements"""
    scraper = BeautifulSoupScraper()
    return scraper.extract_text(url, selector)


def extract_links(url: str) -> List[str]:
    """Extract all links from page"""
    scraper = BeautifulSoupScraper()
    return scraper.extract_links(url)


def extract_tables(url: str) -> List[List[List[str]]]:
    """Extract all tables from page"""
    scraper = BeautifulSoupScraper()
    return scraper.extract_tables(url)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "OutputFormat",
    "SelectorType",

    # Data classes
    "ScrapedItem",
    "ScrapingResult",
    "CrawlConfig",

    # Scrapers
    "BeautifulSoupScraper",
    "ScrapyRunner",
    "PuppeteerScraper",
    "PlaywrightScraper",
    "RequestsHTMLScraper",

    # Unified toolkit
    "WebScrapingToolkit",

    # Convenience functions
    "quick_scrape",
    "extract_text",
    "extract_links",
    "extract_tables",
]
