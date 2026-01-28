#!/usr/bin/env python3
"""
Token Optimization Intelligence Scraper
========================================
Scrapes clearnet and dark web for token optimization techniques

Research Focus:
- LLM optimization methods
- Prompt engineering efficiency
- Context compression techniques
- Token reduction strategies
- API cost optimization

Standards: FREE tools only, verifiable sources, comprehensive data
"""

import sys
import io
import requests
from pathlib import Path
from datetime import datetime
import hashlib
import json
import time

# Fix Windows encoding
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

class TokenOptimizationScraper:
    """Scraper for token optimization intelligence"""

    def __init__(self, output_dir='D:/DeadMan_AI_Research/Research/Token_Optimization'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })

        # Research targets for Phase 1 (Clearnet)
        self.research_targets = {
            'GitHub - LLM Optimization': [
                'https://github.com/topics/llm-optimization',
                'https://github.com/topics/prompt-engineering',
                'https://github.com/topics/token-reduction',
                'https://github.com/topics/context-compression',
            ],
            'GitHub - API Optimization': [
                'https://github.com/search?q=claude+api+optimization&type=repositories',
                'https://github.com/search?q=anthropic+efficient&type=repositories',
                'https://github.com/search?q=llm+cost+optimization&type=repositories',
                'https://github.com/search?q=prompt+compression&type=repositories',
            ],
            'Reddit - AI Communities': [
                'https://www.reddit.com/r/LocalLLaMA/search/?q=token+optimization',
                'https://www.reddit.com/r/PromptEngineering/search/?q=efficient+prompting',
                'https://www.reddit.com/r/MachineLearning/search/?q=llm+efficiency',
                'https://www.reddit.com/r/OpenAI/search/?q=reduce+tokens',
            ],
            'Academic Research': [
                'https://arxiv.org/search/?query=context+compression&searchtype=all',
                'https://arxiv.org/search/?query=efficient+transformers&searchtype=all',
                'https://arxiv.org/search/?query=prompt+optimization&searchtype=all',
            ],
            'Stack Overflow': [
                'https://stackoverflow.com/questions/tagged/langchain',
                'https://stackoverflow.com/search?q=anthropic+api+token',
                'https://stackoverflow.com/search?q=openai+reduce+tokens',
            ],
            'Developer Documentation': [
                'https://docs.anthropic.com/en/docs/overview',
                'https://platform.openai.com/docs/guides/prompt-engineering',
                'https://python.langchain.com/docs/get_started/introduction',
            ],
            'AI Research Blogs': [
                'https://www.anthropic.com/research',
                'https://openai.com/blog',
                'https://huggingface.co/blog',
            ],
            'Hacker News': [
                'https://news.ycombinator.com/item?id=38861969',
                'https://hn.algolia.com/?q=llm+optimization',
                'https://hn.algolia.com/?q=prompt+engineering',
            ],
        }

        self.stats = {
            'total_targets': 0,
            'successful': 0,
            'failed': 0,
            'total_bytes': 0,
            'start_time': None,
            'end_time': None
        }

    def scrape_url(self, url, category):
        """Scrape single URL and save results"""
        try:
            print(f"[SCRAPING] {url}")

            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            content = response.text
            size = len(content.encode('utf-8'))

            # Generate filename from URL hash
            url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
            filename = f"{category.replace(' ', '_')}_{url_hash}.html"

            # Save HTML content
            filepath = self.output_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            # Save metadata
            metadata = {
                'url': url,
                'category': category,
                'timestamp': datetime.now().isoformat(),
                'size_bytes': size,
                'status_code': response.status_code,
                'content_type': response.headers.get('content-type', 'unknown'),
                'filename': filename
            }

            metadata_file = self.output_dir / f"{filename}.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)

            self.stats['successful'] += 1
            self.stats['total_bytes'] += size

            print(f"[OK] Saved {size:,} bytes to {filename}")
            return True

        except Exception as e:
            print(f"[FAIL] {url}: {str(e)}")
            self.stats['failed'] += 1
            return False

    def run_phase1(self):
        """Execute Phase 1: Clearnet intelligence gathering"""
        print("=" * 70)
        print("TOKEN OPTIMIZATION INTELLIGENCE GATHERING")
        print("Phase 1: Clearnet Research")
        print("=" * 70)
        print()

        self.stats['start_time'] = datetime.now()

        for category, urls in self.research_targets.items():
            print(f"\n[CATEGORY] {category}")
            print("-" * 70)

            for url in urls:
                self.stats['total_targets'] += 1
                self.scrape_url(url, category)

                # Rate limiting: be respectful
                time.sleep(2)

        self.stats['end_time'] = datetime.now()
        self.print_stats()
        self.save_report()

    def print_stats(self):
        """Print collection statistics"""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()

        print("\n" + "=" * 70)
        print("COLLECTION STATISTICS")
        print("=" * 70)
        print(f"Total Targets:    {self.stats['total_targets']}")
        print(f"Successful:       {self.stats['successful']}")
        print(f"Failed:           {self.stats['failed']}")
        print(f"Success Rate:     {self.stats['successful']/self.stats['total_targets']*100:.1f}%")
        print(f"Total Data:       {self.stats['total_bytes']:,} bytes ({self.stats['total_bytes']/1024/1024:.2f} MB)")
        print(f"Duration:         {duration:.1f} seconds")
        print(f"Output Dir:       {self.output_dir}")
        print("=" * 70)

    def save_report(self):
        """Save collection report"""
        report = {
            'phase': 'Phase 1 - Clearnet',
            'objective': 'Token optimization intelligence gathering',
            'timestamp': datetime.now().isoformat(),
            'stats': self.stats,
            'categories': list(self.research_targets.keys()),
            'total_urls': sum(len(urls) for urls in self.research_targets.values())
        }

        report_file = self.output_dir / 'COLLECTION_REPORT.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n[REPORT] Saved to {report_file}")


def main():
    """Main execution"""
    import argparse

    parser = argparse.ArgumentParser(description='Token Optimization Intelligence Scraper')
    parser.add_argument('--phase', type=int, default=1, choices=[1, 2],
                       help='Phase 1: Clearnet, Phase 2: Dark Web (requires TOR)')
    parser.add_argument('--tor', action='store_true',
                       help='Use TOR proxy (Phase 2)')

    args = parser.parse_args()

    scraper = TokenOptimizationScraper()

    if args.phase == 1:
        print("[INFO] Starting Phase 1: Clearnet Research")
        scraper.run_phase1()
        print("\n[NEXT] Install TOR and run with --phase 2 --tor for dark web research")

    elif args.phase == 2:
        if not args.tor:
            print("[ERROR] Phase 2 requires --tor flag and TOR running on port 9050")
            print("[INFO] Start TOR: python tor_manager.py start")
            sys.exit(1)

        print("[INFO] Phase 2: Dark Web research not yet implemented")
        print("[TODO] Implement dark web target discovery and scraping")


if __name__ == '__main__':
    main()
