"""
Source Map Extractor Module

Extracts original source code from exposed JavaScript source maps.
Critical for intelligence gathering when .map files are accessible.
"""

import json
import os
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import asyncio
import aiohttp


@dataclass
class SourceFile:
    """Extracted source file from sourcemap"""
    path: str
    content: str
    size: int
    hash: str
    is_vendor: bool = False
    secrets_found: List[str] = field(default_factory=list)
    endpoints_found: List[str] = field(default_factory=list)


@dataclass
class SourceMapResult:
    """Result of sourcemap extraction"""
    url: str
    version: int
    sources_count: int
    total_size: int
    files: List[SourceFile]
    vendor_count: int
    app_count: int
    secrets: List[Dict]
    endpoints: List[str]
    technologies: List[str]


class SourceMapExtractor:
    """
    Extracts and analyzes JavaScript source maps.

    Features:
    - Downloads and parses .map files
    - Extracts original source code
    - Identifies vendor vs application code
    - Scans for secrets and sensitive patterns
    - Discovers API endpoints
    - Identifies technologies used
    """

    SECRET_PATTERNS = [
        (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'API_KEY'),
        (r'["\']?secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_-]{20,}["\']', 'SECRET'),
        (r'["\']?token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_.-]{20,}["\']', 'TOKEN'),
        (r'["\']?password["\']?\s*[:=]\s*["\'][^"\']{8,}["\']', 'PASSWORD'),
        (r'["\']?aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']AKIA[A-Z0-9]{16}["\']', 'AWS_KEY'),
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'PRIVATE_KEY'),
        (r'ghp_[a-zA-Z0-9]{36}', 'GITHUB_TOKEN'),
        (r'sk-[a-zA-Z0-9]{48}', 'OPENAI_KEY'),
        (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'SLACK_TOKEN'),
    ]

    ENDPOINT_PATTERNS = [
        r'["\']/(api|v[0-9]+)/[a-zA-Z0-9/_-]+["\']',
        r'fetch\s*\(\s*["\'][^"\']+["\']',
        r'axios\.[a-z]+\s*\(\s*["\'][^"\']+["\']',
        r'\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']',
    ]

    VENDOR_INDICATORS = [
        'node_modules',
        '@types/',
        'lodash',
        'react',
        'vue',
        'angular',
        'jquery',
        'bootstrap',
        'moment',
        'axios',
    ]

    TECH_PATTERNS = {
        'react': r'React\.|useState|useEffect|jsx',
        'vue': r'Vue\.|createApp|ref\(|computed\(',
        'angular': r'@Component|@Injectable|NgModule',
        'lit': r'LitElement|@customElement|html`',
        'svelte': r'\$:|on:click|{#if',
        'typescript': r':\s*(string|number|boolean|void)\b',
        'graphql': r'gql`|query\s+\w+|mutation\s+\w+',
        'websocket': r'WebSocket\(|\.send\(|\.onmessage',
        'redux': r'createStore|useSelector|useDispatch',
        'tailwind': r'className.*(?:flex|grid|bg-|text-|p-|m-)',
    }

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir) if output_dir else None
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=60),
            headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'}
        )
        return self

    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()

    async def extract_from_url(self, url: str) -> Optional[SourceMapResult]:
        """Extract source code from a sourcemap URL"""
        if not self.session:
            async with self:
                return await self._extract(url)
        return await self._extract(url)

    async def _extract(self, url: str) -> Optional[SourceMapResult]:
        """Internal extraction logic"""
        try:
            async with self.session.get(url) as resp:
                if resp.status != 200:
                    return None
                content = await resp.text()
                data = json.loads(content)
        except Exception as e:
            print(f"[-] Failed to fetch sourcemap: {e}")
            return None

        return self.parse_sourcemap(data, url)

    def parse_sourcemap(self, data: Dict, source_url: str = "") -> SourceMapResult:
        """Parse a sourcemap JSON object"""
        sources = data.get('sources', [])
        contents = data.get('sourcesContent', [])
        version = data.get('version', 3)

        files: List[SourceFile] = []
        all_secrets: List[Dict] = []
        all_endpoints: List[str] = []
        technologies: set = set()

        for i, source_path in enumerate(sources):
            content = contents[i] if i < len(contents) and contents[i] else ""
            if not content:
                continue

            is_vendor = any(ind in source_path.lower() for ind in self.VENDOR_INDICATORS)

            # Scan for secrets
            secrets = self._find_secrets(content, source_path)

            # Scan for endpoints
            endpoints = self._find_endpoints(content) if not is_vendor else []

            # Detect technologies
            if not is_vendor:
                for tech, pattern in self.TECH_PATTERNS.items():
                    if re.search(pattern, content):
                        technologies.add(tech)

            file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

            sf = SourceFile(
                path=source_path,
                content=content,
                size=len(content),
                hash=file_hash,
                is_vendor=is_vendor,
                secrets_found=[s['type'] for s in secrets],
                endpoints_found=endpoints
            )
            files.append(sf)
            all_secrets.extend(secrets)
            all_endpoints.extend(endpoints)

        # Save files if output directory specified
        if self.output_dir:
            self._save_files(files)

        vendor_count = sum(1 for f in files if f.is_vendor)

        return SourceMapResult(
            url=source_url,
            version=version,
            sources_count=len(files),
            total_size=sum(f.size for f in files),
            files=files,
            vendor_count=vendor_count,
            app_count=len(files) - vendor_count,
            secrets=all_secrets,
            endpoints=list(set(all_endpoints)),
            technologies=list(technologies)
        )

    def _find_secrets(self, content: str, filepath: str) -> List[Dict]:
        """Find secrets in source content"""
        secrets = []
        for pattern, secret_type in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                secrets.append({
                    'type': secret_type,
                    'file': filepath,
                    'line': line_num,
                    'match': match.group()[:100] + '...' if len(match.group()) > 100 else match.group()
                })
        return secrets

    def _find_endpoints(self, content: str) -> List[str]:
        """Find API endpoints in source content"""
        endpoints = []
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                # Clean up the match
                if isinstance(match, tuple):
                    match = match[0]
                cleaned = re.sub(r'^["\']|["\']$', '', match)
                if cleaned and len(cleaned) > 2:
                    endpoints.append(cleaned)
        return endpoints

    def _save_files(self, files: List[SourceFile]):
        """Save extracted files to output directory"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        for sf in files:
            if sf.is_vendor:
                continue

            # Create safe filename
            safe_name = sf.path.replace('../', '').replace('/', '_').replace('\\', '_')
            if safe_name.startswith('_'):
                safe_name = safe_name[1:]

            filepath = self.output_dir / safe_name
            filepath.write_text(sf.content)

    def generate_report(self, result: SourceMapResult) -> str:
        """Generate a markdown report of findings"""
        report = f"""# Source Map Analysis Report

## Overview
- **URL:** {result.url}
- **Version:** {result.version}
- **Total Files:** {result.sources_count}
- **Application Files:** {result.app_count}
- **Vendor Files:** {result.vendor_count}
- **Total Size:** {result.total_size:,} bytes

## Technologies Detected
{chr(10).join(f'- {tech}' for tech in result.technologies) or '- None detected'}

## Secrets Found ({len(result.secrets)})
"""
        if result.secrets:
            for secret in result.secrets:
                report += f"\n### {secret['type']}\n"
                report += f"- **File:** {secret['file']}\n"
                report += f"- **Line:** {secret['line']}\n"
                report += f"- **Match:** `{secret['match']}`\n"
        else:
            report += "\nNo hardcoded secrets detected.\n"

        report += f"\n## API Endpoints Found ({len(result.endpoints)})\n"
        if result.endpoints:
            for ep in sorted(set(result.endpoints))[:50]:
                report += f"- `{ep}`\n"
        else:
            report += "\nNo endpoints detected.\n"

        report += "\n## Application Files\n"
        for sf in sorted(result.files, key=lambda x: x.path):
            if not sf.is_vendor:
                report += f"- `{sf.path}` ({sf.size:,} bytes)\n"

        return report


# CLI interface
async def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sourcemap_extractor.py <url_or_file> [output_dir]")
        sys.exit(1)

    target = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./extracted_source"

    extractor = SourceMapExtractor(output_dir)

    if target.startswith('http'):
        async with extractor:
            result = await extractor.extract_from_url(target)
    else:
        with open(target) as f:
            data = json.load(f)
        result = extractor.parse_sourcemap(data, target)

    if result:
        print(extractor.generate_report(result))
    else:
        print("Failed to extract sourcemap")


if __name__ == "__main__":
    asyncio.run(main())
