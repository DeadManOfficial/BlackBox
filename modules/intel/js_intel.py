"""
JavaScript Intelligence Module

Extracts intelligence from JavaScript bundles including:
- API endpoints and routes
- Hardcoded secrets and tokens
- Configuration objects
- Authentication patterns
- Internal function names
- Hidden features
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import urllib.request


@dataclass
class JSFinding:
    """A finding from JS analysis"""
    category: str
    severity: str  # critical, high, medium, low, info
    title: str
    value: str
    line: Optional[int] = None
    context: Optional[str] = None


@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    path: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    auth_required: bool = False
    source_context: str = ""


@dataclass
class JSIntelResult:
    """Result of JS intelligence extraction"""
    url: str
    size: int
    hash: str
    findings: List[JSFinding] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    secrets: List[Dict] = field(default_factory=list)
    config_objects: List[Dict] = field(default_factory=list)
    technologies: Set[str] = field(default_factory=set)
    internal_functions: List[str] = field(default_factory=list)
    hidden_routes: List[str] = field(default_factory=list)
    feature_flags: List[str] = field(default_factory=list)


class JSIntelligence:
    """
    Extracts intelligence from JavaScript code.

    Analyzes both minified and source JavaScript to find:
    - Hardcoded credentials and API keys
    - API endpoint definitions
    - Configuration objects
    - Hidden admin routes
    - Feature flags
    - Internal function names
    - Technology stack
    """

    SECRET_PATTERNS = [
        # API Keys
        (r'["\']?(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'API_KEY', 'critical'),
        (r'["\']?(?:secret|client[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'SECRET', 'critical'),

        # Cloud Provider Keys
        (r'AKIA[A-Z0-9]{16}', 'AWS_ACCESS_KEY', 'critical'),
        (r'(?:aws[_-]?secret|secret[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']', 'AWS_SECRET', 'critical'),
        (r'AIza[a-zA-Z0-9_-]{35}', 'GOOGLE_API_KEY', 'critical'),
        (r'["\']?(?:firebase|gcp)[_-]?(?:key|token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', 'FIREBASE_KEY', 'critical'),

        # OAuth/Auth Tokens
        (r'ghp_[a-zA-Z0-9]{36}', 'GITHUB_PAT', 'critical'),
        (r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}', 'GITHUB_FINE_PAT', 'critical'),
        (r'sk-[a-zA-Z0-9]{48}', 'OPENAI_KEY', 'critical'),
        (r'sk-ant-[a-zA-Z0-9-]{90,}', 'ANTHROPIC_KEY', 'critical'),
        (r'xox[baprs]-[0-9a-zA-Z-]{10,}', 'SLACK_TOKEN', 'critical'),
        (r'discord[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{50,})["\']', 'DISCORD_TOKEN', 'critical'),

        # Private Keys
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', 'PRIVATE_KEY', 'critical'),
        (r'-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----', 'EC_PRIVATE_KEY', 'critical'),

        # Passwords
        (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'HARDCODED_PASSWORD', 'high'),

        # Database Connection Strings
        (r'mongodb(?:\+srv)?://[^"\'\s]+', 'MONGODB_URI', 'critical'),
        (r'postgres(?:ql)?://[^"\'\s]+', 'POSTGRES_URI', 'critical'),
        (r'mysql://[^"\'\s]+', 'MYSQL_URI', 'critical'),
        (r'redis://[^"\'\s]+', 'REDIS_URI', 'high'),

        # JWT Secrets
        (r'["\']?(?:jwt[_-]?secret|jwt[_-]?key)["\']?\s*[:=]\s*["\']([^"\']{16,})["\']', 'JWT_SECRET', 'critical'),
    ]

    ENDPOINT_PATTERNS = [
        # REST API paths
        (r'["\']/(api|v[0-9]+)/([a-zA-Z0-9/_:-]+)["\']', 'REST'),
        (r'(?:fetch|axios)\s*\(\s*[`"\']([^`"\']+)[`"\']', 'FETCH'),
        (r'\.(get|post|put|patch|delete)\s*\(\s*[`"\']([^`"\']+)[`"\']', 'HTTP_METHOD'),
        (r'(?:baseURL|baseUrl|base_url)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'BASE_URL'),
        (r'(?:endpoint|url|path)["\']?\s*[:=]\s*["\']/(api[^"\']+)["\']', 'ENDPOINT'),
    ]

    CONFIG_PATTERNS = [
        r'(?:config|settings|options)\s*[:=]\s*\{[^}]{20,}\}',
        r'(?:window\.__[A-Z_]+__)\s*=\s*[^;]+',
        r'process\.env\.[A-Z_]+',
        r'(?:const|let|var)\s+(?:CONFIG|SETTINGS|OPTIONS)\s*=\s*\{[^}]+\}',
    ]

    TECH_SIGNATURES = {
        'react': [r'React\.', r'useState', r'useEffect', r'createRoot', r'jsx'],
        'vue': [r'Vue\.', r'createApp', r'ref\(', r'computed\(', r'\.vue'],
        'angular': [r'@Component', r'@Injectable', r'NgModule', r'angular\.module'],
        'svelte': [r'\$:', r'<script\s+lang="ts">', r'on:click'],
        'jquery': [r'\$\(', r'jQuery', r'\.ajax\(', r'\.ready\('],
        'lodash': [r'_\.', r'lodash'],
        'axios': [r'axios\.', r'axios\('],
        'graphql': [r'gql`', r'useQuery', r'useMutation', r'ApolloClient'],
        'websocket': [r'WebSocket\(', r'\.onmessage', r'\.send\('],
        'socket.io': [r'io\(', r'socket\.emit', r'socket\.on'],
        'redux': [r'createStore', r'useSelector', r'useDispatch', r'combineReducers'],
        'mobx': [r'@observable', r'makeAutoObservable', r'observer\('],
        'tailwind': [r'className[=:].*?(?:flex|grid|bg-|text-|p-|m-)'],
        'bootstrap': [r'class[=:].*?(?:btn|container|row|col-)'],
        'typescript': [r':\s*(?:string|number|boolean|void|any)\b', r'interface\s+\w+'],
        'webpack': [r'__webpack_require__', r'webpackChunk'],
        'vite': [r'import\.meta\.hot', r'@vite'],
    }

    ADMIN_ROUTE_PATTERNS = [
        r'["\']/(admin|dashboard|panel|manage|internal|backstage)[/a-zA-Z0-9_-]*["\']',
        r'["\']/(debug|dev|staging|test|beta)[/a-zA-Z0-9_-]*["\']',
        r'["\']/(system|maintenance|health|status)[/a-zA-Z0-9_-]*["\']',
        r'["\']/__[a-zA-Z]+__["\']',  # Dunder routes
    ]

    FEATURE_FLAG_PATTERNS = [
        r'(?:feature[_-]?flag|flag|toggle|feature)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']',
        r'(?:isEnabled|isActive|isOn)\s*\(\s*["\']([a-zA-Z0-9_-]+)["\']',
        r'(?:FEATURE|FLAG|TOGGLE)_[A-Z_]+',
    ]

    def __init__(self):
        self.results: List[JSIntelResult] = []

    def analyze_url(self, url: str) -> JSIntelResult:
        """Analyze JavaScript from URL"""
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            return JSIntelResult(url=url, size=0, hash="",
                               findings=[JSFinding('error', 'high', 'Fetch Error', str(e))])

        return self.analyze_content(content, url)

    def analyze_file(self, filepath: str) -> JSIntelResult:
        """Analyze JavaScript from file"""
        path = Path(filepath)
        content = path.read_text(errors='ignore')
        return self.analyze_content(content, filepath)

    def analyze_content(self, content: str, source: str = "") -> JSIntelResult:
        """Analyze JavaScript content"""
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        result = JSIntelResult(
            url=source,
            size=len(content),
            hash=content_hash
        )

        # Find secrets
        self._find_secrets(content, result)

        # Find endpoints
        self._find_endpoints(content, result)

        # Find config objects
        self._find_configs(content, result)

        # Detect technologies
        self._detect_technologies(content, result)

        # Find hidden routes
        self._find_hidden_routes(content, result)

        # Find feature flags
        self._find_feature_flags(content, result)

        # Find internal function names
        self._find_internal_functions(content, result)

        self.results.append(result)
        return result

    def _find_secrets(self, content: str, result: JSIntelResult):
        """Find hardcoded secrets"""
        for pattern, secret_type, severity in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line = content[:match.start()].count('\n') + 1
                value = match.group(1) if match.lastindex else match.group()

                # Skip obvious false positives
                if value.lower() in ['your-api-key', 'api-key-here', 'xxx', 'placeholder']:
                    continue

                result.secrets.append({
                    'type': secret_type,
                    'value': value[:50] + '...' if len(value) > 50 else value,
                    'line': line,
                    'severity': severity
                })

                result.findings.append(JSFinding(
                    category='secret',
                    severity=severity,
                    title=f'Hardcoded {secret_type}',
                    value=value[:30] + '...',
                    line=line
                ))

    def _find_endpoints(self, content: str, result: JSIntelResult):
        """Find API endpoints"""
        seen = set()

        for pattern, endpoint_type in self.ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                groups = match.groups()
                path = groups[-1] if groups else match.group()

                if path in seen or len(path) < 3:
                    continue
                seen.add(path)

                # Determine HTTP method
                method = "GET"
                if endpoint_type == "HTTP_METHOD":
                    method = groups[0].upper() if groups else "GET"
                elif 'post' in match.group().lower():
                    method = "POST"

                # Check if auth might be required
                context_start = max(0, match.start() - 200)
                context = content[context_start:match.start() + len(match.group())]
                auth_required = bool(re.search(r'auth|token|bearer|credential', context, re.I))

                result.endpoints.append(APIEndpoint(
                    path=path,
                    method=method,
                    auth_required=auth_required,
                    source_context=context[-100:]
                ))

    def _find_configs(self, content: str, result: JSIntelResult):
        """Find configuration objects"""
        for pattern in self.CONFIG_PATTERNS:
            for match in re.finditer(pattern, content):
                try:
                    # Try to extract just the object
                    obj_match = re.search(r'\{[^{}]*\}', match.group())
                    if obj_match:
                        result.config_objects.append({
                            'raw': obj_match.group()[:500],
                            'line': content[:match.start()].count('\n') + 1
                        })
                except:
                    pass

        # Find window globals
        for match in re.finditer(r'window\.(__[A-Z_]+__)\s*=\s*([^;]+)', content):
            result.config_objects.append({
                'name': match.group(1),
                'value': match.group(2)[:200],
                'line': content[:match.start()].count('\n') + 1
            })

    def _detect_technologies(self, content: str, result: JSIntelResult):
        """Detect technologies used"""
        for tech, patterns in self.TECH_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    result.technologies.add(tech)
                    break

    def _find_hidden_routes(self, content: str, result: JSIntelResult):
        """Find hidden/admin routes"""
        seen = set()
        for pattern in self.ADMIN_ROUTE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                route = match.group().strip('"\'')
                if route not in seen:
                    seen.add(route)
                    result.hidden_routes.append(route)
                    result.findings.append(JSFinding(
                        category='hidden_route',
                        severity='medium',
                        title='Hidden/Admin Route',
                        value=route,
                        line=content[:match.start()].count('\n') + 1
                    ))

    def _find_feature_flags(self, content: str, result: JSIntelResult):
        """Find feature flags"""
        seen = set()
        for pattern in self.FEATURE_FLAG_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                flag = match.group(1) if match.lastindex else match.group()
                if flag not in seen and len(flag) > 3:
                    seen.add(flag)
                    result.feature_flags.append(flag)

    def _find_internal_functions(self, content: str, result: JSIntelResult):
        """Find internal function names"""
        # Look for function definitions with interesting names
        patterns = [
            r'function\s+(_[a-zA-Z][a-zA-Z0-9_]+)\s*\(',
            r'(?:const|let|var)\s+(_[a-zA-Z][a-zA-Z0-9_]+)\s*=\s*(?:function|\()',
            r'([a-zA-Z]+(?:Admin|Internal|Private|Debug|Secret)[a-zA-Z]*)\s*[:=]\s*(?:function|\()',
        ]

        seen = set()
        for pattern in patterns:
            for match in re.finditer(pattern, content):
                name = match.group(1)
                if name not in seen and len(name) > 4:
                    seen.add(name)
                    result.internal_functions.append(name)

    def generate_report(self, result: JSIntelResult) -> str:
        """Generate markdown report"""
        report = f"""# JavaScript Intelligence Report

## Target
- **Source:** {result.url}
- **Size:** {result.size:,} bytes
- **Hash:** {result.hash}

## Technologies Detected
{chr(10).join(f'- {t}' for t in sorted(result.technologies)) or '- None detected'}

## Secrets Found ({len(result.secrets)})
"""
        for secret in result.secrets:
            report += f"\n### [{secret['severity'].upper()}] {secret['type']}\n"
            report += f"- Line: {secret['line']}\n"
            report += f"- Value: `{secret['value']}`\n"

        report += f"\n## API Endpoints ({len(result.endpoints)})\n"
        for ep in result.endpoints[:30]:
            auth = '🔒' if ep.auth_required else '🔓'
            report += f"- {auth} `{ep.method}` `{ep.path}`\n"
        if len(result.endpoints) > 30:
            report += f"\n... and {len(result.endpoints) - 30} more\n"

        report += f"\n## Hidden/Admin Routes ({len(result.hidden_routes)})\n"
        for route in result.hidden_routes:
            report += f"- `{route}`\n"

        report += f"\n## Feature Flags ({len(result.feature_flags)})\n"
        for flag in result.feature_flags[:20]:
            report += f"- `{flag}`\n"

        report += f"\n## Configuration Objects ({len(result.config_objects)})\n"
        for cfg in result.config_objects[:5]:
            report += f"\n```javascript\n{cfg.get('raw', cfg.get('value', ''))[:300]}\n```\n"

        return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python js_intel.py <url_or_file>")
        sys.exit(1)

    intel = JSIntelligence()

    target = sys.argv[1]
    if target.startswith('http'):
        result = intel.analyze_url(target)
    else:
        result = intel.analyze_file(target)

    print(intel.generate_report(result))
