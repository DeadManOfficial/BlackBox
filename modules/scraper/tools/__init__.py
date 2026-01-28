"""
DeadMan Security Tools - 2026 Frontier Security Suite

Comprehensive security assessment toolkit including:
- Nuclei vulnerability scanning
- JavaScript security analysis
- AI/LLM security testing
- LLM Red Team framework (40+ vulnerability types)
- Autonomous Pentest agent (MCTS attack planning)
- Stealth browser automation (Camoufox/Nodriver)
- TLS fingerprint client (curl_cffi)
- Browser context pooling
- CORS/IDOR/XXE/CRLF/RCE vulnerability scanners
- Advanced attacks (WAF bypass, race conditions, OAuth, payment)
- Deep pentesting (JWT, file upload, WebSocket, rate limit)

Author: DeadManOfficial
Version: 4.0.0
"""

# Core security tools
from .nuclei_scanner import NucleiScanner, ScanConfig, Severity as SeverityLevel, ScanResult
from .js_analyzer import JSSecurityAnalyzer, JSFinding, JSAnalysisReport
from .ai_security import AISecurityTester, VulnerabilityType, TestResult, SecurityReport
from .enhanced_pipeline import EnhancedSecurityPipeline, PipelineConfig, PipelineReport

# Aliases for compatibility
SecretFinding = JSFinding
EndpointFinding = JSFinding

# LLM Red Team
from .llm_redteam import (
    LLMRedTeamFramework,
    AttackStrategy,
    VulnerabilityClass,
    AttackResult,
    RedTeamReport,
    PayloadLibrary,
)

# Pentest Agent
from .pentest_agent import (
    AutonomousPentestAgent,
    PentestReport,
    AttackPathPlanner,
    MCTSNode,
    ToolRegistry,
    ReasoningModule,
    AttackPhase as PentestPhase,
)
PentestConfig = None  # Not implemented

# Stealth Browser
from .stealth_browser import (
    StealthBrowserFactory,
    StealthConfig,
    StealthSession,
    CamoufoxBrowser,
    NodriverBrowser,
    PlaywrightStealthBrowser,
    BrowserFingerprint
)

# TLS Client
from .tls_client import (
    TLSClient,
    TLSConfig,
    TLSResponse,
    BrowserProfile,
    ProxyWaterfall,
)
def create_stealth_client(*args, **kwargs):
    """Factory function for TLSClient"""
    return TLSClient(*args, **kwargs)

# Browser Pool
from .browser_pool import (
    BrowserPool,
    StealthConfig as BrowserStealthConfig,
    BrowserPoolConfig as PoolConfig,
)
BrowserContext = None  # Use BrowserContextWrapper instead

# Vulnerability Scanners (native implementations)
from .vuln_scanners import (
    CORSScanner,
    IDORScanner,
    XXEScanner,
    CRLFScanner,
    RCEScanner,
    UnifiedVulnScanner,
    VulnFinding,
    Severity as VulnSeverity
)

# Advanced Attacks
from .advanced_attacks import (
    WAFBypassEngine,
    RaceConditionScanner as RaceConditionTester,
    OAuthVulnerabilityScanner as OAuthAttacker,
    PaymentSecurityTester,
    HTTPSmugglingScanner as HTTPSmugglingDetector,
    OriginDiscoveryResult
)

# Deep Pentesting
from .deep_pentest import (
    JWTAnalyzer,
    SourceMapHunter,
    APIFuzzer,
    RateLimitBypass,
    FileUploadTester,
    DeepFinding
)
# Aliases
WebSocketTester = None  # Use advanced_attacks.WebSocketScanner
BusinessLogicTester = None  # Use DeepPentest class

# Advanced Recon
from .advanced_recon import (
    JSDeepAnalyzer,
    GraphQLTester as GraphQLSecurityTester,
    SubdomainEnumerator,
    AuthTester,
    CloudAssetDiscovery,
    ReconFinding
)

__all__ = [
    # Nuclei Scanner
    'NucleiScanner',
    'ScanConfig',
    'SeverityLevel',
    'ScanResult',

    # JS Analyzer
    'JSSecurityAnalyzer',
    'JSFinding',
    'SecretFinding',
    'EndpointFinding',
    'JSAnalysisReport',

    # AI Security
    'AISecurityTester',
    'VulnerabilityType',
    'TestResult',
    'SecurityReport',

    # Enhanced Pipeline
    'EnhancedSecurityPipeline',
    'PipelineConfig',
    'PipelineReport',

    # LLM Red Team
    'LLMRedTeamFramework',
    'AttackStrategy',
    'VulnerabilityClass',
    'AttackResult',
    'RedTeamReport',
    'PayloadLibrary',

    # Pentest Agent
    'AutonomousPentestAgent',
    'PentestPhase',
    'PentestReport',
    'AttackPathPlanner',
    'MCTSNode',
    'ToolRegistry',
    'ReasoningModule',

    # Stealth Browser
    'StealthBrowserFactory',
    'StealthConfig',
    'StealthSession',
    'CamoufoxBrowser',
    'NodriverBrowser',
    'PlaywrightStealthBrowser',
    'BrowserFingerprint',

    # TLS Client
    'TLSClient',
    'TLSConfig',
    'TLSResponse',
    'BrowserProfile',
    'ProxyWaterfall',
    'create_stealth_client',

    # Browser Pool
    'BrowserPool',
    'BrowserStealthConfig',
    'PoolConfig',

    # Vulnerability Scanners
    'CORSScanner',
    'IDORScanner',
    'XXEScanner',
    'CRLFScanner',
    'RCEScanner',
    'UnifiedVulnScanner',
    'VulnFinding',
    'VulnSeverity',

    # Advanced Attacks
    'WAFBypassEngine',
    'RaceConditionTester',
    'OAuthAttacker',
    'PaymentSecurityTester',
    'HTTPSmugglingDetector',
    'OriginDiscoveryResult',

    # Deep Pentesting
    'JWTAnalyzer',
    'SourceMapHunter',
    'APIFuzzer',
    'RateLimitBypass',
    'FileUploadTester',
    'DeepFinding',

    # Advanced Recon
    'JSDeepAnalyzer',
    'GraphQLSecurityTester',
    'SubdomainEnumerator',
    'AuthTester',
    'CloudAssetDiscovery',
    'ReconFinding',
]

__version__ = '4.0.0'
__author__ = 'DeadManOfficial'
