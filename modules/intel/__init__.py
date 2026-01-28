"""
BlackBox Intelligence Gathering Modules

Advanced modules for extracting intelligence from targets:
- Source map extraction and analysis
- WebSocket protocol analysis
- JavaScript bundle intelligence
- API endpoint discovery
- Specialized service scanners (Clawdbot, Open WebUI)
"""

from .sourcemap_extractor import SourceMapExtractor
from .js_intel import JSIntelligence
from .websocket_analyzer import WebSocketAnalyzer
from .endpoint_discovery import EndpointDiscovery
from .clawdbot_scanner import ClawdbotScanner, ClawdbotInstance
from .openwebui_scanner import OpenWebUIScanner, OpenWebUIInstance

__all__ = [
    'SourceMapExtractor',
    'JSIntelligence',
    'WebSocketAnalyzer',
    'EndpointDiscovery',
    'ClawdbotScanner',
    'ClawdbotInstance',
    'OpenWebUIScanner',
    'OpenWebUIInstance',
]
