"""
WebSocket Protocol Analyzer Module

Analyzes WebSocket-based APIs, extracts protocol information,
and documents RPC methods for further exploitation.
"""

import json
import asyncio
import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import websockets
from websockets.exceptions import WebSocketException


@dataclass
class RPCMethod:
    """Discovered RPC method"""
    name: str
    params_schema: Optional[Dict] = None
    requires_auth: bool = False
    sample_request: Optional[Dict] = None
    sample_response: Optional[Dict] = None
    error_codes: List[str] = field(default_factory=list)


@dataclass
class WebSocketProtocol:
    """Analyzed WebSocket protocol"""
    url: str
    protocol_version: Optional[int] = None
    auth_required: bool = False
    auth_method: Optional[str] = None
    handshake_flow: List[Dict] = field(default_factory=list)
    rpc_methods: List[RPCMethod] = field(default_factory=list)
    event_types: List[str] = field(default_factory=list)
    error_codes: Dict[str, str] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict] = field(default_factory=list)


class WebSocketAnalyzer:
    """
    Analyzes WebSocket APIs to extract protocol information.

    Features:
    - Protocol handshake analysis
    - RPC method enumeration
    - Event type discovery
    - Authentication mechanism detection
    - Vulnerability identification
    """

    # Common RPC method patterns to probe
    COMMON_METHODS = [
        "ping", "pong", "connect", "disconnect", "status", "health",
        "auth", "login", "logout", "register",
        "get", "list", "create", "update", "delete",
        "subscribe", "unsubscribe", "publish",
        "user.get", "user.list", "user.create",
        "session.get", "session.list", "session.create",
        "config.get", "config.set",
        "admin.status", "admin.users",
        "debug", "metrics", "logs",
    ]

    # Known protocol patterns
    PROTOCOL_SIGNATURES = {
        'socket.io': r'EIO=\d|socket\.io',
        'signalr': r'negotiate\?|signalr',
        'graphql-ws': r'connection_init|start|data',
        'json-rpc': r'"jsonrpc"\s*:\s*"2\.0"',
        'custom-rpc': r'"type"\s*:\s*"(req|res|event)"',
        'phoenix': r'phx_join|phx_reply',
    }

    # Vulnerability patterns
    VULN_PATTERNS = [
        ('no_auth_required', 'Authentication not required for sensitive methods'),
        ('info_disclosure', 'Sensitive information in responses'),
        ('method_enumeration', 'All methods accessible without restrictions'),
        ('debug_enabled', 'Debug endpoints accessible'),
        ('rate_limit_missing', 'No rate limiting detected'),
    ]

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.messages: List[Dict] = []

    async def analyze(self, url: str,
                      auth_callback: Optional[Callable] = None) -> WebSocketProtocol:
        """
        Analyze a WebSocket endpoint.

        Args:
            url: WebSocket URL (ws:// or wss://)
            auth_callback: Optional callback for authentication
        """
        protocol = WebSocketProtocol(url=url)

        try:
            async with websockets.connect(
                url,
                open_timeout=self.timeout,
                close_timeout=5
            ) as ws:
                # Capture initial handshake
                await self._analyze_handshake(ws, protocol)

                # Attempt authentication if callback provided
                if auth_callback:
                    await auth_callback(ws, protocol)

                # Probe for methods
                await self._probe_methods(ws, protocol)

                # Identify protocol type
                self._identify_protocol(protocol)

                # Check for vulnerabilities
                self._check_vulnerabilities(protocol)

        except WebSocketException as e:
            protocol.vulnerabilities.append({
                'type': 'connection_error',
                'detail': str(e)
            })
        except Exception as e:
            protocol.vulnerabilities.append({
                'type': 'analysis_error',
                'detail': str(e)
            })

        return protocol

    async def _analyze_handshake(self, ws, protocol: WebSocketProtocol):
        """Analyze the initial handshake"""
        try:
            # Wait for initial message
            msg = await asyncio.wait_for(ws.recv(), timeout=5)

            try:
                data = json.loads(msg)
                protocol.handshake_flow.append({
                    'direction': 'server',
                    'type': 'initial',
                    'data': data
                })

                # Check for challenge-response auth
                if 'challenge' in str(data).lower() or 'nonce' in str(data).lower():
                    protocol.auth_required = True
                    protocol.auth_method = 'challenge-response'

                # Extract event type if present
                if isinstance(data, dict) and 'event' in data:
                    protocol.event_types.append(data['event'])

                # Check for protocol version
                if isinstance(data, dict):
                    for key in ['version', 'protocol', 'protocolVersion']:
                        if key in data:
                            protocol.protocol_version = data[key]
                            break

            except json.JSONDecodeError:
                protocol.handshake_flow.append({
                    'direction': 'server',
                    'type': 'initial',
                    'data': msg[:500]
                })

        except asyncio.TimeoutError:
            pass  # No initial message

    async def _probe_methods(self, ws, protocol: WebSocketProtocol):
        """Probe for available RPC methods"""
        for method in self.COMMON_METHODS:
            try:
                # Try JSON-RPC style
                request = {
                    "type": "req",
                    "id": hashlib.md5(method.encode()).hexdigest()[:8],
                    "method": method,
                    "params": {}
                }

                await ws.send(json.dumps(request))

                try:
                    response = await asyncio.wait_for(ws.recv(), timeout=2)
                    data = json.loads(response)

                    # Record the response
                    if isinstance(data, dict):
                        if data.get('ok') or 'result' in data or 'payload' in data:
                            # Method exists and returned data
                            rpc = RPCMethod(
                                name=method,
                                requires_auth=False,
                                sample_request=request,
                                sample_response=data
                            )
                            protocol.rpc_methods.append(rpc)

                        elif 'error' in data or data.get('ok') == False:
                            # Method exists but returned error
                            error_msg = data.get('error', {})
                            if isinstance(error_msg, dict):
                                code = error_msg.get('code', 'UNKNOWN')
                                protocol.error_codes[code] = error_msg.get('message', '')

                                # Check if auth required
                                if 'auth' in code.lower() or 'permission' in code.lower():
                                    rpc = RPCMethod(
                                        name=method,
                                        requires_auth=True,
                                        error_codes=[code]
                                    )
                                    protocol.rpc_methods.append(rpc)
                                    protocol.auth_required = True

                except (asyncio.TimeoutError, json.JSONDecodeError):
                    pass

            except Exception:
                pass

    def _identify_protocol(self, protocol: WebSocketProtocol):
        """Identify the WebSocket protocol type"""
        all_text = json.dumps(protocol.handshake_flow) + json.dumps([m.name for m in protocol.rpc_methods])

        for proto_name, pattern in self.PROTOCOL_SIGNATURES.items():
            if re.search(pattern, all_text, re.IGNORECASE):
                protocol.technologies.append(proto_name)

        # Check handshake for tech hints
        for msg in protocol.handshake_flow:
            data = msg.get('data', {})
            if isinstance(data, dict):
                if 'type' in data and data['type'] == 'event':
                    protocol.technologies.append('event-driven')
                if 'jsonrpc' in str(data):
                    protocol.technologies.append('json-rpc-2.0')

    def _check_vulnerabilities(self, protocol: WebSocketProtocol):
        """Check for common vulnerabilities"""
        # Check if methods accessible without auth
        unauthenticated = [m for m in protocol.rpc_methods if not m.requires_auth]
        if len(unauthenticated) > 5:
            protocol.vulnerabilities.append({
                'type': 'excessive_unauthenticated_access',
                'severity': 'medium',
                'detail': f'{len(unauthenticated)} methods accessible without authentication',
                'methods': [m.name for m in unauthenticated]
            })

        # Check for debug/admin methods
        sensitive_methods = ['debug', 'admin', 'config', 'logs', 'exec']
        exposed_sensitive = [m for m in protocol.rpc_methods
                           if any(s in m.name.lower() for s in sensitive_methods)]
        if exposed_sensitive:
            protocol.vulnerabilities.append({
                'type': 'sensitive_method_exposure',
                'severity': 'high',
                'detail': 'Sensitive administrative methods may be accessible',
                'methods': [m.name for m in exposed_sensitive]
            })

        # Check for info disclosure in errors
        for code, msg in protocol.error_codes.items():
            if any(x in msg.lower() for x in ['stack', 'trace', 'internal', 'database']):
                protocol.vulnerabilities.append({
                    'type': 'error_info_disclosure',
                    'severity': 'low',
                    'detail': f'Error message may leak internal details: {msg}'
                })
                break

    def generate_report(self, protocol: WebSocketProtocol) -> str:
        """Generate a markdown report"""
        report = f"""# WebSocket Protocol Analysis

## Target
- **URL:** {protocol.url}
- **Protocol Version:** {protocol.protocol_version or 'Unknown'}
- **Authentication Required:** {'Yes' if protocol.auth_required else 'No'}
- **Auth Method:** {protocol.auth_method or 'Unknown'}

## Technologies Detected
{chr(10).join(f'- {t}' for t in protocol.technologies) or '- None identified'}

## Handshake Flow
```json
{json.dumps(protocol.handshake_flow, indent=2)}
```

## RPC Methods ({len(protocol.rpc_methods)})
"""
        for method in protocol.rpc_methods:
            auth_badge = '🔒' if method.requires_auth else '🔓'
            report += f"\n### {auth_badge} {method.name}\n"
            if method.sample_response:
                report += f"```json\n{json.dumps(method.sample_response, indent=2)[:500]}\n```\n"

        report += f"\n## Event Types\n"
        report += '\n'.join(f'- `{e}`' for e in protocol.event_types) or '- None detected'

        report += f"\n\n## Error Codes\n"
        for code, msg in protocol.error_codes.items():
            report += f"- **{code}:** {msg}\n"

        report += f"\n## Vulnerabilities ({len(protocol.vulnerabilities)})\n"
        for vuln in protocol.vulnerabilities:
            report += f"\n### [{vuln.get('severity', 'unknown').upper()}] {vuln['type']}\n"
            report += f"{vuln['detail']}\n"
            if 'methods' in vuln:
                report += f"Affected methods: {', '.join(vuln['methods'])}\n"

        return report


# Convenience function for quick analysis
async def analyze_websocket(url: str) -> WebSocketProtocol:
    """Quick analysis of a WebSocket endpoint"""
    analyzer = WebSocketAnalyzer()
    return await analyzer.analyze(url)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python websocket_analyzer.py <ws_url>")
        sys.exit(1)

    async def main():
        analyzer = WebSocketAnalyzer()
        result = await analyzer.analyze(sys.argv[1])
        print(analyzer.generate_report(result))

    asyncio.run(main())
