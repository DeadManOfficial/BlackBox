#!/usr/bin/env python3
"""
Reverse Engineering Analyzer
Integrates RE tools for comprehensive analysis

Usage:
    ./re-analyzer.py --tool ghidra --target binary.exe
    ./re-analyzer.py --tool frida --target com.app.name
    ./re-analyzer.py --tool mitmproxy --capture
    ./re-analyzer.py --tool jadx --target app.apk
    ./re-analyzer.py --tool beautify --target bundle.js
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
OUTPUT_DIR = FRAMEWORK_DIR / "analysis"


class REAnalyzer:
    """Reverse Engineering tool orchestrator"""

    def __init__(self):
        self.tools = {
            "ghidra": GhidraIntegration(),
            "frida": FridaIntegration(),
            "mitmproxy": MitmproxyIntegration(),
            "jadx": JadxIntegration(),
            "beautify": JSBeautifier()
        }
        OUTPUT_DIR.mkdir(exist_ok=True)

    def analyze(self, tool_name, target, options=None):
        """Run analysis with specified tool"""
        if tool_name not in self.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        tool = self.tools[tool_name]
        return tool.analyze(target, options)

    def check_tools(self):
        """Check which tools are available"""
        status = {}
        for name, tool in self.tools.items():
            status[name] = tool.is_available()
        return status


class GhidraIntegration:
    """Ghidra binary analysis integration"""

    def is_available(self):
        """Check if Ghidra is installed"""
        try:
            result = subprocess.run(["which", "analyzeHeadless"],
                                   capture_output=True, text=True)
            return result.returncode == 0 or Path("~/.claude-home/BlackBox/external-tools/ghidra").exists()
        except:
            return False

    def analyze(self, target, options=None):
        """Analyze binary with Ghidra headless"""
        result = {
            "tool": "ghidra",
            "target": str(target),
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }

        if not self.is_available():
            result["error"] = "Ghidra not installed"
            result["install"] = "Download from https://ghidra-sre.org/"
            return result

        # Headless analysis command template
        project_path = OUTPUT_DIR / "ghidra_projects"
        project_path.mkdir(exist_ok=True)

        result["analysis"]["command"] = f"""
analyzeHeadless {project_path} temp_project \\
    -import {target} \\
    -postScript FunctionExporter.java \\
    -scriptPath ~/.claude-home/BlackBox/external-tools/ghidra/Ghidra/RuntimeScripts/Common/support
        """.strip()

        result["analysis"]["manual_steps"] = [
            "1. Open Ghidra GUI for detailed analysis",
            "2. File > Import File > Select binary",
            "3. Analyze with default analyzers",
            "4. Review Decompiler window for pseudocode",
            "5. Check Symbol Tree for functions/strings"
        ]

        result["analysis"]["key_views"] = [
            "Decompiler - Pseudocode",
            "Listing - Assembly",
            "Symbol Tree - Functions/Data",
            "Defined Strings - String literals",
            "Function Graph - Control flow"
        ]

        return result


class FridaIntegration:
    """Frida dynamic instrumentation integration"""

    def is_available(self):
        """Check if Frida is installed"""
        try:
            result = subprocess.run(["frida", "--version"],
                                   capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def analyze(self, target, options=None):
        """Setup Frida instrumentation"""
        result = {
            "tool": "frida",
            "target": str(target),
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }

        if not self.is_available():
            result["error"] = "Frida not installed"
            result["install"] = "pip install frida-tools"
            return result

        # Generate hook scripts
        result["analysis"]["scripts"] = {
            "trace_calls": self._generate_trace_script(),
            "hook_functions": self._generate_hook_script(target),
            "ssl_bypass": self._generate_ssl_bypass()
        }

        result["analysis"]["commands"] = {
            "spawn": f"frida -U -f {target} -l hook.js --no-pause",
            "attach": f"frida -U {target} -l hook.js",
            "trace": f"frida-trace -U {target} -i 'recv*' -i 'send*'"
        }

        return result

    def _generate_trace_script(self):
        return '''
// Function tracer
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter: function(args) {
        console.log('[open] ' + Memory.readUtf8String(args[0]));
    }
});
        '''.strip()

    def _generate_hook_script(self, target):
        return f'''
// Hook template for {target}
Java.perform(function() {{
    var targetClass = Java.use('com.target.ClassName');

    targetClass.methodName.implementation = function(arg1) {{
        console.log('[+] methodName called with: ' + arg1);
        var result = this.methodName(arg1);
        console.log('[+] methodName returned: ' + result);
        return result;
    }};
}});
        '''.strip()

    def _generate_ssl_bypass(self):
        return '''
// SSL Pinning Bypass
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: 'com.custom.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var context = SSLContext.getInstance('TLS');
    context.init(null, [TrustManager.$new()], null);
    console.log('[+] SSL Pinning Bypassed');
});
        '''.strip()


class MitmproxyIntegration:
    """mitmproxy traffic interception integration"""

    def is_available(self):
        """Check if mitmproxy is installed"""
        try:
            result = subprocess.run(["mitmproxy", "--version"],
                                   capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def analyze(self, target, options=None):
        """Setup mitmproxy capture"""
        result = {
            "tool": "mitmproxy",
            "target": str(target) if target else "all",
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }

        if not self.is_available():
            result["error"] = "mitmproxy not installed"
            result["install"] = "pip install mitmproxy"
            return result

        # Generate addon scripts
        scripts_dir = OUTPUT_DIR / "mitm_scripts"
        scripts_dir.mkdir(exist_ok=True)

        result["analysis"]["scripts"] = {
            "capture": self._generate_capture_script(),
            "modify": self._generate_modify_script(),
            "filter": self._generate_filter_script(target) if target else None
        }

        result["analysis"]["commands"] = {
            "interactive": "mitmproxy -p 8080",
            "web": "mitmweb -p 8080",
            "dump": "mitmdump -p 8080 -w traffic.mitm",
            "replay": "mitmdump -nC traffic.mitm",
            "script": "mitmproxy -s addon.py"
        }

        result["analysis"]["proxy_setup"] = {
            "http_proxy": "http://127.0.0.1:8080",
            "https_proxy": "http://127.0.0.1:8080",
            "cert_install": "http://mitm.it (after proxy configured)"
        }

        return result

    def _generate_capture_script(self):
        return '''
from mitmproxy import http
import json

def response(flow: http.HTTPFlow):
    """Log all requests and responses"""
    print(f"[{flow.request.method}] {flow.request.pretty_url}")

    # Log interesting headers
    for header in ['authorization', 'x-api-key', 'cookie']:
        if header in flow.request.headers:
            print(f"  {header}: {flow.request.headers[header][:50]}...")

    # Log response
    print(f"  -> {flow.response.status_code}")
        '''.strip()

    def _generate_modify_script(self):
        return '''
from mitmproxy import http

def request(flow: http.HTTPFlow):
    """Modify requests on the fly"""
    # Add custom header
    flow.request.headers["X-Custom-Header"] = "injected"

    # Modify specific endpoints
    if "/api/v1/user" in flow.request.path:
        # Change user ID for IDOR testing
        if flow.request.method == "GET":
            flow.request.path = flow.request.path.replace("/123", "/124")

def response(flow: http.HTTPFlow):
    """Modify responses on the fly"""
    # Bypass client-side checks
    if "isAdmin" in flow.response.text:
        flow.response.text = flow.response.text.replace(
            '"isAdmin":false', '"isAdmin":true'
        )
        '''.strip()

    def _generate_filter_script(self, target):
        return f'''
from mitmproxy import http

TARGET_DOMAIN = "{target}"

def request(flow: http.HTTPFlow):
    """Filter to only capture target domain"""
    if TARGET_DOMAIN not in flow.request.host:
        flow.kill()  # Drop non-target traffic
        '''.strip()


class JadxIntegration:
    """Jadx Android APK decompiler integration"""

    def is_available(self):
        """Check if Jadx is installed"""
        try:
            result = subprocess.run(["jadx", "--version"],
                                   capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def analyze(self, target, options=None):
        """Decompile APK with Jadx"""
        result = {
            "tool": "jadx",
            "target": str(target),
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }

        if not self.is_available():
            result["error"] = "Jadx not installed"
            result["install"] = "Download from https://github.com/skylot/jadx/releases"
            return result

        output_path = OUTPUT_DIR / "jadx_output" / Path(target).stem
        output_path.parent.mkdir(parents=True, exist_ok=True)

        result["analysis"]["commands"] = {
            "decompile": f"jadx -d {output_path} {target}",
            "gui": f"jadx-gui {target}",
            "export_gradle": f"jadx -e -d {output_path} {target}"
        }

        result["analysis"]["key_files"] = [
            "AndroidManifest.xml - Permissions and components",
            "resources/res/values/strings.xml - String resources",
            "sources/ - Decompiled Java source"
        ]

        result["analysis"]["search_patterns"] = [
            "API keys: grep -r 'api[_-]?key' sources/",
            "URLs: grep -rE 'https?://' sources/",
            "Secrets: grep -ri 'password|secret|token' sources/",
            "Firebase: grep -r 'firebase' sources/",
            "AWS: grep -r 'AKIA' sources/"
        ]

        return result


class JSBeautifier:
    """JavaScript beautifier/deobfuscator integration"""

    def is_available(self):
        """Check if js-beautify is installed"""
        try:
            result = subprocess.run(["js-beautify", "--version"],
                                   capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def analyze(self, target, options=None):
        """Beautify JavaScript file"""
        result = {
            "tool": "beautify",
            "target": str(target),
            "timestamp": datetime.now().isoformat(),
            "analysis": {}
        }

        target_path = Path(target)
        if not target_path.exists():
            result["error"] = f"File not found: {target}"
            return result

        output_path = OUTPUT_DIR / "beautified" / target_path.name
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if self.is_available():
            result["analysis"]["commands"] = {
                "beautify": f"js-beautify {target} -o {output_path}",
                "minify_check": f"js-beautify --type js {target}"
            }
        else:
            result["analysis"]["install"] = "npm install -g js-beautify"

        # Analysis patterns for beautified JS
        result["analysis"]["search_patterns"] = [
            "API endpoints: grep -E '(api|v[0-9])/[a-z]' file.js",
            "Fetch calls: grep -E 'fetch\\(|axios\\.' file.js",
            "Secrets: grep -E 'api[_-]?key|secret|token' file.js",
            "Debug: grep -E 'console\\.(log|debug)' file.js",
            "URLs: grep -oE 'https?://[^\"]+' file.js"
        ]

        result["analysis"]["deobfuscation_tools"] = [
            "de4js - https://lelinhtinh.github.io/de4js/",
            "js-beautify - npm install -g js-beautify",
            "synchrony - npm install -g synchrony",
            "webcrack - https://webcrack.netlify.app/"
        ]

        return result


def main():
    parser = argparse.ArgumentParser(description="RE Analyzer")
    parser.add_argument("--tool", "-t", required=True,
                       choices=["ghidra", "frida", "mitmproxy", "jadx", "beautify"],
                       help="Analysis tool to use")
    parser.add_argument("--target", help="Target file/app/domain")
    parser.add_argument("--capture", action="store_true", help="Start capture mode")
    parser.add_argument("--check", action="store_true", help="Check tool availability")
    parser.add_argument("--output", "-o", help="Output format",
                       choices=["json", "text"], default="text")

    args = parser.parse_args()
    analyzer = REAnalyzer()

    if args.check:
        status = analyzer.check_tools()
        print("\nTool Status:")
        print("-" * 40)
        for tool, available in status.items():
            icon = "✓" if available else "✗"
            print(f"  [{icon}] {tool}")
        return

    if not args.target and not args.capture:
        print("Error: --target required (or --capture for mitmproxy)")
        sys.exit(1)

    target = args.target if args.target else None
    result = analyzer.analyze(args.tool, target)

    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"RE Analysis: {args.tool.upper()}")
        print(f"{'='*60}")
        print(f"Target: {result.get('target', 'N/A')}")
        print(f"Time: {result.get('timestamp', 'N/A')}")

        if "error" in result:
            print(f"\n[!] Error: {result['error']}")
            if "install" in result:
                print(f"    Install: {result['install']}")
        else:
            analysis = result.get("analysis", {})

            if "commands" in analysis:
                print("\nCommands:")
                for name, cmd in analysis["commands"].items():
                    print(f"  {name}: {cmd}")

            if "scripts" in analysis:
                print("\nGenerated Scripts:")
                for name in analysis["scripts"]:
                    if analysis["scripts"][name]:
                        print(f"  - {name}")

            if "manual_steps" in analysis:
                print("\nManual Steps:")
                for step in analysis["manual_steps"]:
                    print(f"  {step}")

            if "search_patterns" in analysis:
                print("\nSearch Patterns:")
                for pattern in analysis["search_patterns"]:
                    print(f"  {pattern}")


if __name__ == "__main__":
    main()
