#!/usr/bin/env python3
"""
BlackBox AI - Mobile Security Module
=====================================

Mobile application security testing tools:
- MobSF (Mobile Security Framework)
- Frida (Dynamic instrumentation)
- APKTool (APK decompilation)
- Objection (Runtime mobile exploration)
"""

import sys
import os
from pathlib import Path

module_dir = Path(__file__).parent.parent.parent
if str(module_dir) not in sys.path:
    sys.path.insert(0, str(module_dir))

from modules.base import BaseModule, ModuleCategory, ModuleStatus, ToolDefinition, RouteDefinition, ToolWrapper, ToolResult
from modules.cli import CLIToolWrapper
from modules.docker import DockerToolWrapper
from typing import Dict, Any, List, Optional
import logging
import json
import subprocess

logger = logging.getLogger(__name__)


class MobSFWrapper(DockerToolWrapper):
    """Wrapper for MobSF Mobile Security Framework"""
    name = "mobsf"
    image = "opensecurity/mobile-security-framework-mobsf:latest"
    description = "Mobile Security Framework for static/dynamic analysis"

    def build_command(self, apk_path: str = "", api_key: str = "",
                     scan_type: str = "apk", **kwargs) -> List[str]:
        # MobSF runs as a web service, we interact via API
        command = ["python3", "-c", f"""
import requests
import json
import sys

API_KEY = '{api_key or os.environ.get("MOBSF_API_KEY", "")}'
SERVER = 'http://localhost:8000'

# Upload file
with open('{apk_path}', 'rb') as f:
    resp = requests.post(
        f'{{SERVER}}/api/v1/upload',
        files={{'file': f}},
        headers={{'Authorization': API_KEY}}
    )
    upload = resp.json()
    print(json.dumps(upload))

# Scan
resp = requests.post(
    f'{{SERVER}}/api/v1/scan',
    data={{'scan_type': '{scan_type}', 'file_name': upload.get('file_name'), 'hash': upload.get('hash')}},
    headers={{'Authorization': API_KEY}}
)
print(json.dumps(resp.json()))
"""]
        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        try:
            lines = stdout.strip().split('\n')
            results = [json.loads(line) for line in lines if line.strip().startswith('{')]
            return {
                "results": results,
                "success": len(results) > 0
            }
        except:
            return {"raw_output": stdout}


class FridaWrapper(CLIToolWrapper):
    """Wrapper for Frida dynamic instrumentation toolkit"""
    name = "frida"
    description = "Dynamic instrumentation toolkit for mobile apps"

    def _find_tool(self) -> Optional[str]:
        import shutil
        return shutil.which("frida")

    def build_command(self, target: str, script: str = "",
                     spawn: bool = False, usb: bool = False,
                     **kwargs) -> List[str]:
        command = ["frida"]

        if usb:
            command.append("-U")
        if spawn:
            command.extend(["-f", target])
        else:
            command.append(target)

        if script:
            command.extend(["-l", script])

        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "output": stdout,
            "errors": stderr,
            "success": return_code == 0
        }


class APKToolWrapper(CLIToolWrapper):
    """Wrapper for APKTool APK decompilation"""
    name = "apktool"
    description = "APK decompilation and recompilation tool"

    def _find_tool(self) -> Optional[str]:
        import shutil
        path = shutil.which("apktool")
        if not path:
            for p in ["~/.claude-home/BlackBox/external-tools/apktool/apktool.jar"]:
                if os.path.exists(p):
                    return p
        return path

    def build_command(self, apk_path: str, action: str = "d",
                     output_dir: str = "", force: bool = True,
                     **kwargs) -> List[str]:
        if self.tool_path.endswith(".jar"):
            command = ["java", "-jar", self.tool_path]
        else:
            command = [self.tool_path]

        command.append(action)  # d = decode, b = build

        if force:
            command.append("-f")
        if output_dir:
            command.extend(["-o", output_dir])

        command.append(apk_path)
        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "output": stdout,
            "success": return_code == 0,
            "action": "decode" if "d" in stdout else "build"
        }


class ObjectionWrapper(CLIToolWrapper):
    """Wrapper for Objection mobile exploration toolkit"""
    name = "objection"
    description = "Runtime mobile exploration toolkit"

    def _find_tool(self) -> Optional[str]:
        import shutil
        return shutil.which("objection")

    def build_command(self, gadget: str = "", command_str: str = "",
                     **kwargs) -> List[str]:
        cmd = ["objection"]

        if gadget:
            cmd.extend(["--gadget", gadget])

        if command_str:
            cmd.extend(["explore", "--startup-command", command_str])
        else:
            cmd.append("explore")

        return cmd

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "output": stdout,
            "success": return_code == 0
        }


class JadxWrapper(CLIToolWrapper):
    """Wrapper for JADX Android decompiler"""
    name = "jadx"
    description = "Dex to Java decompiler"

    def _find_tool(self) -> Optional[str]:
        import shutil
        path = shutil.which("jadx")
        if not path:
            for p in ["~/.claude-home/BlackBox/external-tools/jadx/bin/jadx"]:
                if os.path.exists(p):
                    return p
        return path

    def build_command(self, input_file: str, output_dir: str = "",
                     deobf: bool = True, **kwargs) -> List[str]:
        command = [self.tool_path]

        if output_dir:
            command.extend(["-d", output_dir])
        if deobf:
            command.append("--deobf")

        command.append(input_file)
        return command

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> Dict[str, Any]:
        return {
            "output": stdout,
            "success": return_code == 0
        }


class MobileSecurityModule(BaseModule):
    """
    Mobile Security Module for BlackBox.

    Provides mobile application security testing capabilities.
    """

    name = "mobile"
    version = "1.0.0"
    category = ModuleCategory.MOBILE
    description = "Mobile application security testing (Android/iOS)"
    author = "BlackBox Team"
    tags = ["mobile", "android", "ios", "apk", "frida"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

        self.mobsf = MobSFWrapper()
        self.frida = FridaWrapper()
        self.apktool = APKToolWrapper()
        self.objection = ObjectionWrapper()
        self.jadx = JadxWrapper()

    def on_load(self) -> bool:
        self.logger.info(f"Loading {self.name} module v{self.version}")

        tools = {
            "mobsf": self.mobsf.is_available(),
            "frida": self.frida.is_available(),
            "apktool": self.apktool.is_available(),
            "objection": self.objection.is_available(),
            "jadx": self.jadx.is_available()
        }

        available = sum(tools.values())
        self.logger.info(f"Mobile tools available: {available}/{len(tools)}")
        return True

    def register_tools(self, mcp: Any, client: Any) -> List[ToolDefinition]:
        tools = []

        @mcp.tool()
        def mobile_apk_decode(apk_path: str, output_dir: str = "",
                             timeout: int = 120) -> Dict[str, Any]:
            """
            Decompile an APK file using APKTool.

            Args:
                apk_path: Path to APK file
                output_dir: Output directory for decompiled files
                timeout: Execution timeout

            Returns:
                Decompilation results
            """
            self.logger.info(f"Decompiling APK: {apk_path}")
            result = self.apktool.execute(
                apk_path=apk_path, action="d",
                output_dir=output_dir, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="mobile_apk_decode",
            description="Decompile APK with APKTool",
            handler=mobile_apk_decode,
            category="mobile",
            tags=["apk", "decode", "android"]
        ))

        @mcp.tool()
        def mobile_jadx_decompile(input_file: str, output_dir: str = "",
                                  timeout: int = 300) -> Dict[str, Any]:
            """
            Decompile DEX/APK to Java source using JADX.

            Args:
                input_file: Path to APK or DEX file
                output_dir: Output directory for Java source
                timeout: Execution timeout

            Returns:
                Decompilation results
            """
            self.logger.info(f"Decompiling with JADX: {input_file}")
            result = self.jadx.execute(
                input_file=input_file, output_dir=output_dir, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="mobile_jadx_decompile",
            description="Decompile APK/DEX to Java with JADX",
            handler=mobile_jadx_decompile,
            category="mobile",
            tags=["jadx", "java", "decompile"]
        ))

        @mcp.tool()
        def mobile_frida_script(target: str, script_path: str,
                               usb: bool = True, timeout: int = 60) -> Dict[str, Any]:
            """
            Run a Frida script against a mobile app.

            Args:
                target: Package name or PID
                script_path: Path to Frida script
                usb: Use USB device
                timeout: Execution timeout

            Returns:
                Script execution results
            """
            self.logger.info(f"Running Frida script on {target}")
            result = self.frida.execute(
                target=target, script=script_path, usb=usb, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="mobile_frida_script",
            description="Run Frida script on mobile app",
            handler=mobile_frida_script,
            category="mobile",
            tags=["frida", "dynamic", "instrumentation"]
        ))

        @mcp.tool()
        def mobile_objection_explore(package: str, command: str = "",
                                    timeout: int = 60) -> Dict[str, Any]:
            """
            Explore a mobile app runtime with Objection.

            Args:
                package: Target package/app
                command: Startup command to run
                timeout: Execution timeout

            Returns:
                Exploration results
            """
            self.logger.info(f"Objection explore: {package}")
            result = self.objection.execute(
                gadget=package, command_str=command, timeout=timeout
            )
            return result.to_dict()

        tools.append(ToolDefinition(
            name="mobile_objection_explore",
            description="Explore mobile app with Objection",
            handler=mobile_objection_explore,
            category="mobile",
            tags=["objection", "runtime", "exploration"]
        ))

        self._tools = tools
        return tools

    def register_routes(self, app: Any) -> List[RouteDefinition]:
        from flask import request, jsonify
        routes = []

        @app.route('/api/mobile/decode', methods=['POST'])
        def api_mobile_decode():
            data = request.get_json() or {}
            apk_path = data.get('apk_path')
            if not apk_path:
                return jsonify({"error": "apk_path required"}), 400
            result = self.apktool.execute(apk_path=apk_path, action="d")
            return jsonify(result.to_dict())

        routes.append(RouteDefinition(path="/api/mobile/decode", methods=["POST"],
                                     handler=api_mobile_decode, description="Decode APK"))

        @app.route('/api/mobile/status', methods=['GET'])
        def api_mobile_status():
            return jsonify(self.health_check())

        routes.append(RouteDefinition(path="/api/mobile/status", methods=["GET"],
                                     handler=api_mobile_status, description="Module status"))

        self._routes = routes
        return routes

    def health_check(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "healthy": any([
                self.apktool.is_available(),
                self.frida.is_available()
            ]),
            "tools": {
                "mobsf": self.mobsf.is_available(),
                "frida": self.frida.is_available(),
                "apktool": self.apktool.is_available(),
                "objection": self.objection.is_available(),
                "jadx": self.jadx.is_available()
            }
        }


Module = MobileSecurityModule
MobileModule = MobileSecurityModule  # Alias for consistent naming
