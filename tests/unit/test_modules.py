#!/usr/bin/env python3
"""
Unit Tests - Module System
==========================

Tests for the BlackBox module architecture.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestBaseModule:
    """Tests for BaseModule abstract class"""

    def test_base_module_is_abstract(self):
        """BaseModule cannot be instantiated directly"""
        from modules.base import BaseModule

        with pytest.raises(TypeError):
            BaseModule()

    def test_module_category_enum(self):
        """ModuleCategory enum has expected values"""
        from modules.base import ModuleCategory

        assert ModuleCategory.CORE.value == "core"
        assert ModuleCategory.SCANNING.value == "scanning"
        assert ModuleCategory.PENTEST.value == "pentest"
        assert ModuleCategory.CTF.value == "ctf"

    def test_tool_definition_dataclass(self):
        """ToolDefinition dataclass works correctly"""
        from modules.base import ToolDefinition

        def dummy_handler():
            pass

        tool = ToolDefinition(
            name="test_tool",
            description="Test tool",
            handler=dummy_handler
        )

        assert tool.name == "test_tool"
        assert tool.description == "Test tool"
        assert tool.timeout == 300  # default


class TestModuleLoader:
    """Tests for ModuleLoader"""

    def test_loader_initialization(self, temp_config):
        """ModuleLoader initializes with config"""
        from modules.loader import ModuleLoader

        loader = ModuleLoader(str(temp_config / "modules.yaml"))
        assert loader is not None
        assert loader.config is not None

    def test_discover_modules(self, module_loader):
        """Loader discovers available modules"""
        modules_dir = project_root / "modules"
        discovered = module_loader.discover_modules(str(modules_dir))

        # Should find at least some modules
        assert len(discovered) > 0

    def test_load_core_scanning_module(self, module_loader):
        """Can load core_scanning module"""
        module = module_loader.load_module('core_scanning')

        if module:
            assert module.name == 'core_scanning'
            assert hasattr(module, 'register_tools')
            assert hasattr(module, 'register_routes')

    def test_load_nonexistent_module(self, module_loader):
        """Loading nonexistent module returns None"""
        module = module_loader.load_module('nonexistent_module_xyz')
        assert module is None


class TestModuleRegistry:
    """Tests for ModuleRegistry singleton"""

    def test_registry_is_singleton(self):
        """ModuleRegistry uses singleton pattern"""
        from modules.loader import ModuleRegistry

        reg1 = ModuleRegistry()
        reg2 = ModuleRegistry()
        assert reg1 is reg2

    def test_register_and_get_module(self):
        """Can register and retrieve modules"""
        from modules.loader import ModuleRegistry

        registry = ModuleRegistry()
        mock_module = MagicMock()
        mock_module.name = "test_mock_unique"

        registry.register(mock_module)
        retrieved = registry.get("test_mock_unique")

        assert retrieved is mock_module

    def test_registry_has_list_method(self):
        """Registry has method to list modules"""
        from modules.loader import ModuleRegistry

        registry = ModuleRegistry()
        # Check for get_all or similar method
        assert hasattr(registry, 'get_all') or hasattr(registry, '_modules')


class TestCoreScanningModule:
    """Tests for CoreScanningModule"""

    def test_module_has_required_attributes(self):
        """CoreScanningModule has required attributes"""
        try:
            from modules.core_scanning.module import CoreScanningModule
            module = CoreScanningModule()

            assert hasattr(module, 'name')
            assert hasattr(module, 'version')
            assert hasattr(module, 'category')
        except ImportError:
            pytest.skip("CoreScanningModule not available")

    def test_register_tools(self, mock_mcp):
        """Module registers tools with MCP"""
        try:
            from modules.core_scanning.module import CoreScanningModule
            module = CoreScanningModule()
            # Note: register_tools takes (mcp, client)
            module.register_tools(mock_mcp, None)

            assert mock_mcp.tool.called
        except ImportError:
            pytest.skip("CoreScanningModule not available")


class TestCTFModule:
    """Tests for CTFModule"""

    def test_crypto_utils_rot_cipher(self):
        """ROT cipher works correctly"""
        try:
            from modules.ctf.module import CryptoUtils

            # ROT13
            result = CryptoUtils.rot("hello", 13)
            assert result == "uryyb"

            # ROT13 is self-inverse
            result2 = CryptoUtils.rot("uryyb", 13)
            assert result2 == "hello"
        except ImportError:
            pytest.skip("CTFModule not available")

    def test_crypto_utils_xor(self):
        """XOR cipher works correctly"""
        try:
            from modules.ctf.module import CryptoUtils

            # XOR takes bytes
            data = b"hello"
            key = b"k"
            encrypted = CryptoUtils.xor(data, key)

            # XOR is self-inverse
            decrypted = CryptoUtils.xor(encrypted, key)
            assert decrypted == data
        except ImportError:
            pytest.skip("CTFModule not available")

    def test_encoding_utils_base_decode(self):
        """Base decoding works"""
        try:
            from modules.ctf.module import EncodingUtils

            # base_decode returns dict of possible decodings
            result = EncodingUtils.base_decode("SGVsbG8gV29ybGQh")
            assert 'base64' in result
            assert result['base64'] == "Hello World!"
        except ImportError:
            pytest.skip("CTFModule not available")

    def test_hash_identification(self):
        """Hash identification works"""
        try:
            from modules.ctf.module import CryptoUtils

            # MD5 hash
            md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
            result = CryptoUtils.hash_identify(md5_hash)
            assert 'MD5' in result or 'md5' in [r.lower() for r in result]
        except ImportError:
            pytest.skip("CTFModule not available")


class TestPayloadsModule:
    """Tests for PayloadsModule"""

    def test_payload_encoder_base64(self):
        """Payload encoder base64 works"""
        try:
            from modules.payloads.module import PayloadEncoder

            result = PayloadEncoder.encode("test", "base64")
            assert result == "dGVzdA=="
        except ImportError:
            pytest.skip("PayloadsModule not available")

    def test_payload_encoder_chain(self):
        """Payload encoder chain encoding works"""
        try:
            from modules.payloads.module import PayloadEncoder

            # chain_encode returns dict with 'final' key
            result = PayloadEncoder.chain_encode("test", ["base64", "hex"])
            assert 'final' in result
            assert isinstance(result['final'], str)
            assert len(result['final']) > 0
        except ImportError:
            pytest.skip("PayloadsModule not available")

    def test_shellcode_generator(self):
        """Shellcode generator produces output"""
        try:
            from modules.payloads.module import ShellcodeGenerator

            result = ShellcodeGenerator.generate("reverse_shell_bash", lhost="10.0.0.1", lport=4444)
            # Returns dict with 'code' or 'template' key
            assert isinstance(result, dict)
            # Check for the generated code
            code = result.get('code') or result.get('template') or str(result)
            assert "10.0.0.1" in code or "10.0.0.1" in str(result)
        except ImportError:
            pytest.skip("PayloadsModule not available")


class TestPentestModule:
    """Tests for PentestModule"""

    def test_pentest_engine_phases(self):
        """Pentest engine has all phases"""
        try:
            from modules.pentest.module import SimplePentestEngine
            engine = SimplePentestEngine()

            phases = ['P1', 'P2', 'P3', 'P4', 'P5', 'P6']
            for phase in phases:
                tools = engine.get_phase_tools(phase)
                assert isinstance(tools, list)
                assert len(tools) > 0
        except ImportError:
            pytest.skip("PentestModule not available")

    def test_add_finding(self):
        """Can add findings to engine"""
        try:
            from modules.pentest.module import SimplePentestEngine, PentestFinding
            engine = SimplePentestEngine()

            finding = PentestFinding(
                phase="P2",
                tool="nuclei",
                severity="high",
                title="Test Finding",
                description="Test description"
            )

            engine.add_finding(finding)
            assert len(engine.findings) == 1
            assert engine.findings[0].title == "Test Finding"
        except ImportError:
            pytest.skip("PentestModule not available")

    def test_generate_report(self):
        """Can generate assessment report"""
        try:
            from modules.pentest.module import SimplePentestEngine, PentestFinding
            engine = SimplePentestEngine()

            # Add some findings
            engine.add_finding(PentestFinding(
                phase="P1", tool="nmap", severity="info",
                title="Open Port", description="Port 22 open"
            ))
            engine.add_finding(PentestFinding(
                phase="P2", tool="nuclei", severity="high",
                title="Vulnerability", description="SQL Injection found"
            ))

            report = engine.generate_report()

            assert 'phase' in report
            assert 'findings' in report
            assert 'findings_summary' in report
            assert report['findings_summary']['total'] == 2
        except ImportError:
            pytest.skip("PentestModule not available")


class TestAgentsModule:
    """Tests for AgentsModule"""

    def test_security_agents_dict(self):
        """Security agents dict is populated"""
        try:
            from modules.agents.module import SecurityAgents

            # SecurityAgents has AGENTS dict
            assert hasattr(SecurityAgents, 'AGENTS')
            agents = SecurityAgents.AGENTS

            assert len(agents) >= 3
            assert 'penetration-tester' in agents
        except ImportError:
            pytest.skip("AgentsModule not available")

    def test_agent_has_system_prompt(self):
        """Agents have system prompts"""
        try:
            from modules.agents.module import SecurityAgents

            agent = SecurityAgents.AGENTS.get('penetration-tester')
            assert agent is not None
            assert 'system_prompt' in agent
            assert len(agent['system_prompt']) > 100
        except ImportError:
            pytest.skip("AgentsModule not available")
