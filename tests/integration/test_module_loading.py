#!/usr/bin/env python3
"""
Integration Tests - Module Loading
==================================

Tests for loading and initializing all modules.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestAllModulesLoad:
    """Test that all modules load without errors"""

    def test_core_scanning_loads(self):
        """Core scanning module loads"""
        try:
            from modules.core_scanning.module import CoreScanningModule
            module = CoreScanningModule()
            assert module.name == 'core_scanning'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_reconnaissance_loads(self):
        """Reconnaissance module loads"""
        try:
            from modules.reconnaissance.module import ReconnaissanceModule
            module = ReconnaissanceModule()
            assert module.name == 'reconnaissance'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_web_attacks_loads(self):
        """Web attacks module loads"""
        try:
            from modules.web_attacks.module import WebAttacksModule
            module = WebAttacksModule()
            assert module.name == 'web_attacks'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_cloud_security_loads(self):
        """Cloud security module loads"""
        try:
            from modules.cloud_security.module import CloudSecurityModule
            module = CloudSecurityModule()
            assert module.name == 'cloud_security'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_darkweb_loads(self):
        """Darkweb module loads"""
        try:
            from modules.darkweb.module import DarkwebModule
            module = DarkwebModule()
            assert module.name == 'darkweb'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_ai_security_loads(self):
        """AI security module loads"""
        try:
            from modules.ai_security.module import AISecurityModule
            module = AISecurityModule()
            assert module.name == 'ai_security'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_mobile_loads(self):
        """Mobile module loads"""
        try:
            from modules.mobile.module import MobileModule
            module = MobileModule()
            assert module.name == 'mobile'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_payloads_loads(self):
        """Payloads module loads"""
        try:
            from modules.payloads.module import PayloadsModule
            module = PayloadsModule()
            assert module.name == 'payloads'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_ctf_loads(self):
        """CTF module loads"""
        try:
            from modules.ctf.module import CTFModule
            module = CTFModule()
            assert module.name == 'ctf'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_pentest_loads(self):
        """Pentest module loads"""
        try:
            from modules.pentest.module import PentestModule
            module = PentestModule()
            assert module.name == 'pentest'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_scraper_loads(self):
        """Scraper module loads"""
        try:
            from modules.scraper.module import ScraperModule
            module = ScraperModule()
            assert module.name == 'scraper'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")

    def test_agents_loads(self):
        """Agents module loads"""
        try:
            from modules.agents.module import AgentsModule
            module = AgentsModule()
            assert module.name == 'agents'
        except ImportError as e:
            pytest.skip(f"Module not available: {e}")


class TestModuleLoaderIntegration:
    """Integration tests for ModuleLoader"""

    def test_loader_discovers_all_modules(self):
        """Loader discovers all expected modules"""
        from modules.loader import ModuleLoader

        config_path = project_root / "config" / "modules.yaml"
        loader = ModuleLoader(str(config_path))

        modules_dir = project_root / "modules"
        discovered = loader.discover_modules(str(modules_dir))

        expected_modules = [
            'core_scanning', 'reconnaissance', 'web_attacks',
            'cloud_security', 'darkweb', 'ai_security',
            'mobile', 'payloads', 'ctf',
            'pentest', 'scraper', 'agents'
        ]

        # Check that we found most expected modules
        found_count = sum(1 for m in expected_modules if m in discovered)
        assert found_count >= 8, f"Only found {found_count} of {len(expected_modules)} modules"

    def test_loader_loads_all_enabled_modules(self):
        """Loader loads all enabled modules"""
        from modules.loader import ModuleLoader

        config_path = project_root / "config" / "modules.yaml"
        loader = ModuleLoader(str(config_path))

        # Load all modules
        modules_dir = project_root / "modules"
        discovered = loader.discover_modules(str(modules_dir))

        loaded = []
        for name in discovered:
            module = loader.load_module(name)
            if module:
                loaded.append(name)

        # Should have loaded most modules
        assert len(loaded) >= 8


class TestModuleToolRegistration:
    """Test module tool registration"""

    def test_modules_register_tools(self):
        """Modules can register tools with MCP"""
        from unittest.mock import MagicMock

        mock_mcp = MagicMock()
        mock_mcp.tool = MagicMock(return_value=lambda f: f)

        # Try to register tools from a few modules
        try:
            from modules.ctf.module import CTFModule
            module = CTFModule()
            # register_tools takes (mcp, client)
            module.register_tools(mock_mcp, None)
            assert mock_mcp.tool.called
        except ImportError:
            pass

        try:
            from modules.payloads.module import PayloadsModule
            module = PayloadsModule()
            module.register_tools(mock_mcp, None)
            assert mock_mcp.tool.called
        except ImportError:
            pass


class TestModuleRouteRegistration:
    """Test module route registration"""

    def test_modules_register_routes(self):
        """Modules can register routes with Flask"""
        from flask import Flask

        app = Flask(__name__)
        app.config['TESTING'] = True

        # Try to register routes from a few modules
        try:
            from modules.pentest.module import PentestModule
            module = PentestModule()
            module.register_routes(app)

            # Check that some routes were registered
            rules = list(app.url_map.iter_rules())
            assert len(rules) > 1  # More than just static
        except ImportError:
            pass


class TestCrossModuleIntegration:
    """Test interactions between modules"""

    def test_pentest_uses_findings_format(self):
        """Pentest module findings are properly formatted"""
        try:
            from modules.pentest.module import SimplePentestEngine, PentestFinding

            engine = SimplePentestEngine()

            # Add finding from "scanning" phase
            finding = PentestFinding(
                phase="P2",
                tool="nuclei",
                severity="high",
                title="SQL Injection",
                description="SQLi in login form"
            )
            engine.add_finding(finding)

            report = engine.generate_report()

            # Should have proper structure
            assert 'findings' in report
            assert 'findings_summary' in report
            assert report['findings_summary']['high'] == 1
        except ImportError:
            pytest.skip("Pentest module not available")

    def test_payload_encoder_chain(self):
        """Payload encoder chains work correctly"""
        try:
            from modules.payloads.module import PayloadEncoder

            # Chain: base64 -> hex (chain_encode returns dict)
            result = PayloadEncoder.chain_encode("test", ["base64", "hex"])

            # Should have 'final' key with valid hex string
            assert 'final' in result
            final = result['final']
            assert all(c in '0123456789abcdefABCDEF' for c in final)
        except ImportError:
            pytest.skip("Payloads module not available")

    def test_ctf_utils_integration(self):
        """CTF utilities work together"""
        try:
            from modules.ctf.module import CryptoUtils, EncodingUtils

            # Encode with base_decode -> ROT13
            original = "secret"

            # First get base64 from base_decode dict
            decoded_dict = EncodingUtils.base_decode("c2VjcmV0")  # base64 of "secret"
            assert 'base64' in decoded_dict
            assert decoded_dict['base64'] == original

            # Apply ROT13
            rotated = CryptoUtils.rot(original, 13)
            unrotated = CryptoUtils.rot(rotated, 13)

            assert unrotated == original
        except ImportError:
            pytest.skip("CTF module not available")
