#!/usr/bin/env python3
"""
BlackBox AI - Pytest Configuration and Fixtures
================================================

Common fixtures for all tests.
"""

import pytest
import sys
import os
from pathlib import Path
from typing import Dict, Any, Optional
from unittest.mock import MagicMock, patch

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


# ============================================================
# MOCK TOOL WRAPPER
# ============================================================

class MockToolWrapper:
    """Mock wrapper for external CLI tools"""

    def __init__(self, tool_name: str, responses: Optional[Dict[str, Any]] = None):
        self.tool_name = tool_name
        self.responses = responses or {}
        self.calls = []
        self._available = True

    def is_available(self) -> bool:
        return self._available

    def set_available(self, available: bool):
        self._available = available

    def execute(self, **kwargs) -> 'MockResult':
        """Mock tool execution"""
        self.calls.append(kwargs)

        # Check for predefined response
        key = kwargs.get('target') or kwargs.get('query') or 'default'
        if key in self.responses:
            return MockResult(
                success=True,
                stdout=self.responses[key].get('stdout', ''),
                parsed_data=self.responses[key].get('parsed', {})
            )

        # Default successful response
        return MockResult(
            success=True,
            stdout=f"Mock {self.tool_name} output",
            parsed_data={'mock': True, 'tool': self.tool_name}
        )


class MockResult:
    """Mock result from tool execution"""

    def __init__(self, success: bool = True, stdout: str = '', stderr: str = '',
                 parsed_data: Optional[Dict] = None, error_message: str = ''):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.parsed_data = parsed_data or {}
        self.error_message = error_message


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def mock_nmap():
    """Mock nmap wrapper"""
    return MockToolWrapper('nmap', {
        'localhost': {
            'stdout': 'Nmap scan report for localhost\nPORT STATE SERVICE\n22/tcp open ssh',
            'parsed': {
                'ports': [
                    {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh'}
                ]
            }
        },
        'example.com': {
            'stdout': 'Nmap scan report for example.com',
            'parsed': {
                'ports': [
                    {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http'},
                    {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https'}
                ]
            }
        }
    })


@pytest.fixture
def mock_nuclei():
    """Mock nuclei wrapper"""
    return MockToolWrapper('nuclei', {
        'example.com': {
            'parsed': {
                'findings': [
                    {
                        'template': 'http-missing-security-headers',
                        'severity': 'info',
                        'host': 'example.com'
                    }
                ],
                'total': 1
            }
        }
    })


@pytest.fixture
def mock_gobuster():
    """Mock gobuster wrapper"""
    return MockToolWrapper('gobuster', {
        'https://example.com': {
            'parsed': {
                'directories': [
                    {'path': '/admin', 'status': 403},
                    {'path': '/api', 'status': 200},
                    {'path': '/login', 'status': 200}
                ]
            }
        }
    })


@pytest.fixture
def mock_sqlmap():
    """Mock sqlmap wrapper"""
    return MockToolWrapper('sqlmap', {
        'default': {
            'parsed': {
                'vulnerable': True,
                'injection_type': 'boolean-based blind',
                'parameter': 'id'
            }
        }
    })


@pytest.fixture
def temp_config(tmp_path):
    """Create temporary config directory"""
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    # Create modules.yaml
    modules_yaml = config_dir / "modules.yaml"
    modules_yaml.write_text("""
modules:
  core_scanning:
    enabled: true
    tools:
      nmap: {timeout: 300}
      nuclei: {severity: "high,critical"}

  test_module:
    enabled: true
    custom_setting: "test_value"
""")

    return config_dir


@pytest.fixture
def module_loader(temp_config):
    """Create module loader with temp config"""
    from modules.loader import ModuleLoader
    loader = ModuleLoader(str(temp_config / "modules.yaml"))
    return loader


@pytest.fixture
def mock_mcp():
    """Mock MCP server for tool registration"""
    mcp = MagicMock()
    mcp.tool = MagicMock(return_value=lambda f: f)
    return mcp


@pytest.fixture
def mock_flask_app():
    """Mock Flask app for route registration"""
    from flask import Flask
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


@pytest.fixture
def cli_runner():
    """Click CLI test runner"""
    from click.testing import CliRunner
    return CliRunner()


# ============================================================
# TEST DATA FIXTURES
# ============================================================

@pytest.fixture
def sample_ports_data():
    """Sample port scan data"""
    return {
        'ports': [
            {'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh'},
            {'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http'},
            {'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https'},
            {'port': 3306, 'protocol': 'tcp', 'state': 'open', 'service': 'mysql'}
        ]
    }


@pytest.fixture
def sample_vuln_data():
    """Sample vulnerability data"""
    return {
        'findings': [
            {
                'id': 'CVE-2024-1234',
                'severity': 'critical',
                'title': 'Remote Code Execution',
                'description': 'Test vulnerability',
                'cvss': 9.8
            },
            {
                'id': 'CVE-2024-5678',
                'severity': 'high',
                'title': 'SQL Injection',
                'description': 'SQL injection in login form',
                'cvss': 8.5
            }
        ]
    }


@pytest.fixture
def sample_pentest_finding():
    """Sample pentest finding"""
    return {
        'phase': 'P2',
        'tool': 'nuclei',
        'severity': 'high',
        'title': 'Missing Security Headers',
        'description': 'X-Frame-Options header is missing',
        'evidence': 'HTTP/1.1 200 OK\nServer: nginx',
        'remediation': 'Add X-Frame-Options: DENY header'
    }


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def assert_tool_registered(mock_mcp, tool_name: str):
    """Assert that a tool was registered with MCP"""
    # Check if tool decorator was called
    assert mock_mcp.tool.called, f"No tools registered with MCP"


def assert_route_registered(app, endpoint: str, methods: list = None):
    """Assert that a route was registered with Flask"""
    methods = methods or ['GET']
    rules = list(app.url_map.iter_rules())
    matching = [r for r in rules if r.endpoint == endpoint.lstrip('/').replace('/', '_')]
    assert matching, f"Route {endpoint} not registered"
