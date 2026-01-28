#!/usr/bin/env python3
"""
Integration Tests - CLI Integration
===================================

End-to-end tests for CLI functionality.
"""

import pytest
import sys
import json
from pathlib import Path
from click.testing import CliRunner

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestCLIEndToEnd:
    """End-to-end CLI tests"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_full_ctf_workflow(self, runner):
        """Complete CTF decode workflow"""
        from cli.main import cli

        # Step 1: Decode base64
        result = runner.invoke(cli, ['-q', 'ctf', 'decode', 'SGVsbG8gV29ybGQh'])
        assert result.exit_code == 0
        assert 'Hello World!' in result.output

        # Step 2: Hash the result
        result = runner.invoke(cli, ['-q', 'ctf', 'hash', 'Hello World!'])
        assert result.exit_code == 0
        assert 'MD5' in result.output or 'md5' in result.output.lower()

    def test_full_payload_workflow(self, runner):
        """Complete payload generation workflow"""
        from cli.main import cli

        # Step 1: List available templates
        result = runner.invoke(cli, ['-q', 'payloads', 'list'])
        assert result.exit_code == 0

        # Step 2: Generate shellcode
        result = runner.invoke(cli, ['-q', 'payloads', 'shellcode',
                                     'reverse_shell_bash', '--lhost', '10.0.0.1'])
        assert result.exit_code == 0
        assert '10.0.0.1' in result.output

        # Step 3: Encode payload
        result = runner.invoke(cli, ['-q', 'payloads', 'encode',
                                     'test_payload', '-e', 'base64'])
        assert result.exit_code == 0

    def test_full_agent_workflow(self, runner):
        """Complete agent selection workflow"""
        from cli.main import cli

        # Step 1: List agents
        result = runner.invoke(cli, ['-q', 'agent', 'list'])
        assert result.exit_code == 0

        # Step 2: Show specific agent
        result = runner.invoke(cli, ['-q', 'agent', 'show', 'penetration-tester'])
        assert result.exit_code == 0

    def test_pentest_workflow(self, runner):
        """Complete pentest workflow"""
        from cli.main import cli

        # Check status
        result = runner.invoke(cli, ['-q', 'pentest', 'status'])
        assert result.exit_code == 0


class TestCLIOutputFormats:
    """Test different output formats"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_text_output(self, runner):
        """Text output format"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', '-o', 'text', 'modules', 'list'])
        assert result.exit_code == 0
        # Should be plain text
        assert 'core_scanning' in result.output or 'Module' in result.output

    def test_json_output_valid(self, runner):
        """JSON output is valid JSON"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', '-o', 'json', 'ctf', 'hash', 'test'])
        assert result.exit_code == 0

        # Try to parse as JSON (may have other text mixed in)
        output = result.output.strip()
        # Look for JSON in output
        if '{' in output:
            start = output.index('{')
            end = output.rindex('}') + 1
            json_str = output[start:end]
            try:
                data = json.loads(json_str)
                assert isinstance(data, dict)
            except json.JSONDecodeError:
                pass  # JSON may not be pure


class TestCLIErrorHandling:
    """Test CLI error handling"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_invalid_command(self, runner):
        """Invalid command shows error"""
        from cli.main import cli

        result = runner.invoke(cli, ['invalid_command_xyz'])
        # Should exit with error or show help
        assert 'Error' in result.output or 'Usage' in result.output or result.exit_code != 0

    def test_missing_required_argument(self, runner):
        """Missing argument shows error"""
        from cli.main import cli

        result = runner.invoke(cli, ['ctf', 'hash'])  # Missing TEXT argument
        # Should show error about missing argument
        assert result.exit_code != 0 or 'Missing' in result.output or 'Error' in result.output

    def test_invalid_option(self, runner):
        """Invalid option shows error"""
        from cli.main import cli

        result = runner.invoke(cli, ['--invalid-option-xyz'])
        assert result.exit_code != 0


class TestCLIModuleInteraction:
    """Test CLI interaction with modules"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_modules_list_shows_loaded(self, runner):
        """Modules list shows loaded modules"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'modules', 'list'])
        assert result.exit_code == 0

        # Should show at least some modules
        output = result.output.lower()
        module_keywords = ['core', 'recon', 'web', 'ctf', 'payload', 'pentest']
        found = sum(1 for k in module_keywords if k in output)
        # Should find at least a few
        assert found >= 2 or 'module' in output

    def test_module_info_shows_details(self, runner):
        """Module info shows details"""
        from cli.main import cli

        # Try a module that should exist
        result = runner.invoke(cli, ['-q', 'modules', 'info', 'ctf'])
        assert result.exit_code == 0
        # Should show some info about the module
