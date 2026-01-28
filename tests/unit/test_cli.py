#!/usr/bin/env python3
"""
Unit Tests - CLI
================

Tests for the BlackBox CLI interface.
"""

import pytest
import sys
from pathlib import Path
from click.testing import CliRunner

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestCLIBasic:
    """Basic CLI tests"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_cli_help(self, runner):
        """CLI shows help"""
        from cli.main import cli

        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'BlackBox AI' in result.output or 'Usage' in result.output

    def test_cli_version(self, runner):
        """CLI shows version"""
        from cli.main import cli

        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert '1.0.0' in result.output

    def test_cli_quiet_mode(self, runner):
        """CLI quiet mode suppresses banner"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', '--help'])
        assert result.exit_code == 0


class TestModulesCommand:
    """Tests for modules command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_modules_list(self, runner):
        """modules list shows modules"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'modules', 'list'])
        # Should not error
        assert result.exit_code == 0

    def test_modules_info(self, runner):
        """modules info shows module details"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'modules', 'info', 'core_scanning'])
        # Should not error even if module doesn't exist
        assert result.exit_code == 0


class TestCTFCommand:
    """Tests for CTF command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_ctf_decode_base64(self, runner):
        """ctf decode handles base64"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'ctf', 'decode', 'SGVsbG8gV29ybGQh'])
        assert result.exit_code == 0
        assert 'Hello World!' in result.output

    def test_ctf_hash(self, runner):
        """ctf hash generates hashes"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'ctf', 'hash', 'test'])
        assert result.exit_code == 0
        assert 'MD5' in result.output or 'md5' in result.output.lower()
        # MD5 of "test" is 098f6bcd4621d373cade4e832627b4f6
        assert '098f6bcd' in result.output

    def test_ctf_identify(self, runner):
        """ctf identify identifies hash types"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'ctf', 'identify', 'd41d8cd98f00b204e9800998ecf8427e'])
        assert result.exit_code == 0


class TestPayloadsCommand:
    """Tests for payloads command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_payloads_list(self, runner):
        """payloads list shows templates"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'payloads', 'list'])
        assert result.exit_code == 0
        assert 'reverse_shell' in result.output or 'shellcode' in result.output.lower() or 'template' in result.output.lower()

    def test_payloads_encode(self, runner):
        """payloads encode encodes payload"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'payloads', 'encode', 'test', '-e', 'base64'])
        assert result.exit_code == 0
        assert 'dGVzdA==' in result.output

    def test_payloads_shellcode(self, runner):
        """payloads shellcode generates code"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'payloads', 'shellcode', 'reverse_shell_bash',
                                     '--lhost', '10.0.0.1', '--lport', '4444'])
        assert result.exit_code == 0
        assert '10.0.0.1' in result.output


class TestAgentCommand:
    """Tests for agent command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_agent_list(self, runner):
        """agent list shows agents"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'agent', 'list'])
        assert result.exit_code == 0
        assert 'penetration-tester' in result.output or 'Agent' in result.output

    def test_agent_show(self, runner):
        """agent show shows agent details"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'agent', 'show', 'penetration-tester'])
        assert result.exit_code == 0


class TestPentestCommand:
    """Tests for pentest command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_pentest_status(self, runner):
        """pentest status shows current state"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'pentest', 'status'])
        assert result.exit_code == 0


class TestScanCommand:
    """Tests for scan command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_scan_help(self, runner):
        """scan group shows help"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'scan', '--help'])
        assert result.exit_code == 0
        assert 'nuclei' in result.output or 'scan' in result.output.lower()


class TestReconCommand:
    """Tests for recon command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_recon_help(self, runner):
        """recon group shows help"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'recon', '--help'])
        assert result.exit_code == 0


class TestWebCommand:
    """Tests for web command group"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_web_help(self, runner):
        """web group shows help"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', 'web', '--help'])
        assert result.exit_code == 0


class TestOutputFormats:
    """Tests for output format options"""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_json_output(self, runner):
        """JSON output format works"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', '-o', 'json', 'ctf', 'hash', 'test'])
        # Should not error
        assert result.exit_code == 0

    def test_table_output(self, runner):
        """Table output format works"""
        from cli.main import cli

        result = runner.invoke(cli, ['-q', '-o', 'table', 'modules', 'list'])
        # Should not error
        assert result.exit_code == 0
