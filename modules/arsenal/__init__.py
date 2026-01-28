"""
BlackBox Payloads & Wordlists Module
Unified interface to payload collections.

Collections integrated:
- SecLists - Discovery, fuzzing, passwords
- PayloadsAllTheThings - Attack payloads
- fuzzdb - Fuzzing patterns
"""

from pathlib import Path
from typing import Dict, List, Optional, Generator
import os

BLACKBOX_ROOT = Path(__file__).parent.parent.parent
EXTERNAL_TOOLS = BLACKBOX_ROOT / "external-tools"

SECLISTS_PATH = EXTERNAL_TOOLS / "SecLists"
PAYLOADS_PATH = EXTERNAL_TOOLS / "PayloadsAllTheThings"
FUZZDB_PATH = EXTERNAL_TOOLS / "fuzzdb"


class PayloadsModule:
    """
    Unified payloads and wordlists module.

    Usage:
        payloads = PayloadsModule()
        
        # Get XSS payloads
        for payload in payloads.get_xss_payloads():
            print(payload)
        
        # Get common passwords
        passwords = payloads.get_passwords("common")
        
        # Get fuzzing wordlist
        fuzz = payloads.get_fuzzing_list("sqli")
    """

    def __init__(self):
        self.collections = {
            "seclists": SECLISTS_PATH.exists(),
            "payloads": PAYLOADS_PATH.exists(),
            "fuzzdb": FUZZDB_PATH.exists(),
        }

    def get_available_collections(self) -> List[str]:
        return [c for c, available in self.collections.items() if available]

    def get_wordlist_path(self, category: str, name: str) -> Optional[Path]:
        """Get path to a specific wordlist."""
        paths = {
            ("discovery", "directories"): SECLISTS_PATH / "Discovery" / "Web-Content" / "directory-list-2.3-medium.txt",
            ("discovery", "subdomains"): SECLISTS_PATH / "Discovery" / "DNS" / "subdomains-top1million-5000.txt",
            ("passwords", "common"): SECLISTS_PATH / "Passwords" / "Common-Credentials" / "10-million-password-list-top-1000.txt",
            ("fuzzing", "xss"): SECLISTS_PATH / "Fuzzing" / "XSS" / "XSS-Bypass-Strings-BruteLogic.txt",
            ("fuzzing", "sqli"): SECLISTS_PATH / "Fuzzing" / "SQLi" / "Generic-SQLi.txt",
        }
        
        path = paths.get((category, name))
        if path and path.exists():
            return path
        return None

    def get_xss_payloads(self, limit: int = 100) -> Generator[str, None, None]:
        """Get XSS payloads."""
        path = self.get_wordlist_path("fuzzing", "xss")
        if path:
            with open(path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    yield line.strip()

    def get_sqli_payloads(self, limit: int = 100) -> Generator[str, None, None]:
        """Get SQL injection payloads."""
        path = self.get_wordlist_path("fuzzing", "sqli")
        if path:
            with open(path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    yield line.strip()

    def get_passwords(self, wordlist: str = "common", limit: int = 1000) -> List[str]:
        """Get password wordlist."""
        path = self.get_wordlist_path("passwords", wordlist)
        if not path:
            return []
        
        passwords = []
        with open(path, 'r', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= limit:
                    break
                passwords.append(line.strip())
        return passwords

    def get_directories(self, limit: int = 5000) -> Generator[str, None, None]:
        """Get directory wordlist."""
        path = self.get_wordlist_path("discovery", "directories")
        if path:
            with open(path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    line = line.strip()
                    if line and not line.startswith('#'):
                        yield line

    def list_categories(self) -> Dict[str, List[str]]:
        """List available payload categories."""
        categories = {}
        
        if self.collections.get("seclists"):
            categories["seclists"] = []
            for item in SECLISTS_PATH.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    categories["seclists"].append(item.name)
        
        if self.collections.get("payloads"):
            categories["payloads"] = []
            for item in PAYLOADS_PATH.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    categories["payloads"].append(item.name)
        
        return categories


def create_payloads_module() -> PayloadsModule:
    return PayloadsModule()


__all__ = ["PayloadsModule", "create_payloads_module"]
