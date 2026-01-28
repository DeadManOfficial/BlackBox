"""
vFeed CVE Database Integration
==============================
Correlated Vulnerability & Threat Database with CVE, CPE, CWE, OVAL mappings.

Original: https://github.com/toolswatch/vFeed (946 stars)
"""

import subprocess
import json
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

VFEED_PATH = Path(__file__).parent.parent.parent / "external-tools" / "vFeed"


class SearchType(Enum):
    """vFeed search types"""
    CVE = "cve"
    CPE = "cpe"
    CWE = "cwe"
    OVAL = "oval"
    TEXT = "text"


@dataclass
class CVEEntry:
    """CVE vulnerability entry"""
    cve_id: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    cpe_entries: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    exploits: List[Dict] = field(default_factory=list)
    patches: List[Dict] = field(default_factory=list)


class VFeedCVEDatabase:
    """
    vFeed Correlated Vulnerability & Threat Database.

    Features:
    - CVE search and lookup
    - CPE (product) vulnerability mapping
    - CWE weakness classification
    - OVAL definition lookup
    - Exploit and patch correlation
    - MongoDB migration support

    Example:
        vfeed = VFeedCVEDatabase()
        cve = vfeed.get_cve("CVE-2024-1234")
        print(cve.cvss_score, cve.exploits)
    """

    def __init__(self, vfeed_path: Optional[Path] = None):
        self.vfeed_path = vfeed_path or VFEED_PATH

        if not self.vfeed_path.exists():
            raise FileNotFoundError(f"vFeed not found at {self.vfeed_path}")

    def _run_vfeed(self, *args) -> subprocess.CompletedProcess:
        """Run vFeed CLI command"""
        cmd = [sys.executable, str(self.vfeed_path / "vfeedcli.py")] + list(args)
        return subprocess.run(
            cmd,
            cwd=str(self.vfeed_path),
            capture_output=True,
            text=True
        )

    def search(self, search_type: SearchType, query: str) -> str:
        """
        Search vFeed database.

        Args:
            search_type: Type of search (cve, cpe, cwe, oval, text)
            query: Search query

        Returns:
            Search results as string
        """
        result = self._run_vfeed("-s", search_type.value, query)
        return result.stdout

    def get_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """
        Get detailed CVE information.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            CVEEntry with full vulnerability details
        """
        result = self._run_vfeed("-e", "json_dump", cve_id)

        if result.returncode != 0:
            return None

        try:
            data = json.loads(result.stdout)
            return CVEEntry(
                cve_id=cve_id,
                description=data.get("description", ""),
                cvss_score=data.get("cvss", {}).get("score"),
                cvss_vector=data.get("cvss", {}).get("vector", ""),
                cwe_ids=data.get("cwe", []),
                cpe_entries=data.get("cpe", []),
                references=data.get("references", []),
                exploits=data.get("exploits", []),
                patches=data.get("patches", [])
            )
        except json.JSONDecodeError:
            return CVEEntry(cve_id=cve_id, description=result.stdout)

    def search_cve(self, query: str) -> str:
        """Search for CVEs by ID pattern"""
        return self.search(SearchType.CVE, query)

    def search_cpe(self, product: str) -> str:
        """Search for vulnerabilities by CPE/product"""
        return self.search(SearchType.CPE, product)

    def search_cwe(self, cwe_id: str) -> str:
        """Search for CVEs by CWE weakness"""
        return self.search(SearchType.CWE, cwe_id)

    def search_text(self, text: str) -> str:
        """Free text search across all fields"""
        return self.search(SearchType.TEXT, text)

    def get_method(self, method: str, cve_id: str) -> str:
        """
        Invoke vFeed built-in method.

        Available methods:
        - get_cve: Basic CVE info
        - get_cvss: CVSS scores
        - get_cwe: CWE mappings
        - get_cpe: CPE entries
        - get_refs: References
        - get_exploits: Exploit references
        - get_patches: Patch information
        """
        result = self._run_vfeed("-m", method, cve_id)
        return result.stdout

    def export_json(self, cve_id: str) -> Dict[str, Any]:
        """Export CVE data as JSON"""
        result = self._run_vfeed("-e", "json_dump", cve_id)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"error": result.stdout, "cve_id": cve_id}

    def get_stats(self) -> str:
        """Get database statistics"""
        result = self._run_vfeed("--stats", "get_stats")
        return result.stdout

    def get_latest(self) -> str:
        """Get latest CVE entries"""
        result = self._run_vfeed("--stats", "get_latest")
        return result.stdout

    def update_database(self) -> subprocess.CompletedProcess:
        """Update vFeed database"""
        return self._run_vfeed("-u")

    def list_methods(self) -> str:
        """List available vFeed methods"""
        result = self._run_vfeed("--list")
        return result.stdout

    @staticmethod
    def available_methods() -> List[str]:
        """List of known vFeed methods"""
        return [
            "get_cve",
            "get_cvss",
            "get_cwe",
            "get_cpe",
            "get_refs",
            "get_exploits",
            "get_patches",
            "get_oval",
            "get_nessus",
            "get_openvas",
            "get_snort",
            "get_suricata",
            "get_msf",
            "get_saint",
            "get_d2",
        ]
