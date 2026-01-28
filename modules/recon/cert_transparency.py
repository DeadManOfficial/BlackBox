"""
Certificate Transparency Log Subdomain Enumeration

Queries crt.sh to discover subdomains from SSL certificate transparency logs.
Inspired by 0nsec/crt.sh - integrated into BlackBox.

Usage:
    from blackbox.modules.recon.cert_transparency import CertTransparency

    ct = CertTransparency()
    results = ct.enumerate("example.com")
    print(results.subdomains)
"""

import json
import re
import time
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any
from pathlib import Path


@dataclass
class CTResult:
    """Result from Certificate Transparency lookup."""
    domain: str
    subdomains: Set[str] = field(default_factory=set)
    related_domains: Set[str] = field(default_factory=set)
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    raw_data: List[Dict] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    query_time: float = 0.0


class CertTransparency:
    """
    Certificate Transparency Log enumeration using crt.sh.

    Discovers subdomains and related domains from public SSL certificate
    transparency logs. This is a passive reconnaissance technique that
    doesn't touch the target directly.

    Attributes:
        base_url: crt.sh API endpoint
        delay: Delay between requests (rate limiting)
        timeout: Request timeout in seconds
    """

    def __init__(
        self,
        delay: float = 1.0,
        timeout: int = 30,
        user_agent: str = "BlackBox/5.3 Security Research"
    ):
        self.base_url = "https://crt.sh"
        self.delay = delay
        self.timeout = timeout
        self.user_agent = user_agent
        self._last_request = 0.0

    def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()

    def _make_request(self, url: str) -> Optional[str]:
        """Make HTTP request with error handling."""
        self._rate_limit()

        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent}
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return response.read().decode('utf-8')
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Rate limited - back off and retry
                time.sleep(5)
                return self._make_request(url)
            raise
        except urllib.error.URLError:
            return None

    def enumerate(
        self,
        domain: str,
        include_expired: bool = True,
        deduplicate: bool = True
    ) -> CTResult:
        """
        Enumerate subdomains from certificate transparency logs.

        Args:
            domain: Target domain to enumerate
            include_expired: Include expired certificates
            deduplicate: Remove duplicate entries

        Returns:
            CTResult with discovered subdomains
        """
        start_time = time.time()
        result = CTResult(domain=domain)

        try:
            # Query crt.sh JSON API
            params = {
                "q": f"%.{domain}",
                "output": "json"
            }
            if not include_expired:
                params["exclude"] = "expired"

            url = f"{self.base_url}/?{urllib.parse.urlencode(params)}"
            response = self._make_request(url)

            if not response:
                result.error = "No response from crt.sh"
                return result

            # Parse JSON response
            try:
                data = json.loads(response)
            except json.JSONDecodeError:
                # Sometimes returns HTML error page
                result.error = "Invalid JSON response"
                return result

            if not data:
                result.success = True
                result.query_time = time.time() - start_time
                return result

            result.raw_data = data

            # Extract domains from certificates
            seen_names = set()
            for cert in data:
                common_name = cert.get("common_name", "")
                name_value = cert.get("name_value", "")

                # Extract all names from certificate
                names = set()
                if common_name:
                    names.add(common_name.lower())
                if name_value:
                    # name_value can contain multiple domains separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name:
                            names.add(name)

                for name in names:
                    if name in seen_names and deduplicate:
                        continue
                    seen_names.add(name)

                    # Clean wildcard prefixes
                    clean_name = name.lstrip("*.")

                    # Categorize as subdomain or related domain
                    if clean_name.endswith(f".{domain}") or clean_name == domain:
                        result.subdomains.add(clean_name)
                    else:
                        result.related_domains.add(clean_name)

                # Store certificate info
                result.certificates.append({
                    "id": cert.get("id"),
                    "issuer": cert.get("issuer_name"),
                    "common_name": common_name,
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                    "names": list(names)
                })

            result.success = True
            result.query_time = time.time() - start_time

        except Exception as e:
            result.error = str(e)

        return result

    def enumerate_multiple(
        self,
        domains: List[str],
        delay_between: float = 2.0
    ) -> Dict[str, CTResult]:
        """
        Enumerate multiple domains with rate limiting.

        Args:
            domains: List of domains to enumerate
            delay_between: Delay between domain queries

        Returns:
            Dict mapping domain to CTResult
        """
        results = {}

        for i, domain in enumerate(domains):
            if i > 0:
                time.sleep(delay_between)
            results[domain] = self.enumerate(domain)

        return results

    def find_wildcards(self, domain: str) -> Set[str]:
        """
        Find wildcard certificates for a domain.

        Args:
            domain: Target domain

        Returns:
            Set of wildcard certificate patterns
        """
        result = self.enumerate(domain, deduplicate=False)
        wildcards = set()

        for cert in result.raw_data:
            name = cert.get("common_name", "")
            if name.startswith("*."):
                wildcards.add(name)

            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                if name.strip().startswith("*."):
                    wildcards.add(name.strip())

        return wildcards

    def get_certificate_history(self, domain: str) -> List[Dict]:
        """
        Get historical certificate issuance for a domain.

        Args:
            domain: Target domain

        Returns:
            List of certificates ordered by issuance date
        """
        result = self.enumerate(domain)

        # Sort by not_before date
        certs = sorted(
            result.certificates,
            key=lambda x: x.get("not_before", ""),
            reverse=True
        )

        return certs

    def export_results(
        self,
        result: CTResult,
        output_path: Path,
        format: str = "json"
    ) -> None:
        """
        Export results to file.

        Args:
            result: CTResult to export
            output_path: Output file path
            format: Output format (json or txt)
        """
        output_path = Path(output_path)

        if format == "json":
            data = {
                "domain": result.domain,
                "subdomains": sorted(result.subdomains),
                "related_domains": sorted(result.related_domains),
                "certificate_count": len(result.certificates),
                "query_time": result.query_time
            }
            output_path.write_text(json.dumps(data, indent=2))

        elif format == "txt":
            lines = [
                f"# Certificate Transparency Results for {result.domain}",
                f"# Subdomains: {len(result.subdomains)}",
                f"# Related: {len(result.related_domains)}",
                "",
                "## Subdomains",
                *sorted(result.subdomains),
                "",
                "## Related Domains",
                *sorted(result.related_domains)
            ]
            output_path.write_text("\n".join(lines))


# Convenience function
def enumerate_ct(domain: str) -> CTResult:
    """Quick certificate transparency enumeration."""
    ct = CertTransparency()
    return ct.enumerate(domain)


__all__ = ["CertTransparency", "CTResult", "enumerate_ct"]
