"""
Cloud Security Tools Integration
================================
Cloud infrastructure security assessment for AWS, Azure, GCP, and Kubernetes.

Includes:
- Prowler: AWS/Azure/GCP/K8s security scanner (11,000+ stars)

Original: https://github.com/prowler-cloud/prowler
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

EXTERNAL_PATH = Path(__file__).parent.parent.parent / "external-tools"


class CloudProvider(Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class ComplianceFramework(Enum):
    """Compliance frameworks supported by Prowler"""
    CIS = "cis"
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso27001"
    AWS_WELL_ARCHITECTED = "aws_well_architected"
    AWS_AUDIT_MANAGER = "aws_audit_manager"


class Severity(Enum):
    """Finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class CloudFinding:
    """Cloud security finding"""
    check_id: str
    check_title: str
    severity: Severity
    status: str  # PASS, FAIL, MANUAL
    resource_id: str
    resource_arn: Optional[str] = None
    region: str = ""
    account_id: str = ""
    description: str = ""
    risk: str = ""
    remediation: str = ""
    compliance: List[str] = field(default_factory=list)


@dataclass
class CloudSecurityReport:
    """Cloud security assessment report"""
    provider: CloudProvider
    account_id: str
    region: str
    scan_time: str
    total_checks: int
    passed: int
    failed: int
    manual: int
    findings: List[CloudFinding] = field(default_factory=list)
    compliance_summary: Dict[str, Dict] = field(default_factory=dict)


class ProwlerCloudScanner:
    """
    Prowler - Cloud Security Assessment Tool.

    Open Source Security tool for AWS, Azure, GCP, and Kubernetes.
    Performs security assessments, audits, incident response, compliance,
    continuous monitoring, and hardening.

    Original: https://github.com/prowler-cloud/prowler (11,000+ stars)

    Features:
    - 300+ security checks for AWS
    - 200+ security checks for Azure
    - 100+ security checks for GCP
    - Kubernetes security assessment
    - Compliance mapping (CIS, SOC2, HIPAA, GDPR, PCI-DSS, etc.)
    - Multiple output formats (JSON, CSV, HTML)

    Example:
        prowler = ProwlerCloudScanner()
        report = prowler.scan_aws(profile="default", region="us-east-1")
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
    """

    def __init__(self, prowler_path: Optional[Path] = None):
        self.prowler_path = prowler_path or EXTERNAL_PATH / "prowler"

    def _run_prowler(self, *args, **kwargs) -> subprocess.CompletedProcess:
        """Run prowler command"""
        cmd = ["prowler"] + list(args)
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(self.prowler_path) if self.prowler_path.exists() else None,
            **kwargs
        )

    def scan_aws(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        checks: Optional[List[str]] = None,
        compliance: Optional[ComplianceFramework] = None,
        severity: Optional[Severity] = None,
        output_format: str = "json"
    ) -> CloudSecurityReport:
        """
        Scan AWS account for security issues.

        Args:
            profile: AWS CLI profile name
            region: AWS region to scan
            checks: Specific checks to run (e.g., ["iam_1", "s3_2"])
            compliance: Compliance framework to check against
            severity: Minimum severity to report
            output_format: Output format (json, csv, html)

        Returns:
            CloudSecurityReport with findings
        """
        args = ["aws"]

        if profile:
            args.extend(["--profile", profile])
        if region:
            args.extend(["--region", region])
        if checks:
            args.extend(["--checks", ",".join(checks)])
        if compliance:
            args.extend(["--compliance", compliance.value])
        if severity:
            args.extend(["--severity", severity.value])
        args.extend(["--output-format", output_format])
        args.extend(["--output-filename", "prowler_output"])

        result = self._run_prowler(*args)

        return self._parse_report(result.stdout, CloudProvider.AWS)

    def scan_azure(
        self,
        subscription_id: Optional[str] = None,
        compliance: Optional[ComplianceFramework] = None,
        severity: Optional[Severity] = None
    ) -> CloudSecurityReport:
        """
        Scan Azure subscription for security issues.

        Args:
            subscription_id: Azure subscription ID
            compliance: Compliance framework to check against
            severity: Minimum severity to report

        Returns:
            CloudSecurityReport with findings
        """
        args = ["azure"]

        if subscription_id:
            args.extend(["--subscription-id", subscription_id])
        if compliance:
            args.extend(["--compliance", compliance.value])
        if severity:
            args.extend(["--severity", severity.value])
        args.extend(["--output-format", "json"])

        result = self._run_prowler(*args)

        return self._parse_report(result.stdout, CloudProvider.AZURE)

    def scan_gcp(
        self,
        project_id: Optional[str] = None,
        compliance: Optional[ComplianceFramework] = None,
        severity: Optional[Severity] = None
    ) -> CloudSecurityReport:
        """
        Scan GCP project for security issues.

        Args:
            project_id: GCP project ID
            compliance: Compliance framework to check against
            severity: Minimum severity to report

        Returns:
            CloudSecurityReport with findings
        """
        args = ["gcp"]

        if project_id:
            args.extend(["--project-id", project_id])
        if compliance:
            args.extend(["--compliance", compliance.value])
        if severity:
            args.extend(["--severity", severity.value])
        args.extend(["--output-format", "json"])

        result = self._run_prowler(*args)

        return self._parse_report(result.stdout, CloudProvider.GCP)

    def scan_kubernetes(
        self,
        kubeconfig: Optional[str] = None,
        context: Optional[str] = None,
        namespace: Optional[str] = None
    ) -> CloudSecurityReport:
        """
        Scan Kubernetes cluster for security issues.

        Args:
            kubeconfig: Path to kubeconfig file
            context: Kubernetes context to use
            namespace: Namespace to scan (default: all)

        Returns:
            CloudSecurityReport with findings
        """
        args = ["kubernetes"]

        if kubeconfig:
            args.extend(["--kubeconfig", kubeconfig])
        if context:
            args.extend(["--context", context])
        if namespace:
            args.extend(["--namespace", namespace])
        args.extend(["--output-format", "json"])

        result = self._run_prowler(*args)

        return self._parse_report(result.stdout, CloudProvider.KUBERNETES)

    def _parse_report(self, output: str, provider: CloudProvider) -> CloudSecurityReport:
        """Parse Prowler JSON output into report"""
        report = CloudSecurityReport(
            provider=provider,
            account_id="",
            region="",
            scan_time="",
            total_checks=0,
            passed=0,
            failed=0,
            manual=0
        )

        try:
            for line in output.strip().split("\n"):
                if not line:
                    continue
                finding_data = json.loads(line)

                finding = CloudFinding(
                    check_id=finding_data.get("CheckID", ""),
                    check_title=finding_data.get("CheckTitle", ""),
                    severity=Severity(finding_data.get("Severity", "low").lower()),
                    status=finding_data.get("Status", ""),
                    resource_id=finding_data.get("ResourceId", ""),
                    resource_arn=finding_data.get("ResourceArn"),
                    region=finding_data.get("Region", ""),
                    account_id=finding_data.get("AccountId", ""),
                    description=finding_data.get("Description", ""),
                    risk=finding_data.get("Risk", ""),
                    remediation=finding_data.get("Remediation", ""),
                    compliance=finding_data.get("Compliance", [])
                )

                report.findings.append(finding)
                report.total_checks += 1

                if finding.status == "PASS":
                    report.passed += 1
                elif finding.status == "FAIL":
                    report.failed += 1
                else:
                    report.manual += 1

        except json.JSONDecodeError:
            report.findings = []

        return report

    def list_checks(self, provider: CloudProvider) -> List[Dict]:
        """
        List available security checks for a provider.

        Args:
            provider: Cloud provider

        Returns:
            List of available checks
        """
        result = self._run_prowler(provider.value, "--list-checks")
        return result.stdout

    def list_compliance_frameworks(self, provider: CloudProvider) -> List[str]:
        """
        List available compliance frameworks.

        Args:
            provider: Cloud provider

        Returns:
            List of compliance frameworks
        """
        result = self._run_prowler(provider.value, "--list-compliance")
        return result.stdout.strip().split("\n")

    @staticmethod
    def get_aws_check_categories() -> Dict[str, List[str]]:
        """AWS security check categories"""
        return {
            "IAM": [
                "iam_root_hardware_mfa_enabled",
                "iam_no_root_access_key",
                "iam_password_policy_minimum_length_14",
                "iam_user_mfa_enabled_console_access",
            ],
            "S3": [
                "s3_bucket_public_access",
                "s3_bucket_default_encryption",
                "s3_bucket_logging_enabled",
                "s3_bucket_versioning_enabled",
            ],
            "EC2": [
                "ec2_security_group_default_restrict_traffic",
                "ec2_ebs_volume_encryption",
                "ec2_instance_imdsv2_enabled",
            ],
            "CloudTrail": [
                "cloudtrail_enabled",
                "cloudtrail_log_file_validation_enabled",
                "cloudtrail_multi_region_enabled",
            ],
            "RDS": [
                "rds_instance_public_access",
                "rds_instance_encryption_enabled",
                "rds_instance_backup_enabled",
            ],
            "Lambda": [
                "lambda_function_no_secrets_in_variables",
                "lambda_function_url_auth_type",
            ],
        }

    @staticmethod
    def get_compliance_mapping() -> Dict[str, str]:
        """Compliance framework descriptions"""
        return {
            "cis_aws": "CIS Amazon Web Services Foundations Benchmark",
            "cis_azure": "CIS Microsoft Azure Foundations Benchmark",
            "cis_gcp": "CIS Google Cloud Platform Foundation Benchmark",
            "cis_kubernetes": "CIS Kubernetes Benchmark",
            "soc2": "SOC 2 Type II",
            "hipaa": "Health Insurance Portability and Accountability Act",
            "gdpr": "General Data Protection Regulation",
            "pci_dss": "Payment Card Industry Data Security Standard",
            "nist_800_53": "NIST Special Publication 800-53",
            "iso27001": "ISO/IEC 27001:2013",
            "aws_well_architected": "AWS Well-Architected Framework",
        }
