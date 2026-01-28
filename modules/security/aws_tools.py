"""
AWS Security Tools Integration
Integrates Pacu, CloudFox, and other AWS exploitation tools

Usage:
    from modules.security.aws_tools import AWSTools

    aws = AWSTools()
    aws.validate_credentials(access_key, secret_key)
    aws.enumerate_permissions(access_key, secret_key)
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Optional, Dict, List, Any


class AWSTools:
    """AWS security testing toolkit."""

    def __init__(self):
        self.cloudfox_path = Path(__file__).parent.parent.parent / "external-tools" / "cloudfox" / "cloudfox"
        self.pacu_available = self._check_pacu()
        self.cloudfox_available = self.cloudfox_path.exists()

    def _check_pacu(self) -> bool:
        """Check if Pacu is available."""
        try:
            result = subprocess.run(["pacu", "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def validate_credentials(self, access_key: str, secret_key: str, session_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Validate AWS credentials using sts:GetCallerIdentity.

        Returns:
            Dict with account info or error
        """
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = access_key
        env["AWS_SECRET_ACCESS_KEY"] = secret_key
        if session_token:
            env["AWS_SESSION_TOKEN"] = session_token

        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--output", "json"],
                capture_output=True,
                env=env,
                timeout=30
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {
                    "valid": True,
                    "account": data.get("Account"),
                    "arn": data.get("Arn"),
                    "user_id": data.get("UserId")
                }
            else:
                return {
                    "valid": False,
                    "error": result.stderr.decode()
                }
        except FileNotFoundError:
            return {
                "valid": False,
                "error": "AWS CLI not installed"
            }
        except Exception as e:
            return {
                "valid": False,
                "error": str(e)
            }

    def run_cloudfox(self, profile: str, command: str = "all-checks") -> Dict[str, Any]:
        """
        Run CloudFox for AWS enumeration.

        Args:
            profile: AWS profile name
            command: CloudFox command (all-checks, permissions, iam-simulator, etc.)

        Returns:
            Dict with results or error
        """
        if not self.cloudfox_available:
            return {"error": "CloudFox not found"}

        try:
            result = subprocess.run(
                [str(self.cloudfox_path), "aws", "--profile", profile, command],
                capture_output=True,
                timeout=300
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout.decode(),
                "errors": result.stderr.decode()
            }
        except Exception as e:
            return {"error": str(e)}

    def run_pacu_module(self, session: str, module: str, args: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a Pacu module.

        Args:
            session: Pacu session name
            module: Module name (e.g., iam__bruteforce_permissions)
            args: Optional module arguments

        Returns:
            Dict with results
        """
        if not self.pacu_available:
            return {"error": "Pacu not installed"}

        cmd = ["pacu", "--session", session, "--module-name", module]
        if args:
            cmd.extend(["--module-args", args])

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=600)
            return {
                "success": result.returncode == 0,
                "output": result.stdout.decode(),
                "errors": result.stderr.decode()
            }
        except Exception as e:
            return {"error": str(e)}

    def get_privilege_escalation_paths(self) -> List[Dict[str, str]]:
        """Get known AWS privilege escalation techniques."""
        return [
            {
                "technique": "CreateAccessKey",
                "permission": "iam:CreateAccessKey",
                "impact": "Create access keys for other users"
            },
            {
                "technique": "CreatePolicyVersion",
                "permission": "iam:CreatePolicyVersion",
                "impact": "Modify policy to grant admin access"
            },
            {
                "technique": "AttachUserPolicy",
                "permission": "iam:AttachUserPolicy",
                "impact": "Attach admin policy to self"
            },
            {
                "technique": "PassRole",
                "permission": "iam:PassRole + service",
                "impact": "Pass role to service for privilege escalation"
            },
            {
                "technique": "UpdateLoginProfile",
                "permission": "iam:UpdateLoginProfile",
                "impact": "Change password for console access"
            },
            {
                "technique": "AssumeRole",
                "permission": "sts:AssumeRole",
                "impact": "Assume higher-privilege role"
            }
        ]


# Convenience functions
def validate_aws_key(access_key: str, secret_key: str) -> Dict[str, Any]:
    """Quick validation of AWS credentials."""
    return AWSTools().validate_credentials(access_key, secret_key)
