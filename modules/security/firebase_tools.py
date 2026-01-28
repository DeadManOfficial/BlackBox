"""
Firebase Security Testing Tools
Test Firebase databases and storage for misconfigurations

Usage:
    from modules.security.firebase_tools import FirebaseTools

    fb = FirebaseTools("project-id")
    fb.test_database_access()
    fb.test_storage_access()
"""

import json
from typing import Dict, Any, List, Optional
from urllib.parse import quote

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class FirebaseTools:
    """Firebase security testing toolkit."""

    def __init__(self, project_id: str, api_key: Optional[str] = None):
        """
        Initialize Firebase tester.

        Args:
            project_id: Firebase project ID
            api_key: Optional Firebase API key (AIza...)
        """
        self.project_id = project_id
        self.api_key = api_key
        self.database_url = f"https://{project_id}.firebaseio.com"
        self.firestore_url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
        self.storage_url = f"https://firebasestorage.googleapis.com/v0/b/{project_id}.appspot.com/o"

    def test_database_access(self) -> Dict[str, Any]:
        """
        Test Realtime Database for public access.

        Returns:
            Dict with access test results
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        results = {
            "database_url": self.database_url,
            "tests": []
        }

        # Test root access
        try:
            response = requests.get(f"{self.database_url}/.json", timeout=10)
            root_test = {
                "endpoint": "/.json",
                "status_code": response.status_code,
                "accessible": response.status_code == 200,
            }

            if response.status_code == 200:
                data = response.json()
                root_test["data_exposed"] = data is not None and data != "null"
                root_test["response_type"] = type(data).__name__
            elif response.status_code == 401:
                root_test["message"] = "Permission denied (secured)"

            results["tests"].append(root_test)
        except Exception as e:
            results["tests"].append({"endpoint": "/.json", "error": str(e)})

        # Test common paths
        common_paths = [
            "/users.json",
            "/accounts.json",
            "/config.json",
            "/admin.json",
            "/data.json"
        ]

        for path in common_paths:
            try:
                response = requests.get(f"{self.database_url}{path}", timeout=5)
                results["tests"].append({
                    "endpoint": path,
                    "status_code": response.status_code,
                    "accessible": response.status_code == 200 and response.json() is not None
                })
            except:
                pass

        # Summary
        results["vulnerable"] = any(t.get("accessible") and t.get("data_exposed", True) for t in results["tests"])

        return results

    def test_write_access(self, path: str = "/test_write") -> Dict[str, Any]:
        """
        Test if database allows writes.

        Args:
            path: Path to test write access

        Returns:
            Dict with write test results
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        test_data = {"security_test": "blackbox_probe", "timestamp": "auto"}

        try:
            response = requests.post(
                f"{self.database_url}{path}.json",
                json=test_data,
                timeout=10
            )

            result = {
                "endpoint": f"{path}.json",
                "status_code": response.status_code,
                "write_allowed": response.status_code == 200
            }

            if response.status_code == 200:
                result["response"] = response.json()
                # Clean up - try to delete the test entry
                if "name" in response.json():
                    cleanup_url = f"{self.database_url}{path}/{response.json()['name']}.json"
                    requests.delete(cleanup_url, timeout=5)

            return result
        except Exception as e:
            return {"endpoint": f"{path}.json", "error": str(e)}

    def test_storage_access(self) -> Dict[str, Any]:
        """
        Test Firebase Storage for public access.

        Returns:
            Dict with storage test results
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        try:
            response = requests.get(self.storage_url, timeout=10)

            result = {
                "storage_url": self.storage_url,
                "status_code": response.status_code,
                "listing_allowed": response.status_code == 200
            }

            if response.status_code == 200:
                data = response.json()
                if "items" in data:
                    result["files_exposed"] = len(data["items"])
                    result["sample_files"] = [
                        item.get("name") for item in data["items"][:5]
                    ]

            return result
        except Exception as e:
            return {"error": str(e)}

    def test_firestore_access(self) -> Dict[str, Any]:
        """
        Test Firestore for public access.

        Returns:
            Dict with Firestore test results
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        try:
            response = requests.get(self.firestore_url, timeout=10)

            result = {
                "firestore_url": self.firestore_url,
                "status_code": response.status_code,
                "accessible": response.status_code == 200
            }

            if response.status_code == 200:
                data = response.json()
                if "documents" in data:
                    result["documents_exposed"] = len(data["documents"])

            return result
        except Exception as e:
            return {"error": str(e)}

    def validate_api_key(self) -> Dict[str, Any]:
        """
        Validate Firebase API key.

        Returns:
            Dict with validation results
        """
        if not self.api_key:
            return {"error": "No API key provided"}

        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not available"}

        # Test with Identity Toolkit API
        url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={self.api_key}"

        try:
            response = requests.post(
                url,
                json={"email": "test@test.com", "password": "test", "returnSecureToken": True},
                timeout=10
            )

            if response.status_code == 400:
                error = response.json().get("error", {})
                if "INVALID_EMAIL" in str(error) or "EMAIL_NOT_FOUND" in str(error):
                    return {"valid": True, "message": "API key is valid (tested with Identity Toolkit)"}

            return {
                "valid": False,
                "status_code": response.status_code,
                "response": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text[:200]
            }
        except Exception as e:
            return {"error": str(e)}

    def full_scan(self) -> Dict[str, Any]:
        """
        Run full Firebase security scan.

        Returns:
            Dict with all test results
        """
        return {
            "project_id": self.project_id,
            "database": self.test_database_access(),
            "storage": self.test_storage_access(),
            "firestore": self.test_firestore_access(),
            "api_key": self.validate_api_key() if self.api_key else {"skipped": True}
        }


# Common Firebase project patterns for TikTok
TIKTOK_FIREBASE_PATTERNS = [
    "tiktok",
    "tiktok-prod",
    "tiktok-production",
    "musical-ly",
    "musically",
    "bytedance",
    "bytedance-tiktok"
]


def scan_tiktok_firebase() -> List[Dict[str, Any]]:
    """Scan potential TikTok Firebase projects."""
    results = []

    for pattern in TIKTOK_FIREBASE_PATTERNS:
        fb = FirebaseTools(pattern)
        result = fb.test_database_access()
        result["project_pattern"] = pattern
        results.append(result)

    return results
