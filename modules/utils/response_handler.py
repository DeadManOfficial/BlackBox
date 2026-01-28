#!/usr/bin/env python3
"""
Response Handler - Token Optimization Utility
=============================================
Truncates and optimizes large tool responses to prevent context overflow.

Usage:
    from modules.utils.response_handler import ResponseHandler

    # Truncate large text
    truncated = ResponseHandler.truncate(large_response, max_chars=10000)

    # Summarize JSON
    compact = ResponseHandler.compact_json(data, max_items=10)

    # Extract key elements from HTML/Markdown
    key_info = ResponseHandler.extract_essentials(html_content)
"""

import re
import json
from typing import Any, Dict, List, Optional, Union


class ResponseHandler:
    """Handles large responses to prevent token overflow"""

    # Thresholds
    MAX_CHARS = 10000
    MAX_JSON_ITEMS = 10
    MAX_LINES = 200

    @staticmethod
    def truncate(
        response: str,
        max_chars: int = MAX_CHARS,
        preserve_ends: bool = True
    ) -> str:
        """
        Truncate large response while preserving start and end.

        Args:
            response: The response text to truncate
            max_chars: Maximum characters to keep
            preserve_ends: If True, keep both start and end (avoids "lost in middle")

        Returns:
            Truncated response with indicator of removed content
        """
        if not response or len(response) <= max_chars:
            return response

        if preserve_ends:
            # Split between head and tail to avoid "lost in middle" problem
            head_size = max_chars * 3 // 5  # 60% to head
            tail_size = max_chars * 2 // 5  # 40% to tail

            head = response[:head_size]
            tail = response[-tail_size:]
            removed = len(response) - max_chars

            return f"{head}\n\n[... {removed:,} characters truncated ...]\n\n{tail}"
        else:
            return response[:max_chars] + f"\n\n[... truncated {len(response) - max_chars:,} chars ...]"

    @staticmethod
    def compact_json(
        data: Any,
        max_items: int = MAX_JSON_ITEMS,
        max_depth: int = 3,
        current_depth: int = 0
    ) -> Any:
        """
        Compact JSON by limiting array sizes and depth.

        Args:
            data: JSON data (dict, list, or primitive)
            max_items: Maximum items to keep in arrays
            max_depth: Maximum nesting depth
            current_depth: Current recursion depth

        Returns:
            Compacted JSON structure
        """
        if current_depth >= max_depth:
            if isinstance(data, (dict, list)):
                return f"[{type(data).__name__} with {len(data)} items]"
            return data

        if isinstance(data, list):
            if len(data) > max_items:
                compacted = [
                    ResponseHandler.compact_json(item, max_items, max_depth, current_depth + 1)
                    for item in data[:max_items]
                ]
                compacted.append(f"[... and {len(data) - max_items} more items]")
                return compacted
            return [
                ResponseHandler.compact_json(item, max_items, max_depth, current_depth + 1)
                for item in data
            ]

        if isinstance(data, dict):
            return {
                k: ResponseHandler.compact_json(v, max_items, max_depth, current_depth + 1)
                for k, v in data.items()
            }

        return data

    @staticmethod
    def extract_essentials(content: str, content_type: str = "auto") -> Dict[str, Any]:
        """
        Extract key elements from HTML/Markdown content.

        Args:
            content: The content to analyze
            content_type: "html", "markdown", or "auto"

        Returns:
            Dictionary with extracted essentials
        """
        if content_type == "auto":
            content_type = "html" if "<html" in content.lower() or "<body" in content.lower() else "markdown"

        essentials = {
            "type": content_type,
            "length": len(content),
            "urls": [],
            "emails": [],
            "forms": [],
            "scripts": [],
            "api_endpoints": [],
            "sensitive_patterns": []
        }

        # Extract URLs
        url_pattern = r'https?://[^\s<>"\')\]]+|/[a-zA-Z0-9_/-]+(?:\?[^\s<>"\')\]]*)?'
        essentials["urls"] = list(set(re.findall(url_pattern, content)))[:20]

        # Extract emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        essentials["emails"] = list(set(re.findall(email_pattern, content)))

        # Extract form actions
        form_pattern = r'<form[^>]*action=["\']([^"\']+)["\']'
        essentials["forms"] = list(set(re.findall(form_pattern, content, re.IGNORECASE)))

        # Extract script sources
        script_pattern = r'<script[^>]*src=["\']([^"\']+)["\']'
        essentials["scripts"] = list(set(re.findall(script_pattern, content, re.IGNORECASE)))[:10]

        # Extract API endpoints
        api_pattern = r'/api/[a-zA-Z0-9_/-]+'
        essentials["api_endpoints"] = list(set(re.findall(api_pattern, content)))

        # Check for sensitive patterns
        sensitive_patterns = [
            (r'api[_-]?key', "API Key reference"),
            (r'secret', "Secret reference"),
            (r'password', "Password reference"),
            (r'token', "Token reference"),
            (r'\.env', "Environment file reference"),
            (r'Bearer\s+[A-Za-z0-9\-_]+', "Bearer token"),
        ]

        for pattern, description in sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                essentials["sensitive_patterns"].append(description)

        return essentials

    @staticmethod
    def summarize_for_context(content: str, max_chars: int = 2000) -> str:
        """
        Create a context-friendly summary of content.

        Args:
            content: Full content
            max_chars: Maximum summary length

        Returns:
            Summarized content suitable for LLM context
        """
        essentials = ResponseHandler.extract_essentials(content)

        summary_parts = [
            f"Content: {essentials['type']} ({essentials['length']:,} chars)",
        ]

        if essentials["urls"]:
            summary_parts.append(f"URLs found: {len(essentials['urls'])}")
            summary_parts.append(f"  Sample: {', '.join(essentials['urls'][:5])}")

        if essentials["api_endpoints"]:
            summary_parts.append(f"API endpoints: {', '.join(essentials['api_endpoints'][:10])}")

        if essentials["forms"]:
            summary_parts.append(f"Forms: {', '.join(essentials['forms'])}")

        if essentials["emails"]:
            summary_parts.append(f"Emails: {', '.join(essentials['emails'])}")

        if essentials["sensitive_patterns"]:
            summary_parts.append(f"Sensitive: {', '.join(essentials['sensitive_patterns'])}")

        summary = "\n".join(summary_parts)

        if len(summary) > max_chars:
            summary = summary[:max_chars] + "..."

        return summary

    @staticmethod
    def format_findings(findings: List[Dict], max_findings: int = 10) -> str:
        """
        Format findings list for context-efficient display.

        Args:
            findings: List of finding dictionaries
            max_findings: Maximum findings to include

        Returns:
            Formatted string
        """
        if not findings:
            return "No findings"

        lines = []
        for i, finding in enumerate(findings[:max_findings], 1):
            severity = finding.get("severity", "INFO")
            title = finding.get("title", "Untitled")
            lines.append(f"{i}. [{severity}] {title}")

        if len(findings) > max_findings:
            lines.append(f"   ... and {len(findings) - max_findings} more")

        return "\n".join(lines)


# Convenience functions
def truncate(text: str, max_chars: int = 10000) -> str:
    """Quick truncate function"""
    return ResponseHandler.truncate(text, max_chars)


def compact(data: Any, max_items: int = 10) -> Any:
    """Quick compact function for JSON"""
    return ResponseHandler.compact_json(data, max_items)


def summarize(content: str) -> str:
    """Quick summarize function"""
    return ResponseHandler.summarize_for_context(content)


if __name__ == "__main__":
    # Test
    test_response = "A" * 50000
    print(f"Original: {len(test_response)} chars")
    truncated = truncate(test_response)
    print(f"Truncated: {len(truncated)} chars")
    print(truncated[:200])
