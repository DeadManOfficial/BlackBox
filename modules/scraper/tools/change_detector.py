"""
Structural Change Detection - Monitor Site Layout Changes

Implements SimHash, DOM tree comparison, and schema validation
to detect when target sites change their structure (breaking scrapers).

Author: DeadManOfficial
Version: 1.0.0
"""

import hashlib
import re
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple, Set
from datetime import datetime
from enum import Enum
from collections import Counter
import difflib


class ChangeType(Enum):
    NONE = "none"
    MINOR = "minor"      # Small changes (text updates)
    MODERATE = "moderate"  # Structure changes (new elements)
    MAJOR = "major"       # Significant restructure
    CRITICAL = "critical"  # Complete redesign


@dataclass
class StructuralFingerprint:
    """Fingerprint of a page's structure"""
    url: str
    timestamp: datetime

    # Hashes
    simhash: str
    dom_hash: str
    selector_hash: str

    # Structural metrics
    tag_counts: Dict[str, int]
    depth: int
    total_elements: int
    text_density: float

    # Key selectors present
    selectors_found: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
            "simhash": self.simhash,
            "dom_hash": self.dom_hash,
            "selector_hash": self.selector_hash,
            "tag_counts": self.tag_counts,
            "depth": self.depth,
            "total_elements": self.total_elements,
            "text_density": self.text_density,
            "selectors_found": list(self.selectors_found)
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StructuralFingerprint':
        return cls(
            url=data["url"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            simhash=data["simhash"],
            dom_hash=data["dom_hash"],
            selector_hash=data["selector_hash"],
            tag_counts=data["tag_counts"],
            depth=data["depth"],
            total_elements=data["total_elements"],
            text_density=data["text_density"],
            selectors_found=set(data.get("selectors_found", []))
        )


@dataclass
class ChangeReport:
    """Report of changes between two fingerprints"""
    url: str
    change_type: ChangeType
    confidence: float

    # Metrics
    simhash_distance: int
    dom_similarity: float
    selector_diff: float

    # Details
    added_tags: Dict[str, int]
    removed_tags: Dict[str, int]
    missing_selectors: Set[str]
    new_selectors: Set[str]

    # Timestamps
    baseline_time: datetime
    current_time: datetime

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "change_type": self.change_type.value,
            "confidence": self.confidence,
            "metrics": {
                "simhash_distance": self.simhash_distance,
                "dom_similarity": self.dom_similarity,
                "selector_diff": self.selector_diff
            },
            "changes": {
                "added_tags": self.added_tags,
                "removed_tags": self.removed_tags,
                "missing_selectors": list(self.missing_selectors),
                "new_selectors": list(self.new_selectors)
            },
            "baseline_time": self.baseline_time.isoformat(),
            "current_time": self.current_time.isoformat()
        }

    def to_markdown(self) -> str:
        """Generate markdown report"""
        lines = [
            f"# Change Detection Report: {self.url}",
            "",
            f"**Change Type:** {self.change_type.value.upper()}",
            f"**Confidence:** {self.confidence:.1%}",
            f"**Baseline:** {self.baseline_time.isoformat()}",
            f"**Current:** {self.current_time.isoformat()}",
            "",
            "## Metrics",
            f"- SimHash Distance: {self.simhash_distance} bits",
            f"- DOM Similarity: {self.dom_similarity:.1%}",
            f"- Selector Diff: {self.selector_diff:.1%}",
            "",
        ]

        if self.missing_selectors:
            lines.extend([
                "## ⚠️ Missing Selectors (BREAKING)",
                "",
                *[f"- `{s}`" for s in self.missing_selectors],
                "",
            ])

        if self.new_selectors:
            lines.extend([
                "## ✅ New Selectors",
                "",
                *[f"- `{s}`" for s in self.new_selectors],
                "",
            ])

        if self.added_tags:
            lines.extend([
                "## Added HTML Tags",
                "",
                *[f"- `{tag}`: +{count}" for tag, count in self.added_tags.items()],
                "",
            ])

        if self.removed_tags:
            lines.extend([
                "## Removed HTML Tags",
                "",
                *[f"- `{tag}`: -{count}" for tag, count in self.removed_tags.items()],
                "",
            ])

        return "\n".join(lines)


class SimHash:
    """
    SimHash algorithm for near-duplicate detection.

    Creates a fingerprint that allows measuring similarity
    between documents using Hamming distance.
    """

    def __init__(self, bit_size: int = 64):
        self.bit_size = bit_size

    def compute(self, text: str) -> str:
        """Compute SimHash of text"""
        # Tokenize
        tokens = self._tokenize(text)

        # Initialize bit vector
        v = [0] * self.bit_size

        for token in tokens:
            # Hash token to bit_size bits
            token_hash = self._hash_token(token)

            for i in range(self.bit_size):
                bit = (token_hash >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1

        # Generate final hash
        fingerprint = 0
        for i in range(self.bit_size):
            if v[i] > 0:
                fingerprint |= (1 << i)

        return format(fingerprint, f'0{self.bit_size}b')

    def distance(self, hash1: str, hash2: str) -> int:
        """Calculate Hamming distance between two hashes"""
        if len(hash1) != len(hash2):
            raise ValueError("Hash lengths must match")

        return sum(c1 != c2 for c1, c2 in zip(hash1, hash2))

    def similarity(self, hash1: str, hash2: str) -> float:
        """Calculate similarity (0-1) between two hashes"""
        dist = self.distance(hash1, hash2)
        return 1 - (dist / self.bit_size)

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into shingles"""
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text.lower().strip())

        # Create 3-grams (shingles)
        shingles = []
        words = text.split()

        for i in range(len(words) - 2):
            shingle = ' '.join(words[i:i+3])
            shingles.append(shingle)

        return shingles

    def _hash_token(self, token: str) -> int:
        """Hash a token to bit_size bits"""
        hash_bytes = hashlib.md5(token.encode()).digest()
        hash_int = int.from_bytes(hash_bytes[:8], 'big')
        return hash_int & ((1 << self.bit_size) - 1)


class DOMAnalyzer:
    """Analyze DOM structure without full parsing"""

    # Tags that indicate structural elements
    STRUCTURAL_TAGS = {
        'div', 'section', 'article', 'header', 'footer', 'nav',
        'main', 'aside', 'form', 'table', 'ul', 'ol', 'dl'
    }

    # Tags that indicate content
    CONTENT_TAGS = {
        'p', 'span', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'li', 'td', 'th', 'label', 'input', 'button', 'img'
    }

    def __init__(self, html: str):
        self.html = html
        self._tag_pattern = re.compile(r'<(/?)(\w+)[^>]*>')

    def get_tag_counts(self) -> Dict[str, int]:
        """Count occurrences of each tag"""
        counts = Counter()

        for match in self._tag_pattern.finditer(self.html):
            if not match.group(1):  # Opening tag only
                tag = match.group(2).lower()
                counts[tag] += 1

        return dict(counts)

    def get_depth(self) -> int:
        """Estimate maximum DOM depth"""
        depth = 0
        max_depth = 0
        open_tags = []

        for match in self._tag_pattern.finditer(self.html):
            is_closing = bool(match.group(1))
            tag = match.group(2).lower()

            # Skip self-closing tags
            if tag in {'br', 'hr', 'img', 'input', 'meta', 'link'}:
                continue

            if is_closing:
                if open_tags and open_tags[-1] == tag:
                    open_tags.pop()
                    depth -= 1
            else:
                open_tags.append(tag)
                depth += 1
                max_depth = max(max_depth, depth)

        return max_depth

    def get_structure_signature(self) -> str:
        """Generate structural signature (tag sequence)"""
        tags = []

        for match in self._tag_pattern.finditer(self.html):
            is_closing = bool(match.group(1))
            tag = match.group(2).lower()

            if tag in self.STRUCTURAL_TAGS:
                prefix = '/' if is_closing else ''
                tags.append(f"{prefix}{tag}")

        signature = '|'.join(tags[:100])  # Limit to first 100 structural tags
        return hashlib.md5(signature.encode()).hexdigest()

    def get_text_density(self) -> float:
        """Calculate text-to-HTML ratio"""
        # Remove tags
        text_only = re.sub(r'<[^>]+>', '', self.html)
        text_only = re.sub(r'\s+', ' ', text_only).strip()

        if len(self.html) == 0:
            return 0

        return len(text_only) / len(self.html)

    def check_selectors(self, selectors: List[str]) -> Set[str]:
        """Check which CSS selectors are present (approximate)"""
        found = set()

        for selector in selectors:
            # Convert CSS selector to regex pattern
            pattern = self._selector_to_pattern(selector)
            if pattern and re.search(pattern, self.html, re.IGNORECASE):
                found.add(selector)

        return found

    def _selector_to_pattern(self, selector: str) -> Optional[str]:
        """Convert CSS selector to regex pattern"""
        # Handle simple cases
        if selector.startswith('#'):
            # ID selector
            id_val = selector[1:]
            return f'id=["\']?{re.escape(id_val)}["\']?'

        elif selector.startswith('.'):
            # Class selector
            class_val = selector[1:]
            return f'class=["\'][^"\']*{re.escape(class_val)}[^"\']*["\']'

        elif re.match(r'^\w+$', selector):
            # Tag selector
            return f'<{selector}[\\s>]'

        elif '[' in selector:
            # Attribute selector
            match = re.match(r'\[(\w+)=["\']?([^"\']+)["\']?\]', selector)
            if match:
                attr, val = match.groups()
                return f'{attr}=["\']?{re.escape(val)}["\']?'

        return None


class ChangeDetector:
    """
    Detect structural changes in web pages.

    Compares fingerprints to identify when a site's
    structure has changed (potentially breaking scrapers).
    """

    # Thresholds for change classification
    THRESHOLDS = {
        "simhash_minor": 5,      # < 5 bits = minor
        "simhash_moderate": 15,  # < 15 bits = moderate
        "simhash_major": 30,     # < 30 bits = major

        "dom_minor": 0.95,       # > 95% similar = minor
        "dom_moderate": 0.80,    # > 80% similar = moderate
        "dom_major": 0.50,       # > 50% similar = major
    }

    def __init__(self):
        self.simhash = SimHash()
        self._baselines: Dict[str, StructuralFingerprint] = {}

    def fingerprint(
        self,
        url: str,
        html: str,
        key_selectors: Optional[List[str]] = None
    ) -> StructuralFingerprint:
        """Generate structural fingerprint of a page"""
        analyzer = DOMAnalyzer(html)

        # Check key selectors
        selectors_found = set()
        if key_selectors:
            selectors_found = analyzer.check_selectors(key_selectors)

        # Generate fingerprint
        return StructuralFingerprint(
            url=url,
            timestamp=datetime.now(),
            simhash=self.simhash.compute(html),
            dom_hash=analyzer.get_structure_signature(),
            selector_hash=hashlib.md5(''.join(sorted(selectors_found)).encode()).hexdigest(),
            tag_counts=analyzer.get_tag_counts(),
            depth=analyzer.get_depth(),
            total_elements=sum(analyzer.get_tag_counts().values()),
            text_density=analyzer.get_text_density(),
            selectors_found=selectors_found
        )

    def set_baseline(self, fingerprint: StructuralFingerprint):
        """Set baseline fingerprint for a URL"""
        self._baselines[fingerprint.url] = fingerprint

    def get_baseline(self, url: str) -> Optional[StructuralFingerprint]:
        """Get baseline fingerprint for a URL"""
        return self._baselines.get(url)

    def compare(
        self,
        baseline: StructuralFingerprint,
        current: StructuralFingerprint,
        key_selectors: Optional[List[str]] = None
    ) -> ChangeReport:
        """Compare two fingerprints and generate change report"""

        # Calculate metrics
        simhash_dist = self.simhash.distance(baseline.simhash, current.simhash)

        # DOM similarity (based on tag counts)
        dom_sim = self._calculate_tag_similarity(
            baseline.tag_counts, current.tag_counts
        )

        # Selector diff
        if key_selectors:
            baseline_found = baseline.selectors_found
            current_found = current.selectors_found
            missing = baseline_found - current_found
            new = current_found - baseline_found

            total_selectors = len(set(key_selectors))
            selector_diff = len(missing) / total_selectors if total_selectors > 0 else 0
        else:
            missing = set()
            new = set()
            selector_diff = 0

        # Tag changes
        added_tags = {}
        removed_tags = {}

        all_tags = set(baseline.tag_counts.keys()) | set(current.tag_counts.keys())
        for tag in all_tags:
            baseline_count = baseline.tag_counts.get(tag, 0)
            current_count = current.tag_counts.get(tag, 0)
            diff = current_count - baseline_count

            if diff > 0:
                added_tags[tag] = diff
            elif diff < 0:
                removed_tags[tag] = abs(diff)

        # Classify change
        change_type, confidence = self._classify_change(
            simhash_dist, dom_sim, selector_diff, len(missing)
        )

        return ChangeReport(
            url=baseline.url,
            change_type=change_type,
            confidence=confidence,
            simhash_distance=simhash_dist,
            dom_similarity=dom_sim,
            selector_diff=selector_diff,
            added_tags=added_tags,
            removed_tags=removed_tags,
            missing_selectors=missing,
            new_selectors=new,
            baseline_time=baseline.timestamp,
            current_time=current.timestamp
        )

    def _calculate_tag_similarity(
        self,
        tags1: Dict[str, int],
        tags2: Dict[str, int]
    ) -> float:
        """Calculate Jaccard-like similarity between tag distributions"""
        all_tags = set(tags1.keys()) | set(tags2.keys())

        if not all_tags:
            return 1.0

        intersection = 0
        union = 0

        for tag in all_tags:
            c1 = tags1.get(tag, 0)
            c2 = tags2.get(tag, 0)
            intersection += min(c1, c2)
            union += max(c1, c2)

        return intersection / union if union > 0 else 1.0

    def _classify_change(
        self,
        simhash_dist: int,
        dom_sim: float,
        selector_diff: float,
        missing_count: int
    ) -> Tuple[ChangeType, float]:
        """Classify the type of change"""

        # Critical if key selectors are missing
        if missing_count > 0:
            return ChangeType.CRITICAL, 0.95

        # Based on SimHash distance
        if simhash_dist <= self.THRESHOLDS["simhash_minor"]:
            if dom_sim >= self.THRESHOLDS["dom_minor"]:
                return ChangeType.NONE, 0.90
            return ChangeType.MINOR, 0.85

        if simhash_dist <= self.THRESHOLDS["simhash_moderate"]:
            if dom_sim >= self.THRESHOLDS["dom_moderate"]:
                return ChangeType.MINOR, 0.80
            return ChangeType.MODERATE, 0.75

        if simhash_dist <= self.THRESHOLDS["simhash_major"]:
            if dom_sim >= self.THRESHOLDS["dom_major"]:
                return ChangeType.MODERATE, 0.70
            return ChangeType.MAJOR, 0.65

        return ChangeType.MAJOR, 0.60

    def detect_change(
        self,
        url: str,
        current_html: str,
        key_selectors: Optional[List[str]] = None
    ) -> Optional[ChangeReport]:
        """
        Detect changes from baseline.

        Args:
            url: URL to check
            current_html: Current HTML content
            key_selectors: Critical selectors that must be present

        Returns:
            ChangeReport if baseline exists, None otherwise
        """
        baseline = self.get_baseline(url)
        if not baseline:
            return None

        current = self.fingerprint(url, current_html, key_selectors)
        return self.compare(baseline, current, key_selectors)

    def save_baselines(self, filepath: str):
        """Save baselines to JSON file"""
        data = {
            url: fp.to_dict()
            for url, fp in self._baselines.items()
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load_baselines(self, filepath: str):
        """Load baselines from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        self._baselines = {
            url: StructuralFingerprint.from_dict(fp_data)
            for url, fp_data in data.items()
        }


# Convenience functions
def monitor_page(
    url: str,
    html: str,
    baseline_html: str,
    key_selectors: Optional[List[str]] = None
) -> ChangeReport:
    """Quick comparison between two HTML versions"""
    detector = ChangeDetector()

    baseline = detector.fingerprint(url, baseline_html, key_selectors)
    current = detector.fingerprint(url, html, key_selectors)

    return detector.compare(baseline, current, key_selectors)


# Example usage
def example():
    # Baseline HTML
    baseline_html = """
    <html>
    <body>
        <div class="product-container">
            <h1 class="product-title">iPhone 15</h1>
            <span class="price">$999</span>
            <div class="description">Latest iPhone</div>
        </div>
    </body>
    </html>
    """

    # Modified HTML (site updated)
    current_html = """
    <html>
    <body>
        <section class="product-wrapper">
            <h1 class="product-name">iPhone 15</h1>
            <div class="pricing">$999</div>
            <p class="product-desc">Latest iPhone</p>
        </section>
    </body>
    </html>
    """

    # Key selectors our scraper relies on
    key_selectors = [
        ".product-title",
        ".price",
        ".product-container"
    ]

    # Detect changes
    report = monitor_page(
        url="https://example.com/product/1",
        html=current_html,
        baseline_html=baseline_html,
        key_selectors=key_selectors
    )

    print(report.to_markdown())
    print(f"\nChange Type: {report.change_type.value}")
    print(f"Missing Selectors: {report.missing_selectors}")


if __name__ == "__main__":
    example()
