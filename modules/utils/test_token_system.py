#!/usr/bin/env python3
"""
Token Optimization System - Integration Test
=============================================
Tests all token optimization modules work together.
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def test_response_handler():
    """Test response truncation and summarization."""
    print("\n1. Testing ResponseHandler...")

    from modules.utils.response_handler import ResponseHandler, truncate, summarize

    # Test truncation
    large_text = "A" * 50000
    truncated = truncate(large_text, 10000)
    assert len(truncated) <= 12000  # Some overhead for truncation message
    assert "truncated" in truncated.lower()
    print(f"   ✓ Truncation: {len(large_text)} → {len(truncated)} chars")

    # Test JSON compaction
    large_json = {"items": list(range(100))}
    compacted = ResponseHandler.compact_json(large_json, max_items=10)
    assert len(compacted["items"]) == 11  # 10 items + "...and X more"
    print(f"   ✓ JSON compaction: 100 → {len(compacted['items'])} items")

    # Test summarization
    html = """
    <html>
    <body>
        <a href="/api/users">Users API</a>
        <a href="/api/auth">Auth API</a>
        <form action="/login">Login</form>
        <script src="/app.js"></script>
    </body>
    </html>
    """
    summary = summarize(html)
    assert "API endpoints" in summary or "api" in summary.lower()
    print(f"   ✓ Summarization extracts key elements")

    print("   ResponseHandler: PASSED")


def test_gate_checkpoint():
    """Test gate checkpointing system."""
    print("\n2. Testing GateCheckpoint...")

    from modules.utils.gate_checkpoint import GateCheckpoint

    # Create test checkpoint
    cp = GateCheckpoint("_test_target")

    # Save checkpoint
    summary = cp.save("GATE_1", {
        "findings": [
            {"id": "F1", "severity": "HIGH"},
            {"id": "F2", "severity": "MEDIUM"},
        ],
        "urls_mapped": 50
    })
    assert "GATE_1" in summary
    assert "Findings: 2" in summary
    print(f"   ✓ Checkpoint saved with summary")

    # Load checkpoint
    data = cp.load("GATE_1")
    assert data is not None
    assert len(data["data"]["findings"]) == 2
    print(f"   ✓ Checkpoint loaded correctly")

    # Get summary only
    summary_only = cp.get_summary("GATE_1")
    assert summary_only is not None
    assert len(summary_only) < 500  # Should be compact
    print(f"   ✓ Summary retrieval works ({len(summary_only)} chars)")

    # Test status
    status = cp.get_status()
    assert status["GATE_1"] == "COMPLETE"
    assert status["GATE_2"] == "PENDING"
    print(f"   ✓ Status tracking works")

    # Test next gate detection
    next_gate = cp.get_next_gate()
    assert next_gate == "GATE_2"
    print(f"   ✓ Next gate detection: {next_gate}")

    # Cleanup
    cp.clear()
    print("   GateCheckpoint: PASSED")


def test_token_rules():
    """Test token rules enforcement."""
    print("\n3. Testing TokenRules...")

    from modules.utils.token_rules import (
        TokenRules, BatchProcessor, enforce_token_rules,
        get_optimized_scrape_params, SCRAPING_RULES
    )

    # Test response size checking
    rules = TokenRules("_test_target")
    large_response = "B" * 50000
    processed, was_truncated = rules.check_response_size(large_response)
    assert was_truncated
    assert len(processed) <= 12000
    print(f"   ✓ Response size enforcement works")

    # Test batching
    items = list(range(25))
    batches = rules.batch_items(items)
    assert len(batches) == 3  # 10, 10, 5
    print(f"   ✓ Batching: 25 items → {len(batches)} batches")

    # Test summary generation
    data = {"findings": [1,2,3], "status": "ok"}
    summary = rules.get_summary(data)
    assert "findings" in summary
    print(f"   ✓ Summary generation works")

    # Test optimized scrape params
    params = get_optimized_scrape_params("https://example.com")
    assert params["onlyMainContent"] == True
    assert "markdown" in params["formats"]
    print(f"   ✓ Optimized scrape params configured")

    # Test BatchProcessor
    processor = BatchProcessor("_test_target", batch_size=5)
    test_items = list(range(12))
    batch_count = 0
    for batch in processor.process(test_items):
        batch_count += 1
        processor.save_batch_results(batch)
    assert batch_count == 3  # 5, 5, 2
    results = processor.get_all_results()
    assert len(results) == 12
    print(f"   ✓ BatchProcessor: {len(test_items)} items in {batch_count} batches")

    print("   TokenRules: PASSED")


def test_integration():
    """Test all modules work together."""
    print("\n4. Testing Integration...")

    from modules.utils import (
        truncate, compact, summarize,
        checkpoint, get_summary,
        TokenRules, BatchProcessor
    )

    # Simulate a bounty gate with token optimization
    target = "_integration_test"

    # 1. Process URLs in batches
    urls = [f"https://example.com/page{i}" for i in range(15)]
    processor = BatchProcessor(target, batch_size=5)

    all_findings = []
    for batch in processor.process(urls):
        # Simulate scraping (would normally call MCP tools)
        for url in batch:
            # Simulate large response
            response = f"Page content for {url}\n" * 1000

            # Apply T1: Truncate
            truncated = truncate(response, 500)

            all_findings.append({
                "url": url,
                "content_preview": truncated[:100]
            })

        processor.save_batch_results(batch)

    # 2. Checkpoint results (T2)
    summary = checkpoint(target, "GATE_TEST", {
        "findings": all_findings,
        "urls_processed": len(urls),
        "status": "complete"
    })
    print(f"   ✓ Processed {len(urls)} URLs in batches")
    print(f"   ✓ Checkpoint saved")

    # 3. Verify summary is compact (T3)
    loaded_summary = get_summary(target, "GATE_TEST")
    assert loaded_summary is not None
    assert len(loaded_summary) < 500
    print(f"   ✓ Summary is compact ({len(loaded_summary)} chars)")

    # Cleanup
    from modules.utils.gate_checkpoint import GateCheckpoint
    GateCheckpoint(target).clear()

    print("   Integration: PASSED")


def main():
    """Run all tests."""
    print("=" * 60)
    print("TOKEN OPTIMIZATION SYSTEM - INTEGRATION TEST")
    print("=" * 60)

    try:
        test_response_handler()
        test_gate_checkpoint()
        test_token_rules()
        test_integration()

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED ✓")
        print("=" * 60)
        print("\nToken optimization system ready for use.")
        print("\nUsage in Claude Code:")
        print("  1. ToolSearch before MCP calls")
        print("  2. Use optimized scrape params")
        print("  3. Checkpoint between gates")
        print("  4. Reference files, not inline data")
        return 0

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
