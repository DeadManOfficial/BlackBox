"""
DeadMan Intelligence Command - CLI Interface
=============================================

Unified command-line interface for the intelligence platform.

Usage:
    deadman-intel mission start     # Start single burst cycle
    deadman-intel mission status    # Get mission status
    deadman-intel mission continuous # Run continuous operations
    deadman-intel briefing generate # Generate daily briefing
    deadman-intel briefing show     # Show today's briefing
    deadman-intel research scrape   # Run research scraper
    deadman-intel token stats       # Show token optimization stats
    deadman-intel serve             # Start web dashboard
"""

import asyncio
import click
import json
import logging
from datetime import datetime


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )


@click.group()
@click.option('-v', '--verbose', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """DeadMan Intelligence Command - Unified Intelligence Platform"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    setup_logging(verbose)


# =============================================================================
# Mission Commands
# =============================================================================

@cli.group()
def mission():
    """Mission control operations."""
    pass


@mission.command('start')
@click.option('--focus', '-f', multiple=True, help='Focus areas for agents')
@click.pass_context
def mission_start(ctx, focus):
    """Start a single intelligence burst cycle."""
    from .mission_commander import MissionCommander

    click.echo("=" * 60)
    click.echo("DEADMAN INTELLIGENCE COMMAND")
    click.echo("Starting Intelligence Burst Cycle")
    click.echo("=" * 60)

    commander = MissionCommander()
    focus_areas = list(focus) if focus else None

    async def run():
        findings = await commander.execute_burst_cycle(focus_areas)
        return findings

    findings = asyncio.run(run())

    click.echo(f"\nBurst cycle complete!")
    click.echo(f"Findings collected: {len(findings)}")

    # Show summary
    by_agent = {}
    for f in findings:
        agent = f.agent_id
        by_agent[agent] = by_agent.get(agent, 0) + 1

    click.echo("\nFindings by agent:")
    for agent, count in by_agent.items():
        click.echo(f"  - {agent}: {count}")

    # Token stats
    stats = commander._get_aggregate_token_stats()
    click.echo(f"\nToken optimization:")
    click.echo(f"  - Tokens saved: {stats['total_tokens_saved']:,}")
    click.echo(f"  - Cache hit rate: {stats['cache_hit_rate']}")


@mission.command('status')
def mission_status():
    """Get current mission status."""
    from .mission_commander import MissionCommander

    commander = MissionCommander()
    status = commander.get_status()

    click.echo("\n" + "=" * 50)
    click.echo("MISSION STATUS")
    click.echo("=" * 50)

    cmd_status = status['commander']
    click.echo(f"Running: {cmd_status['is_running']}")
    click.echo(f"Current mission: {cmd_status['current_mission'] or 'None'}")
    click.echo(f"Total findings: {cmd_status['total_findings']}")
    click.echo(f"Missions completed: {cmd_status['missions_completed']}")

    click.echo("\nAgent Status:")
    for agent_id, agent_status in status['agents'].items():
        status_icon = "+" if agent_status['status'] == 'active' else "-"
        click.echo(f"  [{status_icon}] {agent_id}: {agent_status['current_task']}")

    token_stats = status['token_stats']
    click.echo(f"\nToken Optimization:")
    click.echo(f"  - Total saved: {token_stats['total_tokens_saved']:,}")
    click.echo(f"  - API calls: {token_stats['total_api_calls']}")
    click.echo(f"  - Cache hits: {token_stats['cache_hit_rate']}")


@mission.command('continuous')
@click.option('--interval', '-i', default=2, help='Hours between bursts (default: 2)')
def mission_continuous(interval):
    """Run continuous intelligence operations."""
    from .mission_commander import MissionCommander

    click.echo("=" * 60)
    click.echo("DEADMAN INTELLIGENCE COMMAND")
    click.echo("Starting Continuous Operations")
    click.echo(f"Burst interval: {interval} hours")
    click.echo("Press Ctrl+C to stop")
    click.echo("=" * 60)

    commander = MissionCommander()
    commander.burst_interval_hours = interval

    try:
        asyncio.run(commander.run_continuous())
    except KeyboardInterrupt:
        click.echo("\n\nOperations terminated by user.")
        status = commander.get_status()
        click.echo(f"Final stats: {status['commander']['missions_completed']} missions, "
                  f"{status['commander']['total_findings']} findings")


@mission.command('findings')
@click.option('--limit', '-l', default=20, help='Number of findings to show')
@click.option('--agent', '-a', help='Filter by agent ID')
@click.option('--priority', '-p', default=1, type=int, help='Minimum priority (1-5)')
def mission_findings(limit, agent, priority):
    """Show recent intelligence findings."""
    from .mission_commander import MissionCommander

    commander = MissionCommander()
    findings = commander.get_recent_findings(
        limit=limit,
        agent_id=agent,
        min_priority=priority
    )

    if not findings:
        click.echo("No findings found.")
        return

    click.echo(f"\nRecent Findings ({len(findings)}):")
    click.echo("-" * 60)

    for f in findings:
        priority_icon = "*" * f.get('priority', 1)
        click.echo(f"\n[{f['agent_id']}] {priority_icon}")
        click.echo(f"  Type: {f['finding_type']}")
        click.echo(f"  {f['content'][:200]}...")
        click.echo(f"  Confidence: {f['confidence_score']:.2f}")


# =============================================================================
# Briefing Commands
# =============================================================================

@cli.group()
def briefing():
    """Daily briefing operations."""
    pass


@briefing.command('generate')
def briefing_generate():
    """Generate today's intelligence briefing."""
    from .updates import BriefingGenerator

    click.echo("Generating daily briefing...")
    generator = BriefingGenerator()

    async def run():
        return await generator.generate_briefing()

    briefing = asyncio.run(run())

    click.echo("\n" + "=" * 60)
    click.echo(f"DAILY INTELLIGENCE BRIEFING - {briefing.date.strftime('%Y-%m-%d')}")
    click.echo("=" * 60)

    click.echo(f"\nSUMMARY:\n{briefing.summary}")

    click.echo("\nKEY DEVELOPMENTS:")
    for i, dev in enumerate(briefing.key_developments, 1):
        click.echo(f"  {i}. {dev}")

    click.echo(f"\nNews items collected: {len(briefing.news_items)}")
    click.echo(f"Categories: {', '.join(briefing.categories.keys())}")


@briefing.command('show')
@click.option('--date', '-d', help='Date (YYYY-MM-DD), defaults to today')
def briefing_show(date):
    """Show stored briefing."""
    from .updates import BriefingGenerator

    generator = BriefingGenerator()

    if date:
        from datetime import datetime
        target_date = datetime.strptime(date, '%Y-%m-%d')
        briefing = generator.get_briefing(target_date)
    else:
        briefing = generator.get_briefing()

    if not briefing:
        click.echo("No briefing found for this date. Run 'deadman-intel briefing generate' first.")
        return

    click.echo("\n" + "=" * 60)
    click.echo(f"DAILY BRIEFING - {briefing['date']}")
    click.echo("=" * 60)

    click.echo(f"\n{briefing['summary']}")

    click.echo("\nKey Developments:")
    for i, dev in enumerate(briefing['key_developments'], 1):
        click.echo(f"  {i}. {dev}")

    click.echo(f"\nNews items: {briefing['news_count']}")
    click.echo(f"Generated: {briefing['generated_at']}")


@briefing.command('history')
@click.option('--days', '-d', default=7, help='Number of days to show')
def briefing_history(days):
    """Show recent briefing history."""
    from .updates import BriefingGenerator

    generator = BriefingGenerator()
    briefings = generator.get_recent_briefings(days)

    if not briefings:
        click.echo("No briefings found.")
        return

    click.echo(f"\nRecent Briefings ({len(briefings)}):")
    click.echo("-" * 50)

    for b in briefings:
        click.echo(f"\n{b['date']}: {b['news_count']} items")
        click.echo(f"  {b['summary'][:100]}...")


# =============================================================================
# Research Commands
# =============================================================================

@cli.group()
def research():
    """Research and scraping operations."""
    pass


@research.command('scrape')
@click.option('--category', '-c', help='Category to scrape (tech_news, ai_research, finance, policy)')
@click.option('--url', '-u', help='Specific URL to scrape')
def research_scrape(category, url):
    """Run research scraper."""
    from .research import ResearchScraper, ResearchAggregator

    click.echo("Starting research scraper...")

    if url:
        scraper = ResearchScraper()
        content = scraper.fetch_url(url)
        if content:
            click.echo(f"\nScraped: {content.title}")
            click.echo(f"Type: {content.source_type}")
            click.echo(f"Content: {content.content[:500]}...")
        else:
            click.echo("Failed to scrape URL.")
        return

    aggregator = ResearchAggregator()

    if category:
        content = aggregator.scraper.fetch_category(category)
    else:
        content = aggregator.gather_all()

    if isinstance(content, dict):
        total = sum(len(items) for items in content.values())
        click.echo(f"\nScraped {total} items across {len(content)} categories:")
        for cat, items in content.items():
            click.echo(f"  - {cat}: {len(items)} items")
    else:
        click.echo(f"\nScraped {len(content)} items from {category}")

    stats = aggregator.scraper.get_stats()
    click.echo(f"\nStats: {stats['requests_made']} requests, "
              f"{stats['cache_hits']} cache hits, "
              f"{stats['errors']} errors")


# =============================================================================
# Token Commands
# =============================================================================

@cli.group()
def token():
    """Token optimization operations."""
    pass


@token.command('stats')
def token_stats():
    """Show token optimization statistics."""
    from .mission_commander import MissionCommander

    commander = MissionCommander()
    stats = commander._get_aggregate_token_stats()

    click.echo("\n" + "=" * 50)
    click.echo("TOKEN OPTIMIZATION STATISTICS")
    click.echo("=" * 50)

    click.echo(f"Total tokens saved: {stats['total_tokens_saved']:,}")
    click.echo(f"Total API calls: {stats['total_api_calls']}")
    click.echo(f"Cache hits: {stats['total_cache_hits']}")
    click.echo(f"Cache hit rate: {stats['cache_hit_rate']}")

    # Per-agent stats
    click.echo("\nPer-Agent Stats:")
    for agent_id, agent in commander.agents.items():
        agent_stats = agent.get_token_stats()
        if agent_stats.get('status') != 'offline':
            click.echo(f"  - {agent_id}: {agent_stats.get('tokens_saved', 0):,} saved")


@token.command('test')
@click.option('--prompt', '-p', default='Explain quantum computing briefly.', help='Prompt to test')
def token_test(prompt):
    """Test token optimization on a prompt."""
    from .token_optimizer import TokenOptimizer

    optimizer = TokenOptimizer(enable_caching=False)

    original_len = len(prompt)
    optimized = optimizer.optimize_prompt(prompt, compress=True, max_words=100)
    optimized_len = len(optimized)

    reduction = ((original_len - optimized_len) / original_len) * 100

    click.echo("\n" + "=" * 50)
    click.echo("TOKEN OPTIMIZATION TEST")
    click.echo("=" * 50)

    click.echo(f"\nOriginal ({original_len} chars):")
    click.echo(f"  {prompt}")

    click.echo(f"\nOptimized ({optimized_len} chars):")
    click.echo(f"  {optimized}")

    click.echo(f"\nReduction: {reduction:.1f}%")


# =============================================================================
# Quick Commands
# =============================================================================

@cli.command('quick')
@click.option('--focus', '-f', default='AI developments', help='Focus area')
def quick(focus):
    """Quick intelligence scan (single burst with summary)."""
    from .mission_commander import MissionCommander

    click.echo(f"Running quick intelligence scan on: {focus}")

    commander = MissionCommander()

    async def run():
        return await commander.execute_burst_cycle([focus])

    findings = asyncio.run(run())

    click.echo(f"\n{'=' * 50}")
    click.echo(f"QUICK SCAN RESULTS: {focus}")
    click.echo(f"{'=' * 50}")

    # Show top findings
    high_priority = sorted(findings, key=lambda x: x.priority, reverse=True)[:5]
    for f in high_priority:
        click.echo(f"\n[P{f.priority}] {f.metadata.get('title', 'Finding')}")
        click.echo(f"  {f.content[:200]}...")


@cli.command('setup')
def setup():
    """Interactive setup wizard for first-time users."""
    import os

    click.echo("\n" + "=" * 60)
    click.echo("DEADMAN INTELLIGENCE COMMAND - SETUP WIZARD")
    click.echo("=" * 60)

    click.echo("\nWelcome! Let's get you set up.\n")

    # Step 1: Check Python version
    import sys
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        click.echo(f"[OK] Python version: {py_version}")
    else:
        click.echo(f"[!!] Python {py_version} detected. Python 3.10+ recommended.")

    # Step 2: Check API key
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if api_key:
        masked = api_key[:7] + "..." + api_key[-4:] if len(api_key) > 15 else "***"
        click.echo(f"[OK] ANTHROPIC_API_KEY found: {masked}")
    else:
        click.echo("\n[!!] ANTHROPIC_API_KEY not found!")
        click.echo("\n    To fix this:")
        click.echo("    1. Get your API key from: https://console.anthropic.com/")
        click.echo("    2. Set it in your environment:")
        click.echo("       Windows: set ANTHROPIC_API_KEY=sk-ant-xxxxx")
        click.echo("       Linux/Mac: export ANTHROPIC_API_KEY=sk-ant-xxxxx")
        click.echo("\n    Or create a .env file with:")
        click.echo("       ANTHROPIC_API_KEY=sk-ant-xxxxx")
        click.echo("\n    Note: The tool works in OFFLINE MODE without an API key.")
        click.echo("    You'll still get mock responses for testing.\n")

    # Step 3: Test imports
    click.echo("\nChecking components...")
    try:
        from .token_optimizer import TokenOptimizer
        click.echo("  [OK] Token Optimizer")
    except Exception as e:
        click.echo(f"  [!!] Token Optimizer: {e}")

    try:
        from .mission_commander import MissionCommander
        click.echo("  [OK] Mission Control")
    except Exception as e:
        click.echo(f"  [!!] Mission Control: {e}")

    try:
        from .research import ResearchScraper
        click.echo("  [OK] Research Scraper")
    except Exception as e:
        click.echo(f"  [!!] Research Scraper: {e}")

    try:
        from .updates import BriefingGenerator
        click.echo("  [OK] Daily Briefings")
    except Exception as e:
        click.echo(f"  [!!] Daily Briefings: {e}")

    try:
        from flask import Flask
        click.echo("  [OK] Web Dashboard (Flask)")
    except ImportError:
        click.echo("  [!!] Web Dashboard: pip install flask flask-socketio")

    # Step 4: Quick token optimization demo
    click.echo("\n" + "-" * 50)
    click.echo("QUICK DEMO: Token Optimization")
    click.echo("-" * 50)

    from .token_optimizer import PromptOptimizer
    opt = PromptOptimizer()

    original = "Please could you help me understand how this documentation works?"
    optimized = opt.compress_prompt(original)
    saved = ((len(original) - len(optimized)) / len(original)) * 100

    click.echo(f"\nOriginal: {original}")
    click.echo(f"Optimized: {optimized}")
    click.echo(f"Saved: {saved:.0f}% = {saved:.0f}% cost savings on API calls!")

    # Summary
    click.echo("\n" + "=" * 60)
    click.echo("SETUP COMPLETE!")
    click.echo("=" * 60)

    click.echo("\nTry these commands:")
    click.echo("  deadman-intel token test -p 'Your prompt here'")
    click.echo("  deadman-intel mission status")
    click.echo("  deadman-intel briefing generate")
    click.echo("  deadman-intel serve  # Web dashboard")

    click.echo("\nFor full documentation:")
    click.echo("  https://github.com/DeadManOfficial/DeadManIntelligenceCommand")
    click.echo("")


@cli.command('version')
def version():
    """Show version information."""
    click.echo("\nDeadMan Intelligence Command v1.0.0")
    click.echo("=" * 40)
    click.echo("Components:")
    click.echo("  - Mission Control (5 specialized agents)")
    click.echo("  - Token Optimizer (30-50% savings)")
    click.echo("  - Research Scraper")
    click.echo("  - Daily Briefings")
    click.echo("\nGitHub: https://github.com/DeadManOfficial/DeadManIntelligenceCommand")


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
