#!/usr/bin/env python3
"""
Security Buddy — CrewAI Security Audit Crew

Entry point for the CrewAI-based security audit flow.

Features:
- Network security controls (offline mode, domain allowlisting, privacy mode)
- Multi-format reporting (OWASP, GOST, NIST, ISO)
- Progress display with phase tracking and ETA estimation
- Pydantic structured output enforcement with retry recall
- CrewAI Flow with callback-based observability

Usage:
    python -m usage.crewai.crew
    # or via docker compose up
"""

import os
import sys
import logging
from pathlib import Path

from usage.crewai.config import load_config, create_llm
from usage.crewai.network import (
    format_network_banner,
    format_reporting_banner,
    sanitize_report_paths,
)
from usage.crewai.progress import ProgressTracker

logger = logging.getLogger(__name__)


def print_banner(config: dict):
    """Print the startup banner with configuration overview."""
    print("=" * 64)
    print("  Security Buddy - CrewAI Security Audit")
    print("  Flow-based | Memory | Guardrails | Bug Hunter")
    print("=" * 64)

    # Network & Privacy
    print()
    print(format_network_banner(config))

    # Reporting
    print()
    print(format_reporting_banner(config))

    # LLM / Crew banner
    print()
    print(f"  LLM Provider   : {config['llm']['provider']}")
    print(f"  Model          : {config['llm']['model']}")
    print(f"  Temperature    : {config['llm'].get('temperature', 0.0)}")
    print(f"  Max Iterations : {config['crew'].get('max_iterations', 5)}")
    print(f"  Developer      : {'enabled' if config['agents'].get('include_developer') else 'disabled'}")
    print(f"  Bug Hunter     : {'enabled' if config['agents'].get('include_bug_hunter', True) else 'disabled'}")
    print(f"  Memory         : {'enabled' if config['crew'].get('use_memory', True) else 'disabled'}")
    print(f"  Planning       : {'enabled' if config['crew'].get('planning_enabled', False) else 'disabled'}")


def main():
    config = load_config()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO if config["crew"].get("verbose", True) else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Print startup banner
    print_banner(config)

    # Ensure OPENAI_API_KEY env var is set for LiteLLM compatibility
    if config.get("llm", {}).get("api_key"):
        os.environ["OPENAI_API_KEY"] = config["llm"]["api_key"]

    # Import and run the flow
    from usage.crewai.flow import run_flow

    result = run_flow(config)

    # Summary
    state = result.get("state", {})
    print(f"\n{'='*64}")
    print(f"  [OK] Security audit complete!")
    print(f"  [OK] Report: {config['output']['path']}/report.md")
    print(f"  [OK] Findings: {config['output']['path']}/findings.json")
    print(f"  [OK] Iterations: {state.get('iteration', 0)}")
    has_crit = state.get('has_critical', False)
    print(f"  [OK] Critical findings: {'YES' if has_crit else 'None'}")
    print(f"{'='*64}")

    network_cfg = config.get("network", {})
    if not network_cfg.get("internet_access", False):
        print(f"\n  Your code never left the container. Reports saved locally.")
    else:
        print(f"\n  Internet was enabled. Check network_access_log.json for details.")


if __name__ == "__main__":
    main()