#!/usr/bin/env python3
"""
Security Buddy Tools — external security scanner integration.

Tools like semgrep, trivy, grype, syft, nuclei, etc. are downloaded
on-demand per config and exposed to CrewAI agents as custom tools.
"""

from .scanner_pool import (
    ScannerPool,
    ScannerTool,
    ensure_scanner,
    get_available_scanners,
    run_scanner,
)

__all__ = [
    "ScannerPool",
    "ScannerTool",
    "ensure_scanner",
    "get_available_scanners",
    "run_scanner",
]