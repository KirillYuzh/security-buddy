#!/usr/bin/env python3
"""
Security Buddy Artifacts — SBOM, security todos, scan reports.

Artifacts are generated during the audit and saved alongside
the final report. Supported formats: CycloneDX SBOM, JSON findings,
developer TODO comments in source files.
"""

from .manager import ArtifactManager, generate_sbom, write_security_todos

__all__ = [
    "ArtifactManager",
    "generate_sbom",
    "write_security_todos",
]