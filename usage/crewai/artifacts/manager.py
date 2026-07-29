#!/usr/bin/env python3
"""
Artifact Manager — save, load, and convert security audit artifacts.

Artifacts include:
- CycloneDX SBOM files (JSON)
- Security TODO comments injected into source files
- Scan results from external tools
- Merged findings reports
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, TextIO

from usage.crewai.models import AuditReport, SBOM, SBOMComponent, SecurityTodo

logger = logging.getLogger("ArtifactManager")

DEFAULT_OUTPUT_ROOT = "/output"


class ArtifactManager:
    """
    Manages artifact output for a single audit run.

    Usage:
        am = ArtifactManager(audit_id="SB-2024-001", output_dir="/output/artifacts")
        am.save_report(report)
        am.save_sbom(sbom)
        am.save_todos(todos)
    """

    def __init__(self, audit_id: str = "unknown", output_dir: Optional[str] = None):
        self.audit_id = audit_id
        self.root = Path(output_dir or DEFAULT_OUTPUT_ROOT)
        self.reports_dir = self.root / "reports"
        self.sbom_dir = self.root / "sbom"
        self.todos_dir = self.root / "todos"
        self.scans_dir = self.root / "scans"

        for d in [self.reports_dir, self.sbom_dir, self.todos_dir, self.scans_dir]:
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def save_report(self, report: AuditReport, fmt: str = "json") -> str:
        """Save the audit report as JSON or Markdown."""
        if fmt == "json":
            path = self.reports_dir / f"{self.audit_id}_report.json"
            with open(path, "w") as f:
                json.dump(report.model_dump(), f, indent=2, default=str)
        elif fmt == "md":
            path = self.reports_dir / f"{self.audit_id}_report.md"
            with open(path, "w") as f:
                self._write_markdown_report(report, f)
        else:
            raise ValueError(f"Unsupported format: {fmt}")
        logger.info(f"Report saved: {path}")
        return str(path)

    def _write_markdown_report(self, report: AuditReport, f: TextIO) -> None:
        """Write a Markdown-formatted audit report."""
        f.write(f"# Security Audit: {self.audit_id}\n\n")
        f.write(f"**Summary:** {report.summary}\n\n")
        f.write(f"**Overall Score:** {report.overall_score}/10\n")
        f.write(f"**Risk Score:** {report.risk_score}/10\n\n")

        f.write("## Finding Summary\n\n")
        f.write(f"| Severity | Count |\n|---------|-------|\n")
        f.write(f"| Critical | {report.critical_count} |\n")
        f.write(f"| High     | {report.high_count} |\n")
        f.write(f"| Medium   | {report.medium_count} |\n")
        f.write(f"| Low      | {report.low_count} |\n\n")

        f.write("## Findings\n\n")
        for finding in report.findings:
            cwe_str = f" ({finding.cwe})" if finding.cwe else ""
            f.write(f"### {finding.id} — [{finding.severity}]{cwe_str}\n\n")
            f.write(f"**Location:** {finding.location}\n\n")
            f.write(f"{finding.description}\n\n")
            f.write(f"**Impact:** {finding.technical_impact}\n\n")
            if finding.business_impact:
                f.write(f"**Business Impact:** {finding.business_impact}\n\n")
            f.write(f"**Remediation:** {finding.remediation}\n\n")
            if finding.mitre_attack:
                f.write(f"**MITRE ATT&CK:** {finding.mitre_attack}\n\n")
            f.write("---\n\n")

        if report.exploit_chains:
            f.write("## Exploit Chains\n\n")
            for chain in report.exploit_chains:
                f.write(f"### {chain.chain_id} — [{chain.severity}]\n\n")
                for i, step in enumerate(chain.attack_path, 1):
                    f.write(f"{i}. {step}\n")
                f.write(f"\n**Impact:** {chain.technical_impact}\n\n")
                f.write(f"**Chain-Breaking Fix:** {chain.chain_breaking_fix}\n\n")
                f.write("---\n\n")

        if report.strategic_recommendations:
            f.write("## Strategic Recommendations\n\n")
            for rec in report.strategic_recommendations:
                f.write(f"- {rec}\n")
            f.write("\n")

    # ------------------------------------------------------------------
    # SBOM
    # ------------------------------------------------------------------

    def save_sbom(self, sbom: SBOM) -> str:
        """Save a CycloneDX-format SBOM as JSON."""
        path = self.sbom_dir / f"{self.audit_id}_sbom.json"
        data = {
            "bomFormat": sbom.format,
            "specVersion": sbom.spec_version,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [{"name": "Security Buddy", "version": "1.0"}],
            },
            "components": [
                {
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "licenses": (
                        [{"license": {"id": c.license}}] if c.license else []
                    ),
                    "purl": c.purl,
                }
                for c in sbom.components
            ],
            "vulnerabilities": [
                {
                    "id": vid,
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"},
                    "ratings": [],
                }
                for vid in sbom.vulnerabilities
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"SBOM saved: {path}")
        return str(path)

    # ------------------------------------------------------------------
    # Security TODOs
    # ------------------------------------------------------------------

    def save_todos(self, todos: list[SecurityTodo], base_path: str = "/project") -> list[str]:
        """
        Write security TODO comments into source files.

        Returns list of (file, line) tuples where comments were inserted.
        """
        written = []
        for todo in todos:
            file_path = os.path.join(base_path, todo.file_path.strip("/").lstrip("/"))
            if not os.path.exists(file_path):
                logger.warning(f"TODO target file does not exist: {file_path}")
                continue

            severity_tag = f"[{todo.severity}]" if todo.severity else "[INFO]"
            cwe_tag = f" ({todo.cwe})" if todo.cwe else ""
            comment = f"// TODO: {severity_tag}{cwe_tag} {todo.comment}"
            if todo.finding_id:
                comment += f" — {todo.finding_id}"

            try:
                with open(file_path, "r") as f:
                    lines = f.readlines()
            except Exception as e:
                logger.warning(f"Failed to read {file_path}: {e}")
                continue

            line_idx = todo.line_number - 1
            if line_idx < 0 or line_idx > len(lines):
                line_idx = len(lines)  # append at end
            lines.insert(line_idx, comment + "\n")

            try:
                with open(file_path, "w") as f:
                    f.writelines(lines)
                written.append((file_path, todo.line_number))
                logger.info(f"TODO written to {file_path}:{todo.line_number}")
            except Exception as e:
                logger.warning(f"Failed to write TODO to {file_path}: {e}")

        return written

    # ------------------------------------------------------------------
    # Scan results
    # ------------------------------------------------------------------

    def save_scan_result(self, scanner_name: str, result: dict) -> str:
        """Save a raw scan result as JSON."""
        path = self.scans_dir / f"{scanner_name}_{self.audit_id}.json"
        with open(path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        logger.info(f"Scan result saved: {path}")
        return str(path)

    def list_artifacts(self) -> dict[str, list[str]]:
        """List all saved artifacts by category."""
        return {
            "reports": sorted(str(p) for p in self.reports_dir.glob("*")),
            "sbom": sorted(str(p) for p in self.sbom_dir.glob("*")),
            "todos": sorted(str(p) for p in self.todos_dir.glob("*")),
            "scans": sorted(str(p) for p in self.scans_dir.glob("*")),
        }


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def generate_sbom(components: list[dict], vulnerabilities: Optional[list[str]] = None) -> SBOM:
    """
    Quick SBOM builder from component dicts.

    Args:
        components: list of dicts with keys: name, version, license (optional), purl (optional)
        vulnerabilities: list of CVE IDs
    """
    return SBOM(
        components=[
            SBOMComponent(
                name=c["name"],
                version=c["version"],
                license=c.get("license"),
                purl=c.get("purl"),
            )
            for c in components
        ],
        vulnerabilities=vulnerabilities or [],
    )


def write_security_todos(
    todos: list[SecurityTodo],
    project_path: str = "/project",
    output_dir: str = "/output/todos",
) -> list[str]:
    """Quick one-off: write TODOs and return list of written file paths."""
    am = ArtifactManager(audit_id="quick-scan", output_dir=output_dir)
    return am.save_todos(todos, base_path=project_path)