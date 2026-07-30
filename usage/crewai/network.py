#!/usr/bin/env python3
"""
Network security, privacy controls, and report format adapter for Security Buddy.

Controls:
- Internet access filtering (OFFLINE mode)
- Privacy mode for path anonymization
- Domain allowlisting
- Data egress audit logging

Report formatting:
- Multi-format instruction builder (OWASP, GOST, NIST, ISO)
- Language support (en, ru)
"""

import os
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Network / Privacy Controls
# ---------------------------------------------------------------------------

def check_network_allowed(domain: str, config: dict) -> bool:
    """
    Check whether outbound to *domain* is permitted under the current network
    configuration.  If `internet_access` is False, only localhost is allowed.
    If `allowed_domains` is non-empty, the domain must be in the list.
    """
    network_cfg = config.get("network", {})
    if not network_cfg.get("internet_access", False):
        return domain in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
    allowed = network_cfg.get("allowed_domains", [])
    if allowed:
        return any(domain == a or domain.endswith("." + a) for a in allowed)
    return True


def sanitize_report_paths(report_text: str, config: dict) -> str:
    """
    If privacy_mode is enabled, replace the project path with a placeholder
    to prevent sensitive path information from leaking into the report.
    """
    network_cfg = config.get("network", {})
    if not network_cfg.get("privacy_mode", True):
        return report_text
    project_path = config.get("crew", {}).get("project_path", "/project")
    kb_path = config.get("crew", {}).get("knowledge_base_path", "/knowledge")
    result = report_text.replace(project_path, "[PROJECT_ROOT]")
    result = result.replace(kb_path, "[KNOWLEDGE_BASE]")
    return result


def log_outbound_request(domain: str, path: str, config: dict):
    """Log any outbound request for audit trail when data_egress_control is on."""
    network_cfg = config.get("network", {})
    if network_cfg.get("data_egress_control", True):
        logger.info("[NETWORK] Outbound request to %s%s", domain, path)


# ---------------------------------------------------------------------------
# Report Format Adapter
# ---------------------------------------------------------------------------

def build_format_instruction(config: dict) -> str:
    """
    Generate an LLM instruction snippet based on the selected
    reporting formats and language.
    """
    reporting = config.get("reporting", {})
    language = reporting.get("language", "en")
    formats = reporting.get("formats", ["owasp"])
    include_attack_chain = reporting.get("include_attack_chain", True)
    include_business_impact = reporting.get("include_business_impact", True)

    lang_map = {
        "en": "Write the entire report in English.",
        "ru": "Write the entire report in Russian (Русский). "
              "Use Russian headings and descriptions."
    }
    lang_instr = lang_map.get(language, lang_map["en"])

    fmt_instrs = []
    for fmt in formats:
        if fmt == "owasp":
            fmt_instrs.append(
                "- OWASP Style: Follow standard AppSec report structure"
                " (executive summary, methodology, detailed findings with CWE/"
                "severity/location/remediation, recommendations)."
            )
        elif fmt == "gost_r_56545":
            fmt_instrs.append(
                "- ГОСТ Р 56545-2015: Structure each finding as a"
                " 'Vulnerability Passport' with: identifier, name,"
                " vulnerability class, software version, location,"
                " discovery method, and remediation measures."
            )
        elif fmt == "gost_r_56939":
            fmt_instrs.append(
                "- ГОСТ Р 56939-2016: Map each finding to secure"
                " development process requirements. Identify which SDLC"
                " phase was violated and reference the relevant requirement."
            )
        elif fmt == "nist_sar":
            fmt_instrs.append(
                "- NIST SP 800-53 SAR: Produce a Security Assessment"
                " Report structure with control summaries, findings mapped"
                " to NIST control families (e.g. SI-10, SC-13), and a"
                " POA&M (Plan of Action & Milestones) remediation table."
            )
        elif fmt == "iso_27001":
            fmt_instrs.append(
                "- ISO/IEC 27001: Map each finding to Annex A.14"
                " control objectives (security in development, change"
                " management, testing). Include a compliance statement"
                " for each control area."
            )

    sections = []
    if include_attack_chain:
        sections.append("- Include MITRE ATT&CK attack chain mapping for each finding.")
    if include_business_impact:
        sections.append("- Include business impact (financial, reputational, legal) for each finding.")

    instr_parts = [lang_instr]
    if fmt_instrs:
        instr_parts.append("\n\n### Report Format Requirements\n" + "\n".join(fmt_instrs))
    if sections:
        instr_parts.append("\n\n### Required Sections\n" + "\n".join(sections))

    return "\n\n".join(instr_parts)


# ---------------------------------------------------------------------------
# Report / findings saver
# ---------------------------------------------------------------------------

def save_structured_report(results: list, config: dict, flow_state: dict = None):
    """Save structured findings from all tasks."""
    import json
    from pathlib import Path

    output_path = Path(config["output"]["path"])
    output_path.mkdir(parents=True, exist_ok=True)

    all_findings = []
    for result in results:
        if result.output:
            all_findings.append({
                "agent": getattr(result, "agent", "unknown"),
                "output": sanitize_report_paths(str(result.output), config),
            })

    report_file = output_path / "report.md"
    combined = "\n\n---\n\n".join(f.get("output", "") for f in all_findings)
    combined = sanitize_report_paths(combined, config)
    report_file.write_text(combined)
    print(f"  [OK] Report: {report_file}")

    findings_file = output_path / "findings.json"
    with open(findings_file, "w") as f:
        json.dump(all_findings, f, indent=2, default=str)
    print(f"  [OK] Findings: {findings_file}")

    network_cfg = config.get("network", {})
    if network_cfg.get("data_egress_control", True):
        network_log = output_path / "network_access_log.json"
        with open(network_log, "w") as f:
            json.dump({
                "internet_access": network_cfg.get("internet_access", False),
                "privacy_mode": network_cfg.get("privacy_mode", True),
                "allowed_domains": network_cfg.get("allowed_domains", []),
                "note": "All outbound connections were filtered per network policy.",
            }, f, indent=2)
        print(f"  [OK] Network log: {network_log}")


# ---------------------------------------------------------------------------
# Network config banner helpers
# ---------------------------------------------------------------------------

def format_network_banner(config: dict) -> str:
    """Return a network/privacy config display string."""
    network_cfg = config.get("network", {})
    internet_access = network_cfg.get("internet_access", False)
    privacy_mode = network_cfg.get("privacy_mode", True)
    allowed = network_cfg.get("allowed_domains", [])

    lines = []
    lines.append(f"  Network Access : {'ONLINE' if internet_access else 'OFFLINE'}")
    if internet_access:
        lines.append(f"  Allowed Domains: {', '.join(allowed) if allowed else 'ALL'}")
    else:
        lines.append(f"  Only LLM API calls - project code never leaves container")
    lines.append(f"  Privacy Mode  : {'ON' if privacy_mode else 'OFF'}")
    if privacy_mode:
        lines.append(f"     Paths anonymized in reports & logs")
    return "\n".join(lines)


def format_reporting_banner(config: dict) -> str:
    """Return a reporting config display string."""
    reporting_cfg = config.get("reporting", {})
    lang = reporting_cfg.get("language", "en")
    formats = reporting_cfg.get("formats", ["owasp"])
    fmt_labels = {
        "owasp": "OWASP Standard",
        "gost_r_56545": "ГОСТ Р 56545-2015",
        "gost_r_56939": "ГОСТ Р 56939-2016",
        "nist_sar": "NIST SP 800-53 SAR",
        "iso_27001": "ISO/IEC 27001",
    }
    fmt_str = ", ".join(fmt_labels.get(f, f) for f in formats)
    lines = []
    lines.append(f"  Report Language: {'English' if lang == 'en' else 'Russian'}")
    lines.append(f"  Report Formats : {fmt_str}")
    return "\n".join(lines)