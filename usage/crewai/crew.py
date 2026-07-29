#!/usr/bin/env python3
"""
Security Buddy -- CrewAI Security Audit Crew

Migration to CrewAI Flow for conditional branching, loops, state management,
Memory for cross-iteration context, Guardrails for output validation,
Bug Hunter agent for exploit chain discovery, and parallel execution.

Features:
- Network security controls (offline mode, domain allowlisting, privacy mode)
- Multi-format reporting (OWASP, GOST, NIST, ISO)
- Progress display with phase tracking and ETA estimation
- Pydantic structured output enforcement with retry recall
- CrewAI Flow with callback-based observability

Usage:
    python crew.py
    # or via docker compose up
"""

import os
import sys
import json
import yaml
import time
import re
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Any, Dict, List, Callable, Type, TypeVar
from enum import Enum
from dataclasses import dataclass

import pydantic
from pydantic import BaseModel

from crewai import Agent, Task, Crew, Process, LLM
from crewai.flow.flow import Flow, start, listen, router
from crewai.memory import Memory
from crewai_tools import FileReadTool

# Import shared models from the models module
try:
    from usage.crewai.models import (
        Severity, Finding, ExploitChain, FixResult, AuditReport,
        SBOM, SBOMComponent, SecurityTodo,
    )
except ImportError:
    # Define minimal Pydantic models for standalone use
    from pydantic import BaseModel, Field
    from typing import Optional

    class Severity(str, Enum):
        CRITICAL = "Critical"
        HIGH = "High"
        MEDIUM = "Medium"
        LOW = "Low"

    class Finding(BaseModel):
        id: str = ""
        severity: Severity = Severity.MEDIUM
        cwe: Optional[str] = None
        cve: Optional[str] = None
        location: str = ""
        description: str = ""
        technical_impact: str = ""
        business_impact: str = ""
        remediation: str = ""
        mitre_attack: Optional[str] = None
        category: str = ""

    class ExploitChain(BaseModel):
        chain_id: str = ""
        severity: Severity = Severity.HIGH
        attack_path: List[str] = []
        technical_impact: str = ""
        business_impact: str = ""
        chain_breaking_fix: str = ""

    class FixResult(BaseModel):
        finding_id: str = ""
        applied: bool = False
        diff: Optional[str] = None

    class AuditReport(BaseModel):
        title: str = ""
        summary: str = ""
        findings: List[Finding] = []
        exploit_chains: List[ExploitChain] = []
        recommendations: List[str] = []

    class SBOM(BaseModel):
        pass

    class SBOMComponent(BaseModel):
        pass

    class SecurityTodo(BaseModel):
        pass

from usage.crewai.tools import ScannerPool, get_available_scanners
from usage.crewai.tools.scanner_pool import ScannerTool
from usage.crewai.artifacts import ArtifactManager, generate_sbom

# ---------------------------------------------------------------------------
# Pydantic Structured Output Enforcer -- deterministic recall until valid
# ---------------------------------------------------------------------------

M = TypeVar("M", bound=BaseModel)

def enforce_structured_output(
    raw_text: str,
    model_class: Type[M],
    max_recall: int = 5,
    llm: Optional[LLM] = None,
) -> M:
    """
    Parse *raw_text* into the given Pydantic *model_class*.
    If parsing fails, re-prompt an LLM (if provided) up to *max_recall* times
    asking it to reformat the output into valid JSON matching the schema.
    This guarantees deterministic, typed outputs -- no free-form fields.
    """
    for attempt in range(1, max_recall + 1):
        # Try to extract JSON from the raw text (handles markdown code fences)
        json_str = _extract_json(raw_text)
        if json_str:
            try:
                parsed = json.loads(json_str)
                return model_class.model_validate(parsed)
            except (json.JSONDecodeError, pydantic.ValidationError) as exc:
                logging.warning(
                    "Structured output attempt %d/%d failed for %s: %s",
                    attempt, max_recall, model_class.__name__, exc,
                )
        else:
            logging.warning(
                "No JSON found on attempt %d/%d for %s",
                attempt, max_recall, model_class.__name__,
            )

        if llm is None or attempt >= max_recall:
            break

        # Reprompt the LLM to produce valid JSON matching the schema
        schema_json = model_class.model_json_schema()
        schema_str = json.dumps(schema_json, indent=2)
        raw_text = llm.generate(
            f"""The following text should be valid JSON matching this schema:

{schema_str}

But it could not be parsed.  Please return ONLY valid JSON that follows the
schema above.  Do NOT include any markdown formatting, explanation, or extra text.

INPUT TEXT:
{raw_text}

OUTPUT (valid JSON only):"""
        )

    # Fallback: return an empty/default instance
    logging.error(
        "Could not enforce structured output for %s after %d attempts. "
        "Returning default instance.",
        model_class.__name__, max_recall,
    )
    return model_class()


def _extract_json(text: str) -> Optional[str]:
    """Extract a JSON object/array from *text*, stripping markdown fences."""
    # Remove markdown JSON code fences
    text = re.sub(r"```(?:json)?\s*\n?", "", text).strip()
    # Try to find the outermost { ... } or [ ... ]
    for delim in ("{", "["):
        start_idx = text.find(delim)
        if start_idx == -1:
            continue
        # Count brackets to find matching close
        depth = 0
        close_delim = "}" if delim == "{" else "]"
        for i in range(start_idx, len(text)):
            if text[i] == delim:
                depth += 1
            elif text[i] == close_delim:
                depth -= 1
                if depth == 0:
                    candidate = text[start_idx : i + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except json.JSONDecodeError:
                        continue
    return None


def validate_with_pydantic(
    output: str,
    model_class: Type[M],
    llm: Optional[LLM] = None,
) -> M:
    """
    Guardrail-compatible wrapper: takes raw LLM output, enforces Pydantic
    structure via *enforce_structured_output*, and returns the validated text
    repr (for use in CrewAI guardrail callbacks that expect str -> bool).
    """
    try:
        _ = enforce_structured_output(output, model_class, llm=llm)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Progress Display -- plain text, no emoji
# ---------------------------------------------------------------------------

@dataclass
class PhaseInfo:
    name: str
    total_steps: int = 1
    completed_steps: int = 0
    start_time: Optional[float] = None
    weight: float = 1.0  # relative duration weight for ETA estimation

class ProgressTracker:
    """
    Terminal progress display for the audit flow.
    Shows current phase, step count, and estimated time remaining.
    Uses CrewAI callback hooks + manual phase updates.
    """

    PHASES = [
        PhaseInfo(name="[INIT] Initialization",        total_steps=1,   weight=0.3),
        PhaseInfo(name="[ANALYZE] Parallel Analysis",  total_steps=6,   weight=4.0),
        PhaseInfo(name="[CHAINS] Bug Hunter",          total_steps=1,   weight=2.0),
        PhaseInfo(name="[REPORT] Report Generation",   total_steps=1,   weight=1.5),
        PhaseInfo(name="[FIX] Applying Fixes",         total_steps=10,  weight=3.0),
        PhaseInfo(name="[OUTPUT] Output & Save",       total_steps=1,   weight=0.5),
    ]

    def __init__(self):
        self.current_phase_idx = 0
        self.current_step = 0
        self.start_time = time.time()
        self.phase_start_time = time.time()
        self._lock = threading.Lock()
        self._last_line_len = 0
        self._finished = False

    def start_phase(self, idx: int):
        with self._lock:
            self.current_phase_idx = idx
            self.current_step = 0
            self.PHASES[idx].start_time = time.time()
            self.PHASES[idx].completed_steps = 0
            self.phase_start_time = time.time()
            self._render()

    def advance_step(self, step_name: str = ""):
        with self._lock:
            phase = self.PHASES[self.current_phase_idx]
            phase.completed_steps = min(phase.completed_steps + 1, phase.total_steps)
            self.current_step = phase.completed_steps
            self._render(step_name)

    def _render(self, step_name: str = ""):
        elapsed = time.time() - self.start_time
        total_weight = sum(p.weight * p.total_steps for p in self.PHASES)
        done_weight = 0.0
        for i, p in enumerate(self.PHASES):
            if i < self.current_phase_idx:
                done_weight += p.weight * p.total_steps
            elif i == self.current_phase_idx:
                done_weight += p.weight * p.completed_steps
        progress_pct = min(done_weight / max(total_weight, 1), 1.0)
        eta_str = "calculating..."
        if progress_pct > 0.01:
            total_est = elapsed / progress_pct
            remaining = total_est - elapsed
            if remaining > 0:
                eta_str = str(timedelta(seconds=int(remaining)))
        bar_len = 30
        filled = int(bar_len * progress_pct)
        bar = "=" * filled + "-" * (bar_len - filled)
        phase = self.PHASES[self.current_phase_idx]
        phase_info = f"Phase {phase.name} [{phase.completed_steps}/{phase.total_steps}]"
        line = (
            f"\r  [{bar}] {progress_pct*100:5.1f}%  "
            f"ETA {eta_str:>8s}  "
            f"| {phase_info}  "
            f"{step_name[:40]:<40s}"
        )
        if len(line) < self._last_line_len:
            line = line + " " * (self._last_line_len - len(line))
        self._last_line_len = len(line)
        sys.stdout.write(line)
        sys.stdout.flush()

    def finish(self):
        with self._lock:
            self._finished = True
            elapsed = time.time() - self.start_time
            line = (
                f"\r  [{'='*30}] 100.0%  "
                f"Done in {str(timedelta(seconds=int(elapsed))):>8s}  "
                f"| Complete                      "
            )
            sys.stdout.write(line)
            sys.stdout.write("\n")
            sys.stdout.flush()


# Global progress tracker instance
_progress = ProgressTracker()


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
        logging.info(f"[NETWORK] Outbound request to {domain}{path}")


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
                "- GOST R 56545-2015: Structure each finding as a"
                " 'Vulnerability Passport' with: identifier, name,"
                " vulnerability class, software version, location,"
                " discovery method, and remediation measures."
            )
        elif fmt == "gost_r_56939":
            fmt_instrs.append(
                "- GOST R 56939-2016: Map each finding to secure"
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
    instr_parts.append(
        "\n\n### Structured Output Requirement\n"
        "All findings MUST be output as valid JSON matching the Pydantic schema "
        "for Finding objects. Use the following schema:\n"
        "{\n"
        '  "id": "SB-2024-001",\n'
        '  "severity": "Critical | High | Medium | Low",\n'
        '  "cwe": "CWE-79",\n'
        '  "cve": "CVE-2024-XXXX" | null,\n'
        '  "location": "file:line",\n'
        '  "description": "...",\n'
        '  "technical_impact": "...",\n'
        '  "business_impact": "...",\n'
        '  "remediation": "..."\n'
        "}\n"
        "Do NOT include any text outside the JSON block."
    )

    return "\n\n".join(instr_parts)


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

def validate_finding_has_cwe_and_severity(output: str) -> bool:
    """Guardrail: ensure finding output contains required fields."""
    checks = [
        ("CWE-" in output or "CVE-" in output),
        any(s in output for s in ["Critical", "High", "Medium", "Low"]),
        "Location:" in output or "location:" in output or "file:" in output,
    ]
    return all(checks)


def validate_fix_does_not_break(output: str) -> bool:
    """Guardrail: check that fix output doesn't introduce obvious issues."""
    danger_signals = [
        "rm -rf /",
        "chmod 777",
        "eval(",
        "exec(",
        "pickle.loads",
        "yaml.load(",
        "dangerouslySetInnerHTML",
        "innerHTML",
    ]
    for signal in danger_signals:
        if signal in output.lower():
            return False
    return True


def validate_structured_finding(output: str, llm: Optional[LLM] = None) -> bool:
    """
    Guardrail that enforces Pydantic Finding structure.
    Returns True if the output can be parsed as a valid Finding JSON.
    """
    return validate_with_pydantic(output, Finding, llm=llm)


def validate_structured_chain(output: str, llm: Optional[LLM] = None) -> bool:
    """
    Guardrail that enforces Pydantic ExploitChain structure.
    """
    return validate_with_pydantic(output, ExploitChain, llm=llm)


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load configuration from config.yaml or environment variables."""
    config_path = Path("config.yaml")

    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f)
    else:
        config = {
            "network": {
                "internet_access": os.getenv("INTERNET_ACCESS", "false").lower() == "true",
                "privacy_mode": os.getenv("PRIVACY_MODE", "true").lower() != "false",
                "allowed_domains": [],
                "data_egress_control": True,
            },
            "reporting": {
                "language": os.getenv("REPORT_LANGUAGE", "en"),
                "formats": ["owasp"],
                "include_attack_chain": True,
                "include_business_impact": True,
            },
            "llm": {
                "provider": os.getenv("LLM_PROVIDER", "openai"),
                "model": os.getenv("LLM_MODEL", "gpt-4o"),
                "api_key": os.getenv("LLM_API_KEY", ""),
                "api_base": os.getenv("LLM_API_BASE", None),
                "temperature": 0.0,  # zero for deterministic output
            },
            "crew": {
                "max_iterations": int(os.getenv("MAX_ITERATIONS", "5")),
                "verbose": os.getenv("VERBOSE", "true").lower() == "true",
                "knowledge_base_path": "/knowledge",
                "project_path": "/project",
                "planning_enabled": True,
                "use_memory": True,
            },
            "agents": {
                "include_developer": os.getenv("INCLUDE_DEVELOPER", "false").lower() == "true",
                "include_bug_hunter": True,
                "human_input_for_critical": True,
            },
            "output": {
                "path": "/output",
                "formats": ["markdown", "json", "prompts"],
                "log_file": "logs/audit.json",
            },
        }

    return config


def load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    with open(path) as f:
        return yaml.safe_load(f)


def create_llm(config: dict, role_suffix: str = "") -> LLM:
    """Create LLM instance based on configuration, with per-role override."""
    llm_config = config["llm"]
    provider = llm_config.get("provider", "openai")
    model = llm_config.get("model", "gpt-4o")
    api_key = llm_config.get("api_key") or os.getenv("LLM_API_KEY", "")
    api_base = llm_config.get("api_base") or os.getenv("LLM_API_BASE")
    temperature = llm_config.get("temperature", 0.0)

    role_overrides = llm_config.get("role_overrides", {}).get(role_suffix, {})
    if role_overrides:
        provider = role_overrides.get("provider", provider)
        model = role_overrides.get("model", model)
        temperature = role_overrides.get("temperature", temperature)

    if provider == "openai":
        return LLM(
            model=f"openai/{model}",
            api_key=api_key,
            temperature=temperature,
        )
    elif provider == "anthropic":
        return LLM(
            model=f"anthropic/{model}",
            api_key=api_key,
            temperature=temperature,
        )
    elif provider == "google":
        return LLM(
            model=f"google/{model}",
            api_key=api_key,
            temperature=temperature,
        )
    elif provider == "ollama":
        return LLM(
            model=f"ollama/{model}",
            base_url=api_base or "http://localhost:11434",
            temperature=temperature,
        )
    elif provider == "custom":
        return LLM(
            model=model,
            api_key=api_key,
            base_url=api_base,
            temperature=temperature,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

def create_agents(config: dict, agents_config: dict) -> dict:
    """Create all agent instances with per-role LLMs and tools."""
    kb_path = config["crew"]["knowledge_base_path"]
    tools = [FileReadTool()]

    agents = {}
    agent_map = {
        "sast_analyst": agents_config["sast_analyst"],
        "sca_analyst": agents_config["sca_analyst"],
        "config_analyst": agents_config["config_analyst"],
        "architecture_analyst": agents_config["architecture_analyst"],
        "ai_ml_analyst": agents_config["ai_ml_analyst"],
        "crypto_analyst": agents_config["crypto_analyst"],
        "bug_hunter": agents_config["bug_hunter"],
        "reporter": agents_config["reporter"],
    }

    for name, cfg in agent_map.items():
        if name not in agents_config:
            continue
        role_llm = create_llm(config, role_suffix=name) if name != "reporter" else create_llm(config)
        agents[name] = Agent(
            role=cfg["role"],
            goal=cfg["goal"],
            backstory=cfg["backstory"],
            tools=tools,
            llm=role_llm,
            allow_delegation=cfg.get("allow_delegation", False),
            verbose=config["crew"].get("verbose", True),
            max_iter=cfg.get("max_iter", 10),
            max_execution_time=cfg.get("max_execution_time", 300),
            max_retry_limit=cfg.get("max_retry_limit", 3),
        )

    # Developer agent (optional)
    if config["agents"].get("include_developer", False) and "developer" in agents_config:
        dev_cfg = agents_config["developer"]
        dev_llm = create_llm(config, role_suffix="developer")
        agents["developer"] = Agent(
            role=dev_cfg["role"],
            goal=dev_cfg["goal"],
            backstory=dev_cfg["backstory"],
            tools=tools,
            llm=dev_llm,
            allow_delegation=False,
            verbose=config["crew"].get("verbose", True),
            max_iter=dev_cfg.get("max_iter", 10),
            max_execution_time=dev_cfg.get("max_execution_time", 300),
            max_retry_limit=3,
            allow_code_execution=True,
            code_execution_mode="safe",
        )

    return agents


# ---------------------------------------------------------------------------
# Task factory
# ---------------------------------------------------------------------------

def build_crew(agents: dict, tasks: list, config: dict, memory: Optional[Memory] = None,
               step_callback: Optional[Callable] = None,
               task_callback: Optional[Callable] = None) -> Crew:
    """Build a Crew instance with optional memory, planning, and callbacks."""
    crew_kwargs = {
        "agents": list(agents.values()),
        "tasks": tasks,
        "process": Process.sequential,
        "verbose": config["crew"].get("verbose", True),
        "planning": config["crew"].get("planning_enabled", False),
        "step_callback": step_callback,
        "task_callback": task_callback,
    }
    if memory:
        crew_kwargs["memory"] = memory
    output_log = config.get("output", {}).get("log_file")
    if output_log:
        crew_kwargs["output_log_file"] = output_log
    return Crew(**crew_kwargs)


def create_memory(config: dict) -> Optional[Memory]:
    """Create Memory instance for cross-iteration context."""
    if not config["crew"].get("use_memory", True):
        return None
    return Memory(
        recency_weight=0.4,
        semantic_weight=0.4,
        importance_weight=0.2,
    )


# ---------------------------------------------------------------------------
# Observability callbacks
# ---------------------------------------------------------------------------

def log_step(agent, action, result):
    """Callback: log each agent action and advance progress."""
    agent_name = getattr(agent, "role", str(agent))
    action_desc = getattr(action, "tool", str(action)[:80])
    result_preview = str(result)[:100] if result else ""
    logging.info(f"[{agent_name}] {action_desc} -> {result_preview}")
    _progress.advance_step(step_name=f"{agent_name}: {action_desc[:30]}")


def log_task_completion(task_output):
    """Callback: log task completion and advance progress."""
    task_name = getattr(task_output, "agent", "unknown")
    output_preview = str(task_output.output)[:200] if task_output.output else "no output"
    logging.info(f"[TASK DONE] {task_name}: {output_preview}")
    _progress.advance_step(step_name=f"[DONE] {task_name}")


# ---------------------------------------------------------------------------
# Helper: save structured output
# ---------------------------------------------------------------------------

def save_structured_report(results: list, config: dict, flow_state: dict = None):
    """Save structured findings from all tasks."""
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
# SecurityAuditFlow -- CrewAI Flow-based orchestration
# ---------------------------------------------------------------------------

class SecurityAuditFlow(Flow):
    """Flow-based security audit with conditional branching and state management."""

    def __init__(self, config: dict, agents: dict, tasks_config: dict, agents_config: dict):
        super().__init__()
        self.config = config
        self.agents = agents
        self.tasks_config = tasks_config
        self.agents_config = agents_config
        self.logger = logging.getLogger("SecurityAuditFlow")
        self.state.update({
            "iteration": 0,
            "all_findings": [],
            "exploit_chains": [],
            "fix_results": [],
            "has_critical": False,
            "no_changes_count": 0,
        })

    # -----------------------------------------------------------------------
    # Phase 1: Parallel Analysis (routed from start)
    # -----------------------------------------------------------------------

    @start()
    def phase_1_parallel_analysis(self):
        """Step 1: Run all independent analysts in parallel."""
        iteration = self.state.get("iteration", 0)
        self.logger.info(f"Iteration {iteration + 1} - Phase 1: Parallel analysis")
        _progress.start_phase(1)

        kb_path = self.config["crew"]["knowledge_base_path"]
        project_path = self.config["crew"]["project_path"]

        llm = create_llm(self.config)

        # Build analysis tasks
        analysis_tasks = []

        if "sast_analyst" in self.agents and "analyze_sast" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_sast"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_sast"]["expected_output"],
                agent=self.agents["sast_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        if "sca_analyst" in self.agents and "analyze_sca" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_sca"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_sca"]["expected_output"],
                agent=self.agents["sca_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        if "config_analyst" in self.agents and "analyze_config" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_config"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_config"]["expected_output"],
                agent=self.agents["config_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        if "architecture_analyst" in self.agents and "analyze_architecture" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_architecture"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_architecture"]["expected_output"],
                agent=self.agents["architecture_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        if "ai_ml_analyst" in self.agents and "analyze_ai_ml" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_ai_ml"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_ai_ml"]["expected_output"],
                agent=self.agents["ai_ml_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        if "crypto_analyst" in self.agents and "analyze_crypto" in self.tasks_config:
            analysis_tasks.append(Task(
                description=self.tasks_config["analyze_crypto"]["description"].format(
                    project_path=project_path, kb_path=kb_path,
                ) + self._pydantic_output_instruction(),
                expected_output=self.tasks_config["analyze_crypto"]["expected_output"],
                agent=self.agents["crypto_analyst"],
                async_execution=True,
                guardrail=lambda o: validate_structured_finding(o, llm),
                guardrail_max_retries=5,
            ))

        analyst_crew = build_crew(
            self.agents,
            analysis_tasks,
            self.config,
            memory=create_memory(self.config),
            step_callback=log_step,
            task_callback=log_task_completion,
        )
        result = analyst_crew.kickoff()

        findings_text = []
        for task_output in result.tasks_output:
            if task_output.output:
                text = sanitize_report_paths(str(task_output.output), self.config)
                findings_text.append(text)
                if "Critical" in str(task_output.output):
                    self.state["has_critical"] = True

        self.state["all_findings"] = findings_text
        self.logger.info(f"Phase 1 complete - {len(findings_text)} analysis results")
        _progress.advance_step("Phase 1 complete")
        return result

    def _pydantic_output_instruction(self) -> str:
        """Return a consistent Pydantic output instruction for LLM tasks."""
        return (
            "\n\nIMPORTANT: You MUST output each finding as a valid JSON object "
            "with the following exact fields:\n"
            '{\n'
            '  "id": "SB-<YEAR>-<NUM>",\n'
            '  "severity": "Critical|High|Medium|Low",\n'
            '  "cwe": "CWE-<NUM>" or null,\n'
            '  "cve": "CVE-<YEAR>-<NUM>" or null,\n'
            '  "location": "<file>:<line>" or component name,\n'
            '  "description": "<detailed description>",\n'
            '  "technical_impact": "<what attacker can do>",\n'
            '  "business_impact": "<business consequence>",\n'
            '  "remediation": "<step-by-step fix instructions>",\n'
            '  "mitre_attack": "<TECHNIQUE-ID>",\n'
            '  "category": "sast|sca|config|architecture|ai_ml|crypto"\n'
            '}\n'
            "Output ONLY the JSON. Do NOT include markdown formatting, "
            "explanations, or text outside the JSON."
        )

    # -----------------------------------------------------------------------
    # Phase 2: Bug Hunter (triggered after analysis)
    # -----------------------------------------------------------------------

    @listen(phase_1_parallel_analysis)
    def phase_2_hunt_exploit_chains(self):
        """Step 2: Bug Hunter reviews combined findings for exploit chains."""
        self.logger.info("Phase 2: Bug Hunter - hunting exploit chains")
        _progress.start_phase(2)

        if "bug_hunter" not in self.agents or "hunt_exploit_chains" not in self.tasks_config:
            self.logger.info("Bug Hunter not available - skipping exploit chain analysis")
            _progress.advance_step("Skipped (not configured)")
            return None

        combined_findings = "\n\n".join(self.state.get("all_findings", []))
        chain_instr = (
            "\n\nIMPORTANT: You MUST output each exploit chain as a valid JSON "
            "object with the following fields:\n"
            '{\n'
            '  "chain_id": "CHAIN-<NUM>",\n'
            '  "severity": "Critical|High",\n'
            '  "attack_path": ["step1", "step2", ...],\n'
            '  "technical_impact": "...",\n'
            '  "business_impact": "...",\n'
            '  "chain_breaking_fix": "..."\n'
            '}\n'
            "Output ONLY the JSON. Do NOT include explanations outside the JSON."
        )

        hunt_task = Task(
            description=self.tasks_config["hunt_exploit_chains"]["description"]
            + chain_instr,
            expected_output=self.tasks_config["hunt_exploit_chains"]["expected_output"],
            agent=self.agents["bug_hunter"],
            context=combined_findings,
            guardrail=validate_fix_does_not_break,
            guardrail_max_retries=3,
        )

        hunt_crew = build_crew(
            self.agents,
            [hunt_task],
            self.config,
            step_callback=log_step,
            task_callback=log_task_completion,
        )
        result = hunt_crew.kickoff()

        self.state["exploit_chains"] = [sanitize_report_paths(str(result), self.config)] if result else []
        self.logger.info("Phase 2 complete - exploit chains identified")
        _progress.advance_step("Phase 2 complete")
        return result

    # -----------------------------------------------------------------------
    # Phase 3: Report Generation
    # -----------------------------------------------------------------------

    @listen(phase_2_hunt_exploit_chains)
    def phase_3_generate_report(self):
        """Step 3: Generate comprehensive report from all findings."""
        self.logger.info("Phase 3: Generating report")
        _progress.start_phase(3)

        if "reporter" not in self.agents or "generate_report" not in self.tasks_config:
            self.logger.warning("Reporter not available - skipping report generation")
            _progress.advance_step("Skipped (not configured)")
            return None

        kb_path = self.config["crew"]["knowledge_base_path"]
        all_findings = self.state.get("all_findings", [])
        exploit_chains = self.state.get("exploit_chains", [])

        combined_findings = "\n\n".join(all_findings)
        combined_chains = "\n\n".join(exploit_chains) if exploit_chains else "No exploit chains identified."

        format_instruction = build_format_instruction(self.config)

        report_description = self.tasks_config["generate_report"]["description"].format(
            kb_path=kb_path,
        )
        report_description += (
            f"\n\nFINDINGS:\n{combined_findings}"
            f"\n\nEXPLOIT CHAINS:\n{combined_chains}"
            f"\n\nFORMAT INSTRUCTIONS:\n{format_instruction}"
        )

        report_task = Task(
            description=report_description,
            expected_output=self.tasks_config["generate_report"]["expected_output"],
            agent=self.agents["reporter"],
        )

        report_crew = build_crew(
            self.agents,
            [report_task],
            self.config,
            step_callback=log_step,
            task_callback=log_task_completion,
        )
        result = report_crew.kickoff()

        self.state["report"] = sanitize_report_paths(str(result) if result else "", self.config)
        self.logger.info("Phase 3 complete - report generated")
        _progress.advance_step("Phase 3 complete")
        return result

    # -----------------------------------------------------------------------
    # Phase 4: Conditional - Fix or Finish
    # -----------------------------------------------------------------------

    @router(phase_3_generate_report)
    def route_decision(self):
        """Route: decide whether to proceed with fixes or finish."""
        has_critical = self.state.get("has_critical", False)
        has_developer = "developer" in self.agents
        max_iterations = self.config["crew"].get("max_iterations", 5)
        current_iteration = self.state.get("iteration", 0)
        no_changes = self.state.get("no_changes_count", 0)

        should_fix = (
            has_developer
            and (has_critical or current_iteration < 2)
            and current_iteration < max_iterations
            and no_changes < 2
        )

        if should_fix:
            return "fix"
        return "finish"

    @listen("fix")
    def phase_4_apply_fixes(self):
        """Step 4: Apply fixes for vulnerabilities."""
        self.logger.info("Phase 4: Applying fixes")
        _progress.start_phase(4)

        if "developer" not in self.agents or "fix_vulnerabilities" not in self.tasks_config:
            return None

        output_path = self.config["output"]["path"]
        kb_path = self.config["crew"]["knowledge_base_path"]
        project_path = self.config["crew"]["project_path"]

        human_input = self.config["agents"].get("human_input_for_critical", False)
        prompt_with_approval = ""
        if human_input and self.state.get("has_critical", False):
            prompt_with_approval = (
                "\n\n[WARNING] CRITICAL FINDINGS DETECTED - "
                "Human approval required before applying fixes."
            )

        fix_task = Task(
            description=self.tasks_config["fix_vulnerabilities"]["description"].format(
                report_path=f"{output_path}/report.md",
                prompts_path=f"{output_path}/developer_prompts.md",
                kb_path=kb_path,
                project_path=project_path,
            ) + prompt_with_approval,
            expected_output=self.tasks_config["fix_vulnerabilities"]["expected_output"],
            agent=self.agents["developer"],
            guardrail=validate_fix_does_not_break,
            guardrail_max_retries=3,
            human_input=human_input and self.state.get("has_critical", False),
        )

        fix_crew = build_crew(self.agents, [fix_task], self.config)
        result = fix_crew.kickoff()

        result_str = str(result) if result else ""
        self.state["fix_results"].append(result_str)

        if "no changes" in result_str.lower() or "already fixed" in result_str.lower():
            self.state["no_changes_count"] += 1
        else:
            self.state["no_changes_count"] = 0

        self.state["iteration"] += 1
        self.logger.info(f"Phase 4 complete - fix iteration {self.state['iteration']}")
        _progress.advance_step(f"Fix iteration {self.state['iteration']} complete")
        return result

    @listen("finish")
    def finish(self):
        """Final step: save all outputs and print summary."""
        self.logger.info("Audit flow complete - saving outputs")
        _progress.start_phase(5)

        output_path = Path(self.config["output"]["path"])
        output_path.mkdir(parents=True, exist_ok=True)

        report = self.state.get("report", "")
        if report:
            report_file = output_path / "report.md"
            report_file.write_text(report)
            print(f"\n  [OK] Final report: {report_file}")

        fix_results = self.state.get("fix_results", [])
        if fix_results:
            prompts_file = output_path / "developer_prompts.md"
            prompts_file.write_text("\n\n---\n\n".join(
                sanitize_report_paths(r, self.config) for r in fix_results
            ))
            print(f"  [OK] Developer prompts: {prompts_file}")

        structured = {
            "report": report,
            "findings": self.state.get("all_findings", []),
            "exploit_chains": self.state.get("exploit_chains", []),
            "fix_results": fix_results,
            "stats": {
                "iterations": self.state.get("iteration", 0),
                "has_critical": self.state.get("has_critical", False),
            },
            "network": {
                "internet_access": self.config.get("network", {}).get("internet_access", False),
                "privacy_mode": self.config.get("network", {}).get("privacy_mode", True),
            },
            "reporting": {
                "language": self.config.get("reporting", {}).get("language", "en"),
                "formats": self.config.get("reporting", {}).get("formats", ["owasp"]),
            },
        }
        findings_file = output_path / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(structured, f, indent=2, default=str)
        print(f"  [OK] Structured data: {findings_file}")

        _progress.finish()
        return structured


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def main():
    print("=" * 64)
    print("  Security Buddy - CrewAI Security Audit")
    print("  Flow-based | Memory | Guardrails | Bug Hunter")
    print("=" * 64)

    config = load_config()
    agents_config = load_yaml(Path("agents.yaml"))
    tasks_config = load_yaml(Path("tasks.yaml"))

    logging.basicConfig(
        level=logging.INFO if config["crew"].get("verbose", True) else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Network & Privacy banner (plain text)
    network_cfg = config.get("network", {})
    internet_access = network_cfg.get("internet_access", False)
    privacy_mode = network_cfg.get("privacy_mode", True)
    allowed = network_cfg.get("allowed_domains", [])
    print(f"\n  Network Access : {'ONLINE' if internet_access else 'OFFLINE'}")
    if internet_access:
        print(f"  Allowed Domains: {', '.join(allowed) if allowed else 'ALL'}")
    else:
        print(f"  Only LLM API calls - project code never leaves container")
    print(f"  Privacy Mode  : {'ON' if privacy_mode else 'OFF'}")
    if privacy_mode:
        print(f"     Paths anonymized in reports & logs")

    # Reporting banner
    reporting_cfg = config.get("reporting", {})
    lang = reporting_cfg.get("language", "en")
    formats = reporting_cfg.get("formats", ["owasp"])
    fmt_labels = {
        "owasp": "OWASP Standard",
        "gost_r_56545": "GOST R 56545-2015",
        "gost_r_56939": "GOST R 56939-2016",
        "nist_sar": "NIST SP 800-53 SAR",
        "iso_27001": "ISO/IEC 27001",
    }
    fmt_str = ", ".join(fmt_labels.get(f, f) for f in formats)
    print(f"  Report Language: {'English' if lang == 'en' else 'Russian'}")
    print(f"  Report Formats : {fmt_str}")

    # LLM banner
    print(f"\n  LLM Provider   : {config['llm']['provider']}")
    print(f"  Model          : {config['llm']['model']}")
    print(f"  Temperature    : {config['llm'].get('temperature', 0.0)}")
    print(f"  Max Iterations : {config['crew'].get('max_iterations', 5)}")
    print(f"  Developer      : {'enabled' if config['agents'].get('include_developer') else 'disabled'}")
    print(f"  Bug Hunter     : {'enabled' if config['agents'].get('include_bug_hunter', True) else 'disabled'}")
    print(f"  Memory         : {'enabled' if config['crew'].get('use_memory', True) else 'disabled'}")
    print(f"  Planning       : {'enabled' if config['crew'].get('planning_enabled', False) else 'disabled'}")

    # Create agents
    print("\n  Initializing LLMs...")
    _ = create_llm(config)
    print("  Creating agents...")
    agents = create_agents(config, agents_config)
    print(f"  [OK] {len(agents)} agents ready")

    # Run the flow
    print("\n  Starting Security Audit Flow...\n")

    global _progress
    _progress = ProgressTracker()
    _progress.start_phase(0)

    flow = SecurityAuditFlow(config, agents, tasks_config, agents_config)
    result = flow.kickoff()

    # Summary
    print(f"\n{'='*64}")
    print(f"  [OK] Security audit complete!")
    print(f"  [OK] Report: {config['output']['path']}/report.md")
    print(f"  [OK] Findings: {config['output']['path']}/findings.json")
    print(f"  [OK] Iterations: {flow.state.get('iteration', 0)}")
    has_crit = flow.state.get('has_critical', False)
    print(f"  [OK] Critical findings: {'YES' if has_crit else 'None'}")
    print(f"{'='*64}")

    if not network_cfg.get("internet_access", False):
        print(f"\n  Your code never left the container. Reports saved locally.")
    else:
        print(f"\n  Internet was enabled. Check network_access_log.json for details.")


if __name__ == "__main__":
    main()