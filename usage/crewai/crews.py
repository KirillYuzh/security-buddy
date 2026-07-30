#!/usr/bin/env python3
"""
Agent and Crew factory for Security Buddy.

Handles:
- Agent creation with per-role LLMs and tools
- Task creation with guardrails
- Building Crew instances with memory, planning, callbacks
- Memory creation compatible with CrewAI 0.80+
"""

import os
import json
import re
import logging
from pathlib import Path
from typing import Optional, Callable, Dict, List, Any, Type

from crewai import Agent, Task, Crew, Process, LLM
from crewai.memory import Memory
from crewai.tools import BaseTool
from crewai_tools import FileReadTool
from pydantic import BaseModel, Field

from usage.crewai.config import create_llm, load_config, get_effective_llm_model_name
from usage.crewai.guards import (
    validate_structured_finding,
    validate_or_accept,
    validate_fix_does_not_break,
    pydantic_output_instruction,
)

logger = logging.getLogger(__name__)


def create_memory(config: dict, llm: Optional[LLM] = None) -> Optional[Memory]:
    """
    Create Memory instance for cross-iteration context.

    AUTO-DISABLED for ollama/custom providers.

    CrewAI 0.80+'s memory analyzer has a HARDCODED model name ("gpt-5.4-mini")
    that it uses for query classification. This model will never exist on
    ollama or custom providers. While CrewAI falls back gracefully to default
    complexity, it first makes failing HTTP requests that produce 404 errors.

    For ollama and custom providers: memory is disabled to avoid these errors.
    For standard providers (openai/anthropic/google): memory works fully.
    """
    provider = config.get("llm", {}).get("provider", "openai")

    if not config["crew"].get("use_memory", True):
        return None

    # Auto-disable memory for ollama/custom providers -- CrewAI's memory
    # analyzer has a hardcoded model name ("gpt-5.4-mini") that won't exist
    # on these providers.
    if provider in ("ollama", "custom"):
        logger.info(
            "Memory disabled for provider '%s' -- CrewAI's memory analyzer "
            "has a hardcoded model name that is not available on this provider. "
            "Set use_memory: false in config.yaml to suppress this message.",
            provider,
        )
        return None

    try:
        # Try the newer CrewAI 0.80+ Memory constructor
        memory_kwargs: Dict[str, Any] = {
            "recency_weight": 0.4,
            "semantic_weight": 0.4,
            "importance_weight": 0.2,
        }
        if llm is not None:
            memory_kwargs["llm"] = llm
        return Memory(**memory_kwargs)
    except TypeError as e:
        logger.warning("Memory construction failed with kwargs: %s", e)
        # Fallback: Memory with no kwargs
        try:
            return Memory()
        except Exception as e2:
            logger.warning("Memory fallback also failed: %s", e2)
            return None


def build_crew(
    agents: Dict[str, Agent],
    tasks: List[Task],
    config: dict,
    memory: Optional[Memory] = None,
    step_callback: Optional[Callable] = None,
    task_callback: Optional[Callable] = None,
) -> Crew:
    """Build a Crew instance with optional memory, planning, and callbacks.

    NOTE: CrewAI's internal planning agent creates its own LLM instances using
    hardcoded model names (e.g. "gpt-4o-mini") via LiteLLM.  This means:
      - For 'custom' providers: the planner will use OPENAI_BASE_URL (set in
        __init__.py) to route to the custom endpoint, but the model name won't
        match.  We AUTO-DISABLE planning for custom and ollama providers.
      - For standard providers (openai/anthropic/google): planning works fine.
    """
    llm_provider = config.get("llm", {}).get("provider", "openai")
    planning_requested = config["crew"].get("planning_enabled", False)
    planning_effective = planning_requested

    if planning_requested and llm_provider in ("custom", "ollama"):
        logger.warning(
            "Planning is enabled but LLM provider is '%s'. "
            "CrewAI's internal planner uses hardcoded model names (e.g. "
            "'gpt-4o-mini') that won't match this provider's available models. "
            "Disabling planning automatically.  Set planning_enabled: false "
            "in config.yaml to suppress this warning.",
            llm_provider,
        )
        planning_effective = False

    crew_kwargs: Dict[str, Any] = {
        "agents": list(agents.values()),
        "tasks": tasks,
        "process": Process.sequential,
        "verbose": config["crew"].get("verbose", True),
        "planning": planning_effective,
    }

    # Only add callbacks if they are provided
    if step_callback:
        crew_kwargs["step_callback"] = step_callback
    if task_callback:
        crew_kwargs["task_callback"] = task_callback

    if memory:
        crew_kwargs["memory"] = memory

    # Add output log file if configured
    output_log = config.get("output", {}).get("log_file")
    if output_log:
        output_path = Path(config.get("output", {}).get("path", "/output"))
        log_path = output_path / output_log
        log_path.parent.mkdir(parents=True, exist_ok=True)
        crew_kwargs["output_log_file"] = str(log_path)

    return Crew(**crew_kwargs)


class ListDirectorySchema(BaseModel):
    """Input schema for list_directory tool."""
    path: str = Field(description="Directory path to list (e.g. /project, /knowledge)")

class FileReadSchema(BaseModel):
    """Input schema for SafeFileReadTool."""
    file_path: str = Field(description="Absolute path to the file to read (e.g. /project/src/main.py)")
    line_count: Optional[int] = Field(None, description="Number of lines to read (optional)")
    start_line: Optional[int] = Field(None, description="Starting line number (optional, 1-based)")

class ListDirectoryTool(BaseTool):
    """Tool for listing files and directories at a given path."""
    name: str = "list_directory"
    description: str = (
        "List files and directories at a given absolute path. "
        "IMPORTANT: Always use absolute paths starting with '/' (e.g. '/project', '/project/src'). "
        "Do NOT use placeholders like [PROJECT_ROOT] or relative paths. "
        "The project root is always '/project'. "
        "Pass the path as an argument."
    )
    args_schema: Type[BaseModel] = ListDirectorySchema

    def _normalize_path(self, path: str) -> str:
        """Normalize common hallucinated path patterns to real paths."""
        # Replace [PROJECT_ROOT] with /project
        path = path.replace("[PROJECT_ROOT]", "/project")
        # Remove leading "app/" or "./app" if it appears after /project
        # (e.g. "/project/app/src" -> "/project/src" if /project/app doesn't exist)
        return path

    def _run(self, path: str) -> str:
        """List the given directory path."""
        path = self._normalize_path(path)
        try:
            entries = os.listdir(path)
            files = []
            dirs = []
            for e in sorted(entries):
                full = os.path.join(path, e)
                if os.path.isfile(full):
                    files.append(e)
                elif os.path.isdir(full):
                    dirs.append(e)
            result = f"Directory: {path}\n"
            if dirs:
                result += "\nSubdirectories:\n" + "\n".join(f"  {d}/" for d in dirs)
            if files:
                result += "\nFiles:\n" + "\n".join(f"  {f}" for f in files)
            return result
        except PermissionError:
            return f"Error: Permission denied listing directory: {path}"
        except FileNotFoundError:
            return f"Error: Directory not found: {path}"
        except NotADirectoryError:
            return f"Error: Path is not a directory: {path}"
        except Exception as e:
            return f"Error listing directory {path}: {e}"

class SafeFileReadTool(BaseTool):
    """
    Custom file read tool that normalizes hallucinated paths before reading.
    
    Small models often hallucinate paths like:
    - "app/[PROJECT_ROOT]/Cargo.toml:1" (concatenates app/ with [PROJECT_ROOT] and appends :N)
    - "[PROJECT_ROOT]/src/main.py" (uses placeholder instead of /project)
    - "/project/app/src/main.py:42" (appends line number to path)
    
    This tool normalizes these patterns to valid absolute paths.
    """
    name: str = "read_a_files_content"
    description: str = (
        "Read the content of a file at a given path. "
        "IMPORTANT: Always use absolute paths starting with '/' (e.g. '/project/src/main.py'). "
        "Do NOT use placeholders like [PROJECT_ROOT] or relative paths. "
        "The project root is always '/project'. "
        "Pass the file_path as an argument."
    )
    args_schema: Type[BaseModel] = FileReadSchema

    def _normalize_path(self, path: str) -> str:
        """Normalize common hallucinated path patterns to real paths."""
        # Remove line number suffix like ":1", ":42"
        path = re.sub(r':\d+$', '', path)
        # Replace [PROJECT_ROOT] with /project
        path = path.replace("[PROJECT_ROOT]", "/project")
        # Remove leading "app/" or "./app" if it appears before /project
        # e.g. "app/[PROJECT_ROOT]/Cargo.toml" -> "/project/Cargo.toml"
        path = re.sub(r'^app/', '', path)
        path = re.sub(r'^\./app/', '', path)
        path = re.sub(r'^\./', '', path)
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        return path

    def _run(self, file_path: str, line_count: Optional[int] = None, start_line: Optional[int] = None) -> str:
        """Read the given file with path normalization."""
        file_path = self._normalize_path(file_path)
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            if start_line is not None or line_count is not None:
                lines = content.split('\n')
                s = (start_line or 1) - 1
                e = s + (line_count or len(lines))
                content = '\n'.join(lines[s:e])
            return content
        except FileNotFoundError:
            return f"Error: File not found at path: {file_path}"
        except PermissionError:
            return f"Error: Permission denied reading: {file_path}"
        except IsADirectoryError:
            return f"Error: Path is a directory, not a file: {file_path}"
        except Exception as e:
            return f"Error reading file {file_path}: {e}"

def create_agents(config: dict, agents_config: dict) -> Dict[str, Agent]:
    """Create all agent instances with per-role LLMs and tools."""
    tools = [
        SafeFileReadTool(),
        ListDirectoryTool(),
    ]

    agents = {}
    agent_map = {
        "sast_analyst": agents_config.get("sast_analyst"),
        "sca_analyst": agents_config.get("sca_analyst"),
        "config_analyst": agents_config.get("config_analyst"),
        "architecture_analyst": agents_config.get("architecture_analyst"),
        "ai_ml_analyst": agents_config.get("ai_ml_analyst"),
        "crypto_analyst": agents_config.get("crypto_analyst"),
        "bug_hunter": agents_config.get("bug_hunter"),
        "reporter": agents_config.get("reporter"),
    }

    for name, cfg in agent_map.items():
        if cfg is None:
            continue
        # Use role-specific LLM for each agent type
        role_llm = create_llm(config, role_suffix=name)
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


def _should_use_soft_guardrail(config: dict) -> bool:
    """
    Determine if soft guardrail should be used.
    Small local models (ollama) often cannot produce perfectly structured JSON,
    so we use a guardrail that warns but never rejects output.
    """
    provider = config.get("llm", {}).get("provider", "openai")
    return provider in ("ollama", "custom")


def build_analysis_tasks(config: dict, agents: Dict[str, Agent],
                         tasks_config: dict, llm: LLM) -> List[Task]:
    """
    Build the parallel analysis tasks for Phase 1.
    """
    kb_path = config["crew"]["knowledge_base_path"]
    project_path = config["crew"]["project_path"]
    tasks = []

    task_defs = [
        ("sast_analyst", "analyze_sast"),
        ("sca_analyst", "analyze_sca"),
        ("config_analyst", "analyze_config"),
        ("architecture_analyst", "analyze_architecture"),
        ("ai_ml_analyst", "analyze_ai_ml"),
        ("crypto_analyst", "analyze_crypto"),
    ]

    use_soft = _should_use_soft_guardrail(config)
    if use_soft:
        logger.info("Using soft guardrail for provider '%s' — output accepted even if not valid Finding JSON", config.get("llm", {}).get("provider"))

    for agent_key, task_key in task_defs:
        if agent_key in agents and task_key in tasks_config:
            desc = tasks_config[task_key]["description"].format(
                project_path=project_path, kb_path=kb_path,
            ) + pydantic_output_instruction()
            if use_soft:
                guardrail_fn = validate_or_accept
            else:
                guardrail_fn = lambda o, llm_ref=llm: validate_structured_finding(o, llm_ref)
            tasks.append(Task(
                description=desc,
                expected_output=tasks_config[task_key]["expected_output"],
                agent=agents[agent_key],
                guardrail=guardrail_fn,
                guardrail_max_retries=5,
            ))

    return tasks


def build_exploit_chain_task(config: dict, agents: Dict[str, Agent],
                              tasks_config: dict,
                              combined_findings: str) -> Optional[Task]:
    """Build the bug hunter exploit chain task for Phase 2."""
    if "bug_hunter" not in agents or "hunt_exploit_chains" not in tasks_config:
        return None

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

    # CrewAI 0.80+: context must be a list of Task objects, not a raw string.
    # Inline the combined findings into the description instead.
    description = (
        tasks_config["hunt_exploit_chains"]["description"]
        + chain_instr
        + f"\n\nFINDINGS TO ANALYZE:\n{combined_findings}"
    )
    return Task(
        description=description,
        expected_output=tasks_config["hunt_exploit_chains"]["expected_output"],
        agent=agents["bug_hunter"],
        guardrail=validate_fix_does_not_break,
        guardrail_max_retries=3,
    )


def build_report_task(config: dict, agents: Dict[str, Agent],
                       tasks_config: dict,
                       combined_findings: str,
                       combined_chains: str,
                       format_instruction: str) -> Optional[Task]:
    """Build the report generation task for Phase 3."""
    if "reporter" not in agents or "generate_report" not in tasks_config:
        return None

    kb_path = config["crew"]["knowledge_base_path"]

    report_description = tasks_config["generate_report"]["description"].format(
        kb_path=kb_path,
    )
    report_description += (
        f"\n\nFINDINGS:\n{combined_findings}"
        f"\n\nEXPLOIT CHAINS:\n{combined_chains}"
        f"\n\nFORMAT INSTRUCTIONS:\n{format_instruction}"
    )

    return Task(
        description=report_description,
        expected_output=tasks_config["generate_report"]["expected_output"],
        agent=agents["reporter"],
    )


def build_fix_task(config: dict, agents: Dict[str, Agent],
                    tasks_config: dict,
                    has_critical: bool) -> Optional[Task]:
    """Build the fix task for Phase 4."""
    if "developer" not in agents or "fix_vulnerabilities" not in tasks_config:
        return None

    output_path = config["output"]["path"]
    kb_path = config["crew"]["knowledge_base_path"]
    project_path = config["crew"]["project_path"]

    human_input = config["agents"].get("human_input_for_critical", False)
    prompt_with_approval = ""
    if human_input and has_critical:
        prompt_with_approval = (
            "\n\n[WARNING] CRITICAL FINDINGS DETECTED - "
            "Human approval required before applying fixes."
        )

    return Task(
        description=tasks_config["fix_vulnerabilities"]["description"].format(
            report_path=f"{output_path}/report.md",
            prompts_path=f"{output_path}/developer_prompts.md",
            kb_path=kb_path,
            project_path=project_path,
        ) + prompt_with_approval,
        expected_output=tasks_config["fix_vulnerabilities"]["expected_output"],
        agent=agents["developer"],
        guardrail=validate_fix_does_not_break,
        guardrail_max_retries=3,
        human_input=human_input and has_critical,
    )