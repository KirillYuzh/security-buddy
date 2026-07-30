#!/usr/bin/env python3
"""
Configuration loading and LLM creation for Security Buddy CrewAI.

Handles:
- Loading config.yaml or env-var fallback
- Loading YAML agent/task definitions
- Creating LLM instances per provider with role overrides
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Optional

from crewai import LLM

logger = logging.getLogger(__name__)


def load_config() -> dict:
    """Load configuration from config.yaml or environment variables."""
    script_dir = Path(__file__).parent
    config_path = script_dir / "config.yaml"

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
                "temperature": 0.0,
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
    llm_config = config.get("llm", {})
    provider = llm_config.get("provider", "openai")
    model = llm_config.get("model", "gpt-4o")
    api_key = llm_config.get("api_key") or os.getenv("LLM_API_KEY", "")
    api_base = llm_config.get("api_base") or os.getenv("LLM_API_BASE")
    temperature = llm_config.get("temperature", 0.0)

    # Apply per-role overrides
    role_overrides = llm_config.get("role_overrides", {}).get(role_suffix, {})
    if role_overrides:
        provider = role_overrides.get("provider", provider)
        model = role_overrides.get("model", model)
        temperature = role_overrides.get("temperature", temperature)
        api_key = role_overrides.get("api_key", api_key)
        api_base = role_overrides.get("api_base", api_base)

    # CrewAI/LiteLLM checks for OPENAI_API_KEY env var internally.
    # Force-set it before any LLM construction.
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key

    if provider == "openai":
        return LLM(
            model=f"openai/{model}",
            api_key=api_key,
            base_url=api_base,
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
        # Custom/openai-compatible API (e.g. local LLM, proxy).
        if not api_key:
            api_key = "not-needed"
        if not api_base:
            raise ValueError(
                "api_base is required for custom provider. "
                "Set it in config.yaml or via LLM_API_BASE env var."
            )
        return LLM(
            model=f"openai/{model}",
            api_key=api_key,
            base_url=api_base,
            temperature=temperature,
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")


def get_effective_llm_model_name(config: dict) -> str:
    """Get the effective model name for this configuration.
    
    Used to ensure CrewAI internal components (memory, planning) use
    a correct model instead of hardcoded defaults.
    """
    llm_config = config.get("llm", {})
    provider = llm_config.get("provider", "openai")
    model = llm_config.get("model", "gpt-4o")
    
    if provider == "ollama":
        return f"ollama/{model}"
    elif provider == "anthropic":
        return f"anthropic/{model}"
    elif provider == "google":
        return f"google/{model}"
    elif provider in ("custom", "openai"):
        return f"openai/{model}"
    return f"openai/{model}"