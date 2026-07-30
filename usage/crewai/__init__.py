"""
Security Buddy — CrewAI Security Audit Crew package.

Sets global environment variables for CrewAI/LiteLLM compatibility.
CrewAI's internal components (planner agent, memory agent, memory analyzer)
create their own LLM instances directly via LiteLLM. They read:
  - OPENAI_API_KEY  — always set (with dummy for providers that don't need one)
  - OPENAI_BASE_URL — set for custom/ollama providers
  - LITELLM_LOG     — controls LiteLLM debug logging

For the memory query analyzer model:
CrewAI 0.80+ uses a hardcoded model name ("gpt-5.4-mini") for query analysis.
When using ollama/custom providers, this model won't exist. The memory analyzer
gracefully falls back to default complexity, so this is non-fatal. To suppress
the 404 errors, this module sets the LITELLM_LOGGING_LEVEL env var.
"""

import os
import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_script_dir = Path(__file__).parent
_config_path = _script_dir / "config.yaml"

if _config_path.exists():
    try:
        with open(_config_path) as _f:
            _cfg = yaml.safe_load(_f)
        _llm_cfg = _cfg.get("llm", {})
        _provider = _llm_cfg.get("provider", "openai")
        _api_key = (
            _llm_cfg.get("api_key")
            or os.getenv("LLM_API_KEY")
            or ""
        )
        _api_base = (
            _llm_cfg.get("api_base")
            or os.getenv("LLM_API_BASE")
            or ""
        )
        _model = _llm_cfg.get("model", "gpt-4o")

        # Determine API key: use actual key or dummy for providers that don't need one
        if _provider in ("ollama", "custom") and not _api_key:
            _api_key = "not-needed"

        if _api_key:
            os.environ["OPENAI_API_KEY"] = _api_key

        # Set OPENAI_BASE_URL globally so that CrewAI's internal agents
        # (planner, memory, memory analyzer) that create their own LLM
        # instances also route through the correct custom/ollama endpoint.
        # For ollama/custom providers, this is required.
        # For standard providers, respect existing env var if set.
        #
        # IMPORTANT: LiteLLM's OpenAI client (used by CrewAI internals)
        # constructs chat URLs as: {api_base}/chat/completions
        # So we MUST append /v1 to the base URL so the final path
        # becomes http://host:11434/v1/chat/completions (valid for Ollama).
        if _provider in ("custom", "ollama") and _api_base:
            # Ensure /v1 suffix for correct LiteLLM path construction
            _base_for_llm = _api_base.rstrip("/")
            if not _base_for_llm.endswith("/v1"):
                _base_for_llm += "/v1"
            os.environ["OPENAI_BASE_URL"] = _base_for_llm
            logger.debug(
                "Set OPENAI_BASE_URL=%s for provider=%s",
                _base_for_llm, _provider,
            )

        # Suppress CrewAI memory analyzer 404 errors for built-in model names
        # that don't exist on the configured provider (e.g. "gpt-5.4-mini" on
        # ollama).  The analyzer gracefully falls back to defaults, so the
        # 404 errors are harmless but noisy.
        if _provider in ("ollama", "custom"):
            # Reduce log level for httpx and LiteLLM to suppress 4xx errors
            logging.getLogger("httpx").setLevel(logging.ERROR)
            # Suppress LiteLLM's verbose internal logging
            os.environ.setdefault("LITELLM_LOG", "ERROR")
            # The memory analyzer fallback is logged at WARNING level by
            # crewai.memory.analyze -- keep that visible.

    except Exception:
        logger.warning("Failed to load config.yaml for env setup", exc_info=True)