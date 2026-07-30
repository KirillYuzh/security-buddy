#!/usr/bin/env python3
"""
Structured output enforcement and guardrails for Security Buddy.

Features:
- Pydantic structured output enforcement with retry recall
- Guardrail functions for findings, exploit chains, and fixes
- JSON extraction helpers

All guardrails accept string output and return bool for CrewAI compatibility.
"""

import json
import re
import logging
from typing import Optional, Type, TypeVar, Any

import pydantic
from pydantic import BaseModel

from crewai import LLM

from usage.crewai.models import Finding, ExploitChain, FixResult

logger = logging.getLogger(__name__)

M = TypeVar("M", bound=BaseModel)


# ---------------------------------------------------------------------------
# JSON extraction helpers
# ---------------------------------------------------------------------------

def extract_json(text: str) -> Optional[str]:
    """Extract a JSON object/array from *text*, stripping markdown fences."""
    # Remove markdown JSON code fences
    text = re.sub(r"```(?:json)?\s*\n?", "", text).strip()
    # Try to find the outermost { ... } or [ ... ]
    for delim in ("{", "["):
        start_idx = text.find(delim)
        if start_idx == -1:
            continue
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


# ---------------------------------------------------------------------------
# Structured output enforcer
# ---------------------------------------------------------------------------

def enforce_structured_output(
    raw_text: str,
    model_class: Type[M],
    max_recall: int = 5,
    llm: Optional[LLM] = None,
) -> Optional[M]:
    """
    Parse <u>raw_text</u> into the given Pydantic <u>model_class</u>.
    If parsing fails, re-prompt an LLM (if provided) up to <u>max_recall</u> times
    asking it to reformat the output into valid JSON matching the schema.
    This guarantees deterministic, typed outputs -- no free-form fields.

    Returns None if all attempts fail (caller handles fallback gracefully).
    """
    for attempt in range(1, max_recall + 1):
        json_str = extract_json(raw_text)
        if json_str:
            try:
                parsed = json.loads(json_str)
                return model_class.model_validate(parsed)
            except (json.JSONDecodeError, pydantic.ValidationError) as exc:
                logger.warning(
                    "Structured output attempt %d/%d failed for %s: %s",
                    attempt, max_recall, model_class.__name__, exc,
                )
        else:
            logger.warning(
                "No JSON found on attempt %d/%d for %s",
                attempt, max_recall, model_class.__name__,
            )

        if llm is None or attempt >= max_recall:
            break

        # Re-prompt the LLM to produce valid JSON matching the schema
        schema_json = model_class.model_json_schema()
        schema_str = json.dumps(schema_json, indent=2)
        try:
            raw_text = llm.generate(
                f"""The following text should be valid JSON matching this schema:

{schema_str}

But it could not be parsed.  Please return ONLY valid JSON that follows the
schema above.  Do NOT include any markdown formatting, explanation, or extra text.

INPUT TEXT:
{raw_text}

OUTPUT (valid JSON only):"""
            )
        except Exception as exc:
            logger.warning(
                "LLM re-prompt failed on attempt %d/%d for %s: %s",
                attempt, max_recall, model_class.__name__, exc,
            )
            break

    # Fallback: return None instead of crashing on required-field models
    logger.error(
        "Could not enforce structured output for %s after %d attempts. "
        "Returning None.",
        model_class.__name__, max_recall,
    )
    return None


def validate_with_pydantic(
    output: Any,
    model_class: Type[M],
    llm: Optional[LLM] = None,
) -> tuple[bool, Any]:
    """
    Guardrail-compatible wrapper: takes raw LLM output, enforces Pydantic
    structure via *enforce_structured_output*.

    CrewAI 0.80+ expects guardrails to return (accepted: bool, result: Any).
    The second element is the (potentially cleaned) output on success,
    or an error message on failure.
    """
    raw_text = str(output) if not isinstance(output, str) else output
    try:
        result = enforce_structured_output(raw_text, model_class, llm=llm)
        if result is None:
            return (False, f"Failed to validate as {model_class.__name__} — all attempts exhausted")
        # Return original text on success — CrewAI uses the returned output
        return (True, raw_text)
    except Exception as exc:
        return (False, f"Failed to validate as {model_class.__name__}: {exc}")


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

def validate_finding_has_cwe_and_severity(output: Any) -> tuple[bool, Any]:
    """Guardrail: ensure finding output contains required fields.

    CrewAI 0.80+ expects guardrails to return (accepted: bool, result: Any).
    The second element MUST be the (potentially cleaned) output on success,
    not None, or CrewAI raises 'guardrail returned None'.
    """
    raw_text = str(output) if not isinstance(output, str) else output
    checks = [
        ("CWE-" in raw_text or "CVE-" in raw_text),
        any(s in raw_text for s in ["Critical", "High", "Medium", "Low"]),
        "Location:" in raw_text or "location:" in raw_text or "file:" in raw_text,
    ]
    if all(checks):
        return (True, raw_text)
    missing = []
    if not checks[0]:
        missing.append("CWE/CVE identifier")
    if not checks[1]:
        missing.append("severity (Critical/High/Medium/Low)")
    if not checks[2]:
        missing.append("location (file:line)")
    return (False, f"Missing required fields: {', '.join(missing)}")


def validate_fix_does_not_break(output: Any) -> tuple[bool, Any]:
    """Guardrail: check that fix output doesn't introduce obvious issues.

    CrewAI 0.80+ expects guardrails to return (accepted: bool, result: Any).
    The second element MUST be the output text on success, not None.
    """
    raw_text = str(output) if not isinstance(output, str) else output
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
        if signal in raw_text.lower():
            return (False, f"Fix contains dangerous pattern: {signal}")
    return (True, raw_text)


def validate_structured_finding(output: Any, llm: Optional[LLM] = None) -> tuple[bool, Any]:
    """
    Guardrail that enforces Pydantic Finding structure.
    Returns (True, None) if the output can be parsed as a valid Finding JSON.
    CrewAI 0.80+ expects guardrails to return (success: bool, error: Optional[str]).
    """
    return validate_with_pydantic(output, Finding, llm=llm)


def validate_or_accept(output: Any, llm: Optional[LLM] = None) -> tuple[bool, Any]:
    """
    Soft guardrail: attempts to validate as a Finding, but always accepts the
    output regardless.  This prevents small/local models from killing the flow
    when they cannot produce perfectly structured JSON.

    Returns (True, output) always — the output is logged but never rejected.
    The second element MUST be the output text, never None, or CrewAI 0.80+
    raises 'guardrail returned None'.
    Use for providers (like ollama with small models) where strict structured
    output enforcement would cause infinite retries and flow crashes.

    IMPROVED: Now checks that the output actually contains meaningful content
    (not just a directory listing or empty text) and logs warnings when
    the output appears to be low-quality.
    """
    if not isinstance(output, str):
        output = str(output)
    
    # Check for common low-quality patterns and log warnings
    output_stripped = output.strip()
    
    # Detect directory listing (agent just listed files instead of analyzing)
    if output_stripped.startswith("Directory:") or output_stripped.startswith("Subdirectories:"):
        logger.warning(
            "Soft guardrail: output appears to be a directory listing, not findings. "
            "The agent listed files but did not analyze them. "
            "First 200 chars: %s",
            output_stripped[:200],
        )
    
    # Detect empty or near-empty output
    if len(output_stripped) < 50:
        logger.warning(
            "Soft guardrail: output is very short (%d chars) — likely not valid findings. "
            "Content: %s",
            len(output_stripped),
            output_stripped[:200],
        )
    
    # Detect error messages
    if output_stripped.startswith("Error:") or output_stripped.startswith("Error "):
        logger.warning(
            "Soft guardrail: output contains an error message, not findings. "
            "Content: %s",
            output_stripped[:200],
        )
    
    # Try to validate as Finding JSON, log result
    try:
        json_str = extract_json(output)
        if json_str:
            parsed = json.loads(json_str)
            Finding.model_validate(parsed)
            logger.info("Soft guardrail: output successfully validated as Finding JSON")
        else:
            logger.warning(
                "Soft guardrail: no valid JSON found in output. "
                "The model may not have followed the structured output instruction. "
                "First 200 chars: %s",
                output_stripped[:200],
            )
    except Exception as exc:
        logger.warning(
            "Soft guardrail: output could not be parsed as Finding: %s. "
            "First 200 chars: %s",
            exc,
            output_stripped[:200],
        )
    
    # Always accept — but log quality issues so they appear in the audit log
    return (True, output)


def validate_structured_chain(output: Any, llm: Optional[LLM] = None) -> tuple[bool, Any]:
    """
    Guardrail that enforces Pydantic ExploitChain structure.
    Returns (True, None) if the output can be parsed as a valid ExploitChain JSON.
    CrewAI 0.80+ expects guardrails to return (success: bool, error: Optional[str]).
    """
    return validate_with_pydantic(output, ExploitChain, llm=llm)


def pydantic_output_instruction() -> str:
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


def exploit_chain_output_instruction() -> str:
    """Return a consistent Pydantic output instruction for exploit chains."""
    return (
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