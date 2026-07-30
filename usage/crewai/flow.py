#!/usr/bin/env python3
"""
SecurityAuditFlow — CrewAI Flow-based orchestration for Security Buddy.

Flow phases:
1. Parallel Analysis (SAST, SCA, Config, Architecture, AI/ML, Crypto)
2. Bug Hunter — exploit chain discovery
3. Report Generation
4. Conditional — Fix or Finish

Uses CrewAI Flow decorators (@start, @listen, @router) for
conditional branching and state management.
"""

import os
import json
import logging
from pathlib import Path
from typing import Optional

from crewai.flow.flow import Flow, start, listen, router
from crewai import LLM

from usage.crewai.config import create_llm, load_config
from usage.crewai.guards import (
    validate_structured_finding,
    pydantic_output_instruction,
    exploit_chain_output_instruction,
)
from usage.crewai.network import (
    sanitize_report_paths,
    build_format_instruction,
)
from usage.crewai.progress import (
    ProgressTracker,
    make_step_callback,
    make_task_callback,
)
from usage.crewai.crews import (
    create_memory,
    build_crew,
    create_agents,
    build_analysis_tasks,
    build_exploit_chain_task,
    build_report_task,
    build_fix_task,
)

logger = logging.getLogger("SecurityAuditFlow")

# Global progress tracker instance
_progress = ProgressTracker()


class SecurityAuditFlow(Flow):
    """Flow-based security audit with conditional branching and state management."""

    def __init__(self, config: dict, agents: dict, tasks_config: dict, agents_config: dict):
        super().__init__()
        self.config = config
        self.agents = agents
        self.tasks_config = tasks_config
        self.agents_config = agents_config
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
        logger.info("Iteration %d - Phase 1: Parallel analysis", iteration + 1)
        _progress.start_phase(1)

        llm = create_llm(self.config)
        analysis_tasks = build_analysis_tasks(
            self.config, self.agents, self.tasks_config, llm
        )

        if not analysis_tasks:
            logger.warning("No analysis tasks configured — skipping Phase 1")
            _progress.advance_step("No analysis tasks")
            return None

        analyst_crew = build_crew(
            self.agents,
            analysis_tasks,
            self.config,
            memory=create_memory(self.config, llm),
            step_callback=make_step_callback(_progress),
            task_callback=make_task_callback(_progress),
        )
        try:
            result = analyst_crew.kickoff()
        except Exception as exc:
            logger.error("Phase 1 crew.kickoff() failed: %s", exc)
            _progress.advance_step("Phase 1 failed — continuing with empty findings")
            return None

        findings_text = []
        if hasattr(result, 'tasks_output'):
            for task_output in result.tasks_output:
                if task_output:
                    # CrewAI 0.80+ uses 'raw' attribute, fallback to 'output' for older versions
                    raw_text = None
                    if hasattr(task_output, 'raw') and task_output.raw:
                        raw_text = task_output.raw
                    elif hasattr(task_output, 'output') and task_output.output:
                        raw_text = task_output.output
                    if raw_text:
                        # IMPORTANT: Do NOT sanitize paths here — the raw text is fed back
                        # to other agents (bug_hunter, reporter) who need real paths like
                        # /project/src/file.py to read files. Sanitization happens only
                        # in the final output stage (finalize method).
                        text = str(raw_text)
                        findings_text.append(text)
                        if "Critical" in str(raw_text):
                            self.state["has_critical"] = True

        self.state["all_findings"] = findings_text
        logger.info("Phase 1 complete — %d analysis results", len(findings_text))
        _progress.advance_step("Phase 1 complete")
        return result

    # -----------------------------------------------------------------------
    # Phase 2: Bug Hunter (triggered after analysis) — optional
    # -----------------------------------------------------------------------

    @listen(phase_1_parallel_analysis)
    def phase_2_hunt_exploit_chains(self):
        """Step 2: Bug Hunter reviews combined findings for exploit chains."""
        if "bug_hunter" not in self.agents:
            logger.info("Bug Hunter not configured — skipping Phase 2")
            return None

        logger.info("Phase 2: Bug Hunter — hunting exploit chains")
        _progress.start_phase(2)

        combined_findings = "\n\n".join(self.state.get("all_findings", []))
        hunt_task = build_exploit_chain_task(
            self.config, self.agents, self.tasks_config, combined_findings
        )
        if hunt_task is None:
            _progress.advance_step("Skipped (no task)")
            return None

        hunt_crew = build_crew(
            self.agents,
            [hunt_task],
            self.config,
            step_callback=make_step_callback(_progress),
            task_callback=make_task_callback(_progress),
        )
        try:
            result = hunt_crew.kickoff()
        except Exception as exc:
            logger.error("Phase 2 crew.kickoff() failed: %s", exc)
            _progress.advance_step("Phase 2 failed — continuing without exploit chains")
            return None

        result_text = sanitize_report_paths(str(result) if result else "", self.config)
        self.state["exploit_chains"] = [result_text] if result_text else []
        logger.info("Phase 2 complete — exploit chains identified")
        _progress.advance_step("Phase 2 complete")
        return result

    # -----------------------------------------------------------------------
    # Phase 3: Report Generation
    # -----------------------------------------------------------------------

    @listen(phase_2_hunt_exploit_chains)
    def phase_3_generate_report(self):
        """Step 3: Generate comprehensive report from all findings."""
        if "reporter" not in self.agents:
            logger.info("Reporter not configured — skipping Phase 3")
            return None

        logger.info("Phase 3: Generating report")
        _progress.start_phase(3)

        all_findings = self.state.get("all_findings", [])
        exploit_chains = self.state.get("exploit_chains", [])

        combined_findings = "\n\n".join(all_findings) if all_findings else "No findings."
        combined_chains = "\n\n".join(exploit_chains) if exploit_chains else "No exploit chains identified."

        format_instruction = build_format_instruction(self.config)
        report_task = build_report_task(
            self.config, self.agents, self.tasks_config,
            combined_findings, combined_chains, format_instruction,
        )

        if report_task is None:
            _progress.advance_step("Skipped (no task)")
            return None

        report_crew = build_crew(
            self.agents,
            [report_task],
            self.config,
            step_callback=make_step_callback(_progress),
            task_callback=make_task_callback(_progress),
        )
        try:
            result = report_crew.kickoff()
        except Exception as exc:
            logger.error("Phase 3 crew.kickoff() failed: %s", exc)
            _progress.advance_step("Phase 3 failed — continuing without report")
            self.state["report"] = ""
            return None

        self.state["report"] = sanitize_report_paths(str(result) if result else "", self.config)
        logger.info("Phase 3 complete — report generated")
        _progress.advance_step("Phase 3 complete")
        return result

    # -----------------------------------------------------------------------
    # Phase 4: Conditional — Fix or Finish
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
        logger.info("Phase 4: Applying fixes")
        _progress.start_phase(4)

        has_critical = self.state.get("has_critical", False)
        fix_task = build_fix_task(
            self.config, self.agents, self.tasks_config, has_critical,
        )

        if fix_task is None:
            return None

        fix_crew = build_crew(
            self.agents, [fix_task], self.config,
            step_callback=make_step_callback(_progress),
            task_callback=make_task_callback(_progress),
        )
        result = fix_crew.kickoff()

        result_str = str(result) if result else ""
        self.state["fix_results"].append(result_str)

        if "no changes" in result_str.lower() or "already fixed" in result_str.lower():
            self.state["no_changes_count"] += 1
        else:
            self.state["no_changes_count"] = 0

        self.state["iteration"] += 1
        logger.info("Phase 4 complete — fix iteration %d", self.state["iteration"])
        _progress.advance_step(f"Fix iteration {self.state['iteration']} complete")
        return result

    @listen("finish")
    def finalize(self):
        """Final step: save all outputs and print summary."""
        logger.info("Audit flow complete — saving outputs")
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
        }
        findings_file = output_path / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(structured, f, indent=2, default=str)
        print(f"\n  [OK] Results saved to {findings_file}")

        # Print findings inline
        findings = self.state.get("all_findings", [])
        print(f"\n  Findings summary: {len(findings)} analysis results")
        for i, f_text in enumerate(findings):
            lines = f_text.strip().split('\n')
            print(f"\n  --- Finding {i+1} ---")
            for line in lines[:30]:  # first 30 lines per finding
                print(f"  {line}")

        _progress.finish()
        return structured


def run_flow(config: dict) -> dict:
    """Create and run the SecurityAuditFlow. Returns the final flow state."""
    script_dir = Path(__file__).parent
    agents_config_path = script_dir / "agents.yaml"
    tasks_config_path = script_dir / "tasks.yaml"

    # Import here to avoid circular imports
    from usage.crewai.config import load_yaml

    agents_config = load_yaml(agents_config_path)
    tasks_config = load_yaml(tasks_config_path)

    # Ensure OPENAI_API_KEY env var is set for LiteLLM compatibility
    if config.get("llm", {}).get("api_key"):
        os.environ["OPENAI_API_KEY"] = config["llm"]["api_key"]

    # Create agents
    print("  Initializing LLMs...")
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

    return {
        "result": result,
        "state": flow.state,
        "config": config,
    }