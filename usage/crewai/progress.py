#!/usr/bin/env python3
"""
Progress Display — terminal progress tracker for Security Buddy audit flow.

Shows current phase, step count, progress bar, and ETA estimation.
Uses CrewAI callback hooks + manual phase updates.
"""

import os
import sys
import time
import threading
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

logger = logging.getLogger(__name__)


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
    Thread-safe.
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


# Convenience functions for CrewAI callback compatibility

def make_step_callback(progress: ProgressTracker):
    """
    Factory that creates a step_callback compatible with CrewAI's current API.

    CrewAI 0.80+ passes only (task_output) to step_callback, not (agent, action, result).
    This adapter handles both the old and new signatures.

    The old CrewAI signature was:  lambda agent, action, result: ...
    The new CrewAI signature is:   lambda task_output: ...
    """
    def step_callback(*args, **kwargs):
        """Callback: log each agent action and advance progress."""
        if len(args) == 1:
            # New CrewAI 0.80+ style: step_callback(task_output)
            task_output = args[0]
            if hasattr(task_output, 'agent'):
                progress.advance_step(step_name=f"[DONE] {task_output.agent}")
            elif hasattr(task_output, 'output'):
                progress.advance_step(step_name=str(task_output.output)[:50])
            else:
                progress.advance_step(step_name="step completed")
        elif len(args) >= 3:
            # Old CrewAI style: step_callback(agent, action, result)
            agent = args[0]
            action = args[1]
            result = args[2]
            agent_name = getattr(agent, "role", str(agent) if agent else "unknown")
            action_desc = getattr(action, "tool", str(action)[:80]) if action else ""
            logger.info("[%s] %s -> %s", agent_name, action_desc,
                        str(result)[:100] if result else "")
            progress.advance_step(step_name=f"{agent_name}: {action_desc[:30]}")
        else:
            logger.debug("step_callback called with unexpected args: %s", args)
    return step_callback


def make_task_callback(progress: ProgressTracker):
    """
    Factory that creates a task_callback compatible with CrewAI's current API.

    CrewAI 0.80+ passes only (task_output) to task_callback.
    """
    def task_callback(task_output):
        """Callback: log task completion and advance progress."""
        if hasattr(task_output, 'agent'):
            progress.advance_step(step_name=f"[DONE] {task_output.agent}")
        elif hasattr(task_output, 'output'):
            output_preview = str(task_output.output)[:200] if task_output.output else "no output"
            logger.info("[TASK DONE] %s", output_preview)
            progress.advance_step(step_name="task done")
        else:
            progress.advance_step(step_name="task done")
    return task_callback