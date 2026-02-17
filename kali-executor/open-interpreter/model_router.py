"""kali-executor/open-interpreter/model_router.py

Sprint 4: Smart Model Router -- phase-based and task-based model selection.

Use different LLM models for different phases/tasks:
  RECON:                cheap model (Haiku/Flash)       -- simple output parsing
  EXPLOITATION planning: expensive model (Opus/GPT-4)   -- complex reasoning
  Command generation:    mid-tier model (Sonnet)         -- good enough
  Evidence verification: expensive model                 -- critical accuracy

Model names follow the convention of the configured LLM_PROVIDER. When a model
is set to 'auto' (the default), the router returns None to signal that the
caller should use the default model for the provider.
"""

from __future__ import annotations

import logging
import os
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Phase -> model mapping (configurable via env vars)
DEFAULT_MODEL_ROUTING: Dict[str, str] = {
    "RECON": os.getenv("MODEL_RECON", "auto"),
    "VULN_DISCOVERY": os.getenv("MODEL_VULN", "auto"),
    "EXPLOITATION": os.getenv("MODEL_EXPLOIT", "auto"),
    "C2_DEPLOY": os.getenv("MODEL_C2", "auto"),
    "POST_EXPLOIT": os.getenv("MODEL_POST_EXPLOIT", "auto"),
    "REPORT": os.getenv("MODEL_REPORT", "auto"),
}

# Task-specific overrides (higher priority than phase)
TASK_MODEL_OVERRIDES: Dict[str, str] = {
    "exploitation_planning": os.getenv("MODEL_EXPLOIT_PLAN", ""),
    "evidence_verification": os.getenv("MODEL_EVIDENCE", ""),
    "output_parsing": os.getenv("MODEL_PARSE", ""),
    "report_generation": os.getenv("MODEL_REPORT_GEN", ""),
}


class ModelRouter:
    """Route LLM calls to appropriate models based on context."""

    def __init__(
        self,
        routing: Optional[Dict[str, str]] = None,
        task_overrides: Optional[Dict[str, str]] = None,
    ):
        self.routing = routing or dict(DEFAULT_MODEL_ROUTING)
        self.task_overrides = task_overrides or dict(TASK_MODEL_OVERRIDES)

    def get_model_for_phase(self, phase: str) -> Optional[str]:
        """Get the model name for a given phase.

        Returns None if 'auto' (use default model).
        """
        model = self.routing.get(phase, "auto")
        if model in ("auto", "", None):
            return None  # use default
        return model

    def get_model_for_task(self, task: str) -> Optional[str]:
        """Get model for a specific task type.

        Task names: exploitation_planning, evidence_verification,
                    output_parsing, report_generation
        """
        model = self.task_overrides.get(task, "")
        if not model:
            return None
        return model

    def resolve(
        self,
        phase: str,
        task: Optional[str] = None,
    ) -> Optional[str]:
        """Resolve the best model for the current context.

        Priority: task override > phase routing > None (default).
        """
        if task:
            task_model = self.get_model_for_task(task)
            if task_model:
                return task_model
        return self.get_model_for_phase(phase)
