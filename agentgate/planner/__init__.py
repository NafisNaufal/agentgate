"""Planner: proposes the next tool call for a task.

Two implementations:
  ReplayPlanner - feeds pre-recorded proposals from a scenario (default; no API key).
  LLMPlanner    - calls a real LLM (Gemini / OpenRouter / OpenAI / Anthropic) via env.

The guardrail does not care which one is used; the planner only *proposes*, AgentGate
decides.
"""

from .base import Planner, Proposal
from .replay import ReplayPlanner

__all__ = ["Planner", "Proposal", "ReplayPlanner", "get_planner"]


def get_planner(kind: str = "replay", **kwargs):
    """Factory. kind='replay' (default) or 'llm'."""
    if kind == "replay":
        return ReplayPlanner(**kwargs)
    if kind == "llm":
        from .llm import LLMPlanner

        return LLMPlanner(**kwargs)
    raise ValueError(f"Unknown planner kind: {kind}")
