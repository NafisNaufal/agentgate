"""AgentGate - a pre-action guardrail for AI agent tool calls.

Phase 2: the tool registry shape and the planner interface are now defined
alongside the core contract settled in Phase 0-1.
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel
from .tools import ToolSpec, ToolRegistry

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
    "ToolSpec",
    "ToolRegistry",
]

__version__ = "0.1.0"
