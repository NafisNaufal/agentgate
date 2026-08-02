"""AgentGate - a pre-action guardrail for AI agent tool calls.

Sprint 1: the full decision engine - detectors, policy engine, risk scoring,
sanitizer - plus the custom function-calling loop and CLI demo. Real execution
connectors (Gmail/GitHub/Playwright/...) are delegated to an Executor interface for
the Data Engineer track once that interface is defined.
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel
from .decision import DecisionEngine
from .tools import ToolSpec, ToolRegistry

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
    "DecisionEngine",
    "ToolSpec",
    "ToolRegistry",
]

__version__ = "0.2.0"
