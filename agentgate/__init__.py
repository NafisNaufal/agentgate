"""AgentGate - a pre-action guardrail for AI agent tool calls.

The full decision engine, custom function-calling loop, and opt-in executor interface.
GitHub, sandboxed filesystem, and Playwright executors are included; other providers
can register independently.
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel
from .decision import DecisionEngine
from .tools import ToolSpec, ToolRegistry
from .executors import ExecutionResult, ExecutorRegistry

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
    "DecisionEngine",
    "ToolSpec",
    "ToolRegistry",
    "ExecutionResult",
    "ExecutorRegistry",
]

__version__ = "0.2.0"
