"""AgentGate - Framework-agnostic pre-action guardrail engine for AI agent tool actions.

DS-owned core, Phase 3 prototype stage. This package contains an early prototype of
the "brain": the custom function-calling loop, a baseline rule-based evaluator, and
the decision router. The full detector suite, policy engine, risk scoring, sanitizer,
approval queue, and tool registry are Sprint 1+ deliverables, not yet built here.
External execution (Gmail/GitHub/Playwright/...) will be delegated to an Executor
interface for the Data Engineer track once that interface is defined (Sprint 1+).
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel
from .baseline import evaluate_baseline
from .tools import ToolSpec, ToolRegistry

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
    "evaluate_baseline",
    "ToolSpec",
    "ToolRegistry",
]

__version__ = "0.1.0"
