"""AgentGate - Framework-agnostic pre-action guardrail engine for AI agent tool actions.

DS-owned core. This package contains the "brain": the custom function-calling loop,
detectors, policy engine, risk scoring, decision engine, sanitizer, approval logic,
and audit logging. External execution (Gmail/GitHub/Playwright/...) is delegated to an
Executor interface that the Data Engineer track fills with real connectors.
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel
from .engine import AgentGate

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
    "AgentGate",
]

__version__ = "0.1.0"
