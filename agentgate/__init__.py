"""AgentGate - a pre-action guardrail for AI agent tool calls.

Phase 0-1: the guardrail objective and custom loop risks are defined (see the design
notes that follow in later commits), and the core contract - ActionRequest /
DecisionResponse, the shared shape every later piece is built against - is settled
here first.
"""

from .schemas import ActionRequest, DecisionResponse, Decision, RiskLevel

__all__ = [
    "ActionRequest",
    "DecisionResponse",
    "Decision",
    "RiskLevel",
]

__version__ = "0.1.0"
