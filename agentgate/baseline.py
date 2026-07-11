"""Baseline action evaluation.

Grew out of Phase 1's "research ... detector baseline" and became this concrete
module in Phase 3 ("prototype ... a baseline action evaluation"). It is intentionally
a single, small, rule-based evaluator - not the full detector suite, policy engine,
or risk-scoring system, which are Sprint 1+ deliverables. Its purpose here is to
prove the propose -> evaluate -> decide concept end to end: given an ActionRequest,
return one of the five PRD decisions with a reason and a risk score/level (the shape
of risk scoring settled on in schemas.py during Phase 1/2).
"""

from __future__ import annotations

import re

from .schemas import Decision, DecisionResponse, RiskLevel, ActionRequest

# A handful of high-signal patterns, enough to demonstrate the concept without the
# sophistication (multi-entity detection, confidence scoring, policy packs) that
# comes later.
_SECRET_PATTERN = re.compile(
    r"(?i)AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
_PAYMENT_WORDS = re.compile(r"(?i)\b(?:payment|invoice|refund|charge)\b")
_BULK_PATTERN = re.compile(
    r"\b\d{2,}\s+(?:[a-z]+\s+){0,2}(?:emails?|messages?|files?|records?)\b", re.IGNORECASE
)
_DESTRUCTIVE_WORDS = re.compile(r"(?i)\b(?:delete|cancel|remove|purge)\b")


def evaluate_baseline(req: ActionRequest) -> DecisionResponse:
    """Evaluate a single ActionRequest against the baseline rule set."""
    text = " ".join(t for t in (req.raw_payload, req.payload_summary, req.content_context) if t)

    if _SECRET_PATTERN.search(text):
        return DecisionResponse(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.9,
            reasons=["Secret-like pattern detected in the payload (baseline rule)"],
            next_step="stop",
        )

    if _PAYMENT_WORDS.search(text) or "payment_related" in req.risk_hint:
        return DecisionResponse(
            decision=Decision.NEED_APPROVAL,
            risk_level=RiskLevel.HIGH,
            risk_score=0.6,
            reasons=["Payment-related content detected (baseline rule)"],
            next_step="approval",
        )

    if _BULK_PATTERN.search(text) or "bulk_action" in req.risk_hint:
        return DecisionResponse(
            decision=Decision.NEED_APPROVAL,
            risk_level=RiskLevel.HIGH,
            risk_score=0.55,
            reasons=["Bulk operation detected (baseline rule)"],
            next_step="approval",
        )

    if _DESTRUCTIVE_WORDS.search(text) or "destructive_action" in req.risk_hint:
        return DecisionResponse(
            decision=Decision.NEED_APPROVAL,
            risk_level=RiskLevel.HIGH,
            risk_score=0.55,
            reasons=["Destructive verb detected (baseline rule)"],
            next_step="approval",
        )

    return DecisionResponse(
        decision=Decision.ALLOW,
        risk_level=RiskLevel.LOW,
        risk_score=0.0,
        reasons=["No risk signals matched by the baseline evaluator"],
        next_step="execute",
    )
