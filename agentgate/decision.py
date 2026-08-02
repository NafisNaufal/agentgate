"""Decision engine.

Runs every detector over an ActionRequest, aggregates the findings, asks the policy
engine for domain rules, blends that with the risk score, and produces a single
DecisionResponse. This is the place where "what did we detect" becomes "what should
happen".
"""

from __future__ import annotations

from . import risk
from .detectors import DEFAULT_DETECTORS, Detector
from .policy import PolicyContext, PolicyEngine
from .sanitizer import sanitize
from .schemas import ActionRequest, Decision, DecisionResponse, RiskLevel

_RANK = {
    Decision.ALLOW: 0,
    Decision.SANITIZE: 1,
    Decision.ASK_USER: 2,
    Decision.NEED_APPROVAL: 3,
    Decision.BLOCK: 4,
}

_NEXT_STEP = {
    Decision.ALLOW: "execute",
    Decision.SANITIZE: "execute_sanitized",
    Decision.ASK_USER: "ask_user",
    Decision.NEED_APPROVAL: "approval",
    Decision.BLOCK: "stop",
}


def _stronger(a: Decision, b: Decision) -> Decision:
    return a if _RANK[a] >= _RANK[b] else b


def _risk_decision(level: RiskLevel) -> Decision:
    if level == RiskLevel.CRITICAL:
        return Decision.BLOCK
    if level == RiskLevel.HIGH:
        return Decision.NEED_APPROVAL
    return Decision.ALLOW


class DecisionEngine:
    def __init__(
        self,
        detectors: list[Detector] | None = None,
        policy_engine: PolicyEngine | None = None,
    ):
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        self.policy_engine = policy_engine if policy_engine is not None else PolicyEngine()

    def evaluate(self, req: ActionRequest) -> DecisionResponse:
        # 1. Detection
        entities = []
        reasons: list[str] = []
        contributions: list[float] = []
        tags: set[str] = set()
        entity_kinds: set[str] = set()

        for det in self.detectors:
            finding = det.scan(req)
            if not finding.triggered:
                continue
            entities.extend(finding.entities)
            reasons.extend(finding.reasons)
            contributions.append(finding.risk_contribution)
            tags |= finding.tags
            entity_kinds |= {e.kind for e in finding.entities}

        # 2. Risk score (detector-driven). CRITICAL is reserved for categorically
        #    critical signals (a CRITICAL-severity entity such as a live secret or a
        #    credential request) or a CRITICAL policy floor. A pile-up of MEDIUM/HIGH
        #    signals caps at HIGH so legitimate-but-risky actions route to approval
        #    rather than being hard-blocked.
        base_score = risk.combine(contributions)
        has_critical_entity = any(e.severity == "CRITICAL" for e in entities)
        if not has_critical_entity:
            base_score = min(base_score, 0.84)

        # 3. Policy
        ctx = PolicyContext(tags=tags, entity_kinds=entity_kinds)
        policy = self.policy_engine.evaluate(req, ctx)

        # 4. Risk floor from policy, then band
        score = risk.apply_floor(base_score, policy.risk_floor)
        level = risk.score_to_level(score)

        # 5. Final decision = strongest of (policy decision, risk-band decision)
        decision = _stronger(policy.decision, _risk_decision(level))

        # 6. Sanitized preview whenever we have something to redact
        sanitized_payload = None
        if entities and req.raw_payload:
            redacted = sanitize(req.raw_payload)
            if redacted != req.raw_payload:
                sanitized_payload = redacted

        # If policy asked to SANITIZE but we couldn't redact anything, fall back to approval.
        if decision == Decision.SANITIZE and sanitized_payload is None:
            decision = Decision.NEED_APPROVAL

        all_reasons = reasons + [r for r in policy.reasons if r not in reasons]
        if not all_reasons:
            all_reasons = ["No policy violations or sensitive content detected"]

        return DecisionResponse(
            decision=decision,
            risk_level=level,
            risk_score=score,
            reasons=all_reasons,
            triggered_policies=policy.triggered,
            sensitive_entities=entities,
            sanitized_payload=sanitized_payload,
            next_step=_NEXT_STEP[decision],
            audit_id="",  # filled by the audit logger
        )
