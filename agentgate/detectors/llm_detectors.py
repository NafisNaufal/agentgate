"""Full-LLM detector classes: every detection category uses the local LLM.

These replace the regex-based detectors when the ``full_llm`` architecture is
selected. Each class sends a specialised prompt to the local Ollama server and
parses the structured JSON response into the same Finding / SensitiveEntity
objects the rest of the engine expects.

All detectors fail safe: if the LLM is unreachable they return an empty finding
(no entities, zero risk contribution) rather than crashing the evaluation pipeline.
"""

from __future__ import annotations

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate
from .llm_client import LLMUnavailable, chat_json


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _call_llm(system_prompt: str, text: str, *, model: str | None = None,
              host: str | None = None, timeout: float = 30.0,
              extra_options: dict | None = None) -> dict | None:
    """Call the LLM and return parsed JSON, or None on any failure."""
    if not text:
        return None
    try:
        return chat_json(system_prompt, f"TEXT: {text}", model=model, host=host,
                         timeout=timeout, extra_options=extra_options)
    except LLMUnavailable:
        return None  # fail safe


class _LLMDetectorBase(Detector):
    """Common init shared by every full-LLM detector."""

    def __init__(self, model: str | None = None, host: str | None = None,
                 timeout: float = 30.0, extra_options: dict | None = None):
        self.model = model
        self.host = host
        self.timeout = timeout
        self.extra_options = extra_options

    def _llm(self, system_prompt: str, text: str) -> dict | None:
        return _call_llm(system_prompt, text, model=self.model, host=self.host,
                         timeout=self.timeout, extra_options=self.extra_options)


# ---------------------------------------------------------------------------
# 1. PII Detector (LLM)
# ---------------------------------------------------------------------------

_PII_PROMPT = (
    "You are a PII (Personally Identifiable Information) classifier inside an "
    "AI-agent guardrail. Analyse the TEXT and identify any PII present: email "
    "addresses, phone numbers, credit card numbers, booking/order references. "
    "Reply ONLY as JSON: "
    '{"has_pii": true|false, "items": [{"type": "EMAIL"|"PHONE"|"CREDIT_CARD"|"BOOKING_REF", '
    '"value": "<the detected value>", "severity": "LOW"|"MEDIUM"|"HIGH"}]}'
)


class LLMPIIDetector(_LLMDetectorBase):
    name = "pii"

    def scan(self, req: ActionRequest) -> Finding:
        data = self._llm(_PII_PROMPT, req.scan_text)
        if not data or not data.get("has_pii"):
            return self._finding()

        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        sev_weight = {"LOW": 0.1, "MEDIUM": 0.25, "HIGH": 0.45, "CRITICAL": 0.6}

        for item in data.get("items", []):
            kind = str(item.get("type", "PII")).upper()
            value = str(item.get("value", ""))
            severity = str(item.get("severity", "MEDIUM")).upper()
            if severity not in sev_weight:
                severity = "MEDIUM"
            entities.append(SensitiveEntity(kind, truncate(value), self.name, severity))

        if entities:
            kinds = sorted({e.kind for e in entities})
            reasons.append(f"PII / customer data detected: {', '.join(kinds)}")

        contribution = min(0.6, sum(sev_weight.get(e.severity, 0.25) for e in entities))
        return self._finding(entities=entities, reasons=reasons, risk_contribution=contribution)


# ---------------------------------------------------------------------------
# 2. Secret Detector (LLM)
# ---------------------------------------------------------------------------

_SECRET_PROMPT = (
    "You are a secret/credential classifier inside an AI-agent guardrail. "
    "Analyse the TEXT and identify any secrets, API keys, tokens, passwords, "
    "private keys, or credential assignments. "
    "Reply ONLY as JSON: "
    '{"has_secrets": true|false, "items": [{"type": "AWS_ACCESS_KEY"|"GITHUB_TOKEN"|'
    '"OPENAI_KEY"|"STRIPE_KEY"|"PRIVATE_KEY"|"CREDENTIAL_ASSIGNMENT"|"JWT"|"GENERIC_SECRET", '
    '"value": "<masked preview>", "severity": "HIGH"|"CRITICAL"}]}'
)


class LLMSecretDetector(_LLMDetectorBase):
    name = "secret"

    def scan(self, req: ActionRequest) -> Finding:
        data = self._llm(_SECRET_PROMPT, req.scan_text)
        if not data or not data.get("has_secrets"):
            return self._finding()

        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()

        for item in data.get("items", []):
            kind = str(item.get("type", "GENERIC_SECRET")).upper()
            value = str(item.get("value", ""))
            severity = str(item.get("severity", "HIGH")).upper()
            if severity not in ("HIGH", "CRITICAL"):
                severity = "HIGH"
            entities.append(SensitiveEntity(kind, truncate(value), self.name, severity))

        if entities:
            tags.add("source_code")
            kinds = sorted({e.kind for e in entities})
            reasons.append(f"Secret/credential material detected: {', '.join(kinds)}")

        has_critical = any(e.severity == "CRITICAL" for e in entities)
        contribution = 0.85 if has_critical else 0.55 if entities else 0.0
        return self._finding(entities=entities, reasons=reasons,
                             risk_contribution=contribution, tags=tags)


# ---------------------------------------------------------------------------
# 3. Source Code Detector (LLM)
# ---------------------------------------------------------------------------

_SOURCE_CODE_PROMPT = (
    "You are a source-code classifier inside an AI-agent guardrail. Analyse the "
    "TEXT and determine whether it contains programming source code or internal "
    "codenames/project names. "
    "Reply ONLY as JSON: "
    '{"has_code": true|false, "has_codename": true|false, '
    '"language": "<detected language or empty>", "confidence": 0.0-1.0}'
)


class LLMSourceCodeDetector(_LLMDetectorBase):
    name = "source_code"

    def scan(self, req: ActionRequest) -> Finding:
        data = self._llm(_SOURCE_CODE_PROMPT, req.scan_text)
        if not data:
            return self._finding()

        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()
        contribution = 0.0

        if data.get("has_code"):
            tags.add("source_code")
            lang = data.get("language", "unknown")
            conf = float(data.get("confidence", 0.5))
            entities.append(SensitiveEntity("SOURCE_CODE",
                            truncate(f"{lang} code (conf={conf:.2f})"),
                            self.name, "MEDIUM"))
            reasons.append(f"Source code detected ({lang}, confidence {conf:.2f})")
            contribution = 0.3
            if "external_send" in req.risk_hint or req.action_type == "BROWSER_SUBMIT":
                contribution = 0.6
                reasons.append("Source code paired with an outbound/send action")

        if data.get("has_codename"):
            entities.append(SensitiveEntity("INTERNAL_CODENAME",
                            truncate(req.scan_text[:48]), self.name, "MEDIUM"))
            reasons.append("Internal codename detected")

        return self._finding(entities=entities, reasons=reasons,
                             risk_contribution=contribution, tags=tags)


# ---------------------------------------------------------------------------
# 4. Payment / Phishing Detector (LLM)
# ---------------------------------------------------------------------------

_PAYMENT_PROMPT = (
    "You are a payment/phishing classifier inside an AI-agent guardrail. "
    "Analyse the TEXT and determine whether it contains payment-related content "
    "(invoices, refunds, charges, payment links), credential requests (asking "
    "for passwords/PINs/OTPs), or urgency/phishing patterns. "
    "Reply ONLY as JSON: "
    '{"has_payment": true|false, "has_credential_request": true|false, '
    '"has_urgency": true|false, "confidence": 0.0-1.0}'
)


class LLMPaymentPhishingDetector(_LLMDetectorBase):
    name = "payment_phishing"

    def scan(self, req: ActionRequest) -> Finding:
        data = self._llm(_PAYMENT_PROMPT, req.scan_text)
        if not data:
            return self._finding()

        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()
        contribution = 0.0

        has_payment = data.get("has_payment") or "payment_related" in req.risk_hint
        has_cred = data.get("has_credential_request", False)
        has_urgency = data.get("has_urgency", False)

        if has_payment:
            tags.add("payment_related")
            entities.append(SensitiveEntity("PAYMENT_CONTENT",
                            truncate(req.scan_text[:48]), self.name, "HIGH"))
            reasons.append("Payment-related content detected")
            contribution = 0.5

        if has_cred:
            entities.append(SensitiveEntity("CREDENTIAL_REQUEST",
                            truncate(req.scan_text[:48]), self.name, "CRITICAL"))
            reasons.append("Message requests credentials (phishing pattern)")
            contribution = max(contribution, 0.8)

        if has_urgency and (has_payment or has_cred):
            reasons.append("Urgency + payment/credential pattern (phishing-like)")
            contribution = min(0.9, contribution + 0.2)

        if contribution and ("external_send" in req.risk_hint or req.action_type == "BROWSER_SUBMIT"):
            tags.add("external_send")
            contribution = min(0.9, contribution + 0.1)
            reasons.append("Payment/phishing content paired with external send")

        return self._finding(entities=entities, reasons=reasons,
                             risk_contribution=contribution, tags=tags)


# ---------------------------------------------------------------------------
# 5. Action Intent Detector (LLM)
# ---------------------------------------------------------------------------

_INTENT_PROMPT = (
    "You are an action-intent classifier inside an AI-agent guardrail. Analyse "
    "the TEXT and determine whether it expresses: (1) a bulk operation affecting "
    "many items, (2) a destructive action (delete/remove/purge/cancel), or "
    "(3) an outbound send to an external recipient. "
    "Reply ONLY as JSON: "
    '{"is_bulk": true|false, "estimated_count": <number or 0>, '
    '"is_destructive": true|false, "is_external_send": true|false, '
    '"confidence": 0.0-1.0}'
)


class LLMActionIntentDetector(_LLMDetectorBase):
    name = "action_intent"

    def scan(self, req: ActionRequest) -> Finding:
        data = self._llm(_INTENT_PROMPT, req.scan_text)
        if not data:
            return self._finding()

        reasons: list[str] = []
        tags: set[str] = set()
        contribution = 0.0

        if data.get("is_bulk"):
            count = data.get("estimated_count", 0)
            tags.add("bulk_action")
            reasons.append(f"Bulk operation detected ({count or 'many'} items)")
            contribution = max(contribution, 0.5)

        if data.get("is_destructive"):
            tags.add("destructive_action")
            base = 0.7 if not req.rollback_available else 0.5
            reasons.append("Destructive verb detected (delete/cancel/purge/...)")
            contribution = max(contribution, base)

        if data.get("is_external_send"):
            tags.add("external_send")
            reasons.append("Outbound send to an external recipient detected")
            contribution = max(contribution, 0.35)

        return self._finding(reasons=reasons, risk_contribution=contribution, tags=tags)
