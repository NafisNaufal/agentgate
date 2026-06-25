"""Payment / phishing-risk detector.

Flags payment-confirmation language, payment links, refund/charge intent, and
classic phishing/urgency patterns. These are the signals behind the Booking
messaging policy (PRD section 12) and the reservation demo scenario.
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate

PAYMENT_RE = re.compile(
    r"(?i)\b(?:payment|invoice|refund|charge(?:d|s)?|wire transfer|bank account|"
    r"iban|paypal|credit card|confirm(?:ation)? of payment|amount due|pay now)\b"
)
PAYMENT_LINK_RE = re.compile(r"(?i)https?://\S*(?:pay|invoice|checkout|billing|refund)\S*")
URGENCY_RE = re.compile(
    r"(?i)\b(?:urgent|immediately|act now|within 24 hours|verify your account|"
    r"suspended|click here|final notice|failure to)\b"
)
CRED_REQUEST_RE = re.compile(
    r"(?i)\b(?:enter your (?:password|pin|otp|card)|share your (?:password|otp|cvv)|"
    r"confirm your (?:login|credentials))\b"
)


class PaymentPhishingDetector(Detector):
    name = "payment_phishing"

    def scan(self, req: ActionRequest) -> Finding:
        text = req.scan_text
        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()

        pay_hits = PAYMENT_RE.findall(text) + PAYMENT_LINK_RE.findall(text)
        urgency_hits = URGENCY_RE.findall(text)
        cred_hits = CRED_REQUEST_RE.findall(text)

        if pay_hits or "payment_related" in req.risk_hint:
            tags.add("payment_related")
            label = truncate(pay_hits[0]) if pay_hits else "payment_related hint"
            entities.append(SensitiveEntity("PAYMENT_CONTENT", label, self.name, "HIGH"))
            reasons.append("Payment-related content detected")

        if cred_hits:
            entities.append(SensitiveEntity("CREDENTIAL_REQUEST", truncate(cred_hits[0]), self.name, "CRITICAL"))
            reasons.append("Message requests credentials (phishing pattern)")

        if urgency_hits and (pay_hits or cred_hits):
            reasons.append("Urgency + payment/credential pattern (phishing-like)")

        contribution = 0.0
        if pay_hits or "payment_related" in req.risk_hint:
            contribution = 0.5
        if cred_hits:
            contribution = max(contribution, 0.8)
        if urgency_hits and (pay_hits or cred_hits):
            contribution = min(0.9, contribution + 0.2)

        # External target raises the stakes (sending payment content to a customer).
        if contribution and ("external_send" in req.risk_hint or req.action_type == "BROWSER_SUBMIT"):
            tags.add("external_send")
            contribution = min(0.9, contribution + 0.1)
            reasons.append("Payment/phishing content paired with external send")

        return self._finding(
            entities=entities, reasons=reasons, risk_contribution=contribution, tags=tags
        )
