"""PII detector: emails, phone numbers, credit-card-like numbers, booking data.

Regex/heuristic based. The goal for the MVP is high recall on a synthetic test set
(PRD target: >= 85% sensitive-data detection recall), not perfect precision.
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Phone: loose international/local; require at least 9 digits to cut false positives.
PHONE_RE = re.compile(r"(?<!\w)(\+?\d[\d\s().-]{8,}\d)(?!\w)")
# Credit-card-like: 13-16 digits, optionally grouped.
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
# Booking references like BK-001, RES12345, ORDER-2024-99
BOOKING_RE = re.compile(r"\b(?:BK|RES|RESV|ORDER|BOOK|PNR)[-_ ]?\d{2,}\b", re.IGNORECASE)


def _luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not (13 <= len(nums) <= 16):
        return False
    total, alt = 0, False
    for d in reversed(nums):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class PIIDetector(Detector):
    name = "pii"

    def scan(self, req: ActionRequest) -> Finding:
        text = req.scan_text
        entities: list[SensitiveEntity] = []
        reasons: list[str] = []

        # Dedupe by normalized value so the same email/ref appearing twice (e.g. in
        # both the body and a URL) is not counted as two separate findings.
        def _uniq(matches: list[str]) -> list[str]:
            return list(dict.fromkeys(m.strip().lower() for m in matches))

        for m in _uniq(EMAIL_RE.findall(text)):
            entities.append(SensitiveEntity("EMAIL", truncate(m), self.name, "MEDIUM"))

        seen_cards: set[str] = set()
        for m in CARD_RE.findall(text):
            digits = re.sub(r"\D", "", m)
            if _luhn_ok(digits) and digits not in seen_cards:
                seen_cards.add(digits)
                entities.append(
                    SensitiveEntity("CREDIT_CARD", "•••• " + digits[-4:], self.name, "HIGH")
                )

        for m in _uniq(PHONE_RE.findall(text)):
            if 9 <= len(re.sub(r"\D", "", m)) <= 15 and not _looks_like_card(m):
                entities.append(SensitiveEntity("PHONE", truncate(m), self.name, "LOW"))

        for m in _uniq(BOOKING_RE.findall(text)):
            entities.append(SensitiveEntity("BOOKING_REF", truncate(m), self.name, "MEDIUM"))

        if entities:
            kinds = sorted({e.kind for e in entities})
            reasons.append(f"PII / customer data detected: {', '.join(kinds)}")

        # Risk grows with count and max severity, capped.
        sev_weight = {"LOW": 0.1, "MEDIUM": 0.25, "HIGH": 0.45, "CRITICAL": 0.6}
        contribution = min(0.6, sum(sev_weight[e.severity] for e in entities))
        return self._finding(entities=entities, reasons=reasons, risk_contribution=contribution)


def _looks_like_card(s: str) -> bool:
    return _luhn_ok(re.sub(r"\D", "", s))
