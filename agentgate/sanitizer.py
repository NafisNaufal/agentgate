"""Sanitizer: produce a redacted payload when safe continuation is possible.

Replaces detected sensitive spans (emails, cards, secrets, payment links, ...) with
typed placeholders, so an action can sometimes proceed in SANITIZE mode instead of
being blocked outright.
"""

from __future__ import annotations

import re

from .detectors import pii, secrets, payment_phishing

# Order matters: redact the most specific / highest-risk patterns first.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (secrets.PATTERNS[7][1], "[REDACTED_PRIVATE_KEY]"),  # PRIVATE KEY block
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "[REDACTED_STRIPE_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    (secrets.ASSIGN_RE, lambda m: f"{m.group(1)}=[REDACTED]"),
    (pii.CARD_RE, "[REDACTED_CARD]"),
    (pii.EMAIL_RE, "[REDACTED_EMAIL]"),
    (payment_phishing.PAYMENT_LINK_RE, "[REDACTED_PAYMENT_LINK]"),
    (pii.BOOKING_RE, "[REDACTED_BOOKING_REF]"),
]


def sanitize(text: str) -> str:
    """Return a redacted copy of ``text``."""
    out = text
    for pattern, repl in _REDACTIONS:
        out = pattern.sub(repl, out)
    return out
