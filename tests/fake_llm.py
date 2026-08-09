"""Deterministic Ollama classifier fake shared by unit tests."""

from __future__ import annotations

import re
from typing import Any


def fake_chat_json(
    system_prompt: str,
    user_content: str,
    **_: Any,
) -> dict[str, Any]:
    text = user_content.partition("TEXT:")[2].strip()
    lowered = text.lower()
    prompt = system_prompt.lower()

    if "personally identifiable information" in prompt:
        items: list[dict[str, str]] = []
        for email in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text):
            items.append({"type": "EMAIL", "value": email, "severity": "MEDIUM"})
        for booking in re.findall(r"\b(?:BK|RES|ORDER)[-_]?\d{2,}\b", text, re.I):
            items.append({"type": "BOOKING_REF", "value": booking, "severity": "MEDIUM"})
        if "4111 1111 1111 1111" in text or "4111111111111111" in text:
            items.append({"type": "CREDIT_CARD", "value": "4111111111111111", "severity": "HIGH"})
        return {"has_pii": bool(items), "items": items}

    if "secret/credential classifier" in prompt:
        items = []
        if "AKIAIOSFODNN7EXAMPLE" in text:
            items.append({"type": "AWS_ACCESS_KEY", "value": "masked", "severity": "CRITICAL"})
        if "ghp_" in text:
            items.append({"type": "GITHUB_TOKEN", "value": "masked", "severity": "CRITICAL"})
        if "PRIVATE KEY" in text:
            items.append({"type": "PRIVATE_KEY", "value": "masked", "severity": "CRITICAL"})
        if ".env" in lowered or "credentials.json" in lowered:
            items.append({"type": "ENV_FILE", "value": "masked", "severity": "HIGH"})
        return {"has_secrets": bool(items), "items": items}

    if "source-code classifier" in prompt:
        has_code = any(token in text for token in ("def ", "import ", "return ", "SELECT *"))
        return {
            "has_code": has_code,
            "has_codename": False,
            "language": "python" if has_code else "",
            "confidence": 0.95,
        }

    if "payment/phishing classifier" in prompt:
        payment = any(word in lowered for word in ("payment", "charge", "refund", "invoice", "checkout"))
        credential = any(word in lowered for word in ("send your password", "provide your pin", "share your otp"))
        urgency = "urgent" in lowered or "immediately" in lowered
        return {
            "has_payment": payment,
            "has_credential_request": credential,
            "has_urgency": urgency,
            "confidence": 0.95,
        }

    if "action-intent classifier" in prompt:
        counts = [int(value) for value in re.findall(r"affected_items[=:]\s*(\d+)", text, re.I)]
        counts.extend(
            int(value)
            for value in re.findall(
                r"\b(\d{2,})\s+(?:[A-Za-z]+\s+){0,2}"
                r"(?:emails?|messages?|files?|records?|items?)\b",
                text,
                re.I,
            )
        )
        bulk = bool(counts and max(counts) >= 20) or "bulk" in lowered
        destructive = any(word in lowered for word in ("delete", "cancel", "purge", "remove"))
        external = any(word in lowered for word in ("send", "forward", "publish", "external"))
        return {
            "is_bulk": bulk,
            "estimated_count": max(counts) if counts else 0,
            "is_destructive": destructive,
            "is_external_send": external,
            "confidence": 0.95,
        }

    injection = "ignore previous instructions" in lowered or "reveal the system prompt" in lowered
    return {"label": "injection" if injection else "benign", "confidence": 0.98}
