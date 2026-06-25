"""Prompt-injection detector.

Looks for instruction-override / exfiltration patterns embedded in page content or
tool payloads ("ignore previous instructions", "send all data to...", etc.). This is
content the agent *reads* (e.g. from a browser snapshot) trying to hijack the plan.
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate

INJECTION_PATTERNS = [
    re.compile(r"(?i)\bignore (?:all |the )?(?:previous|prior|above) (?:instructions|prompts?)\b"),
    re.compile(r"(?i)\bdisregard (?:all|the|your) (?:previous|prior|system) (?:instructions|prompt)\b"),
    re.compile(r"(?i)\byou are now (?:a |an )?\w+"),
    re.compile(r"(?i)\b(?:reveal|print|show|leak) (?:your |the )?(?:system prompt|instructions|api key|secrets?)\b"),
    re.compile(r"(?i)\bsend (?:all |the )?(?:data|emails?|files?|credentials?) to\b"),
    re.compile(r"(?i)\bdo not (?:tell|inform|alert) the user\b"),
    re.compile(r"(?i)\b(?:exfiltrate|forward everything|bypass (?:the )?(?:guardrail|safety|policy))\b"),
    re.compile(r"(?i)<\s*system\s*>|\[\s*system\s*\]"),
]


class PromptInjectionDetector(Detector):
    name = "prompt_injection"

    def scan(self, req: ActionRequest) -> Finding:
        # Injection most often arrives via page/content context, not the action itself.
        text = "\n".join((req.content_context, req.scan_text))
        entities: list[SensitiveEntity] = []
        reasons: list[str] = []

        for pat in INJECTION_PATTERNS:
            m = pat.search(text)
            if m:
                entities.append(
                    SensitiveEntity("PROMPT_INJECTION", truncate(m.group(0)), self.name, "HIGH")
                )

        contribution = 0.0
        if entities:
            reasons.append(f"Possible prompt injection ({len(entities)} pattern hit(s))")
            contribution = min(0.75, 0.4 + 0.15 * len(entities))
        return self._finding(entities=entities, reasons=reasons, risk_contribution=contribution)
