"""Action-intent detector.

Infers risky *intent* (bulk / destructive / external-send) directly from the action
text, so the guardrail does not depend on the planner self-reporting risk_hint. This
matters because the planner (an LLM) is exactly the component we don't trust to flag
its own dangerous actions.

Emits tags (bulk_action / destructive_action / external_send) that the policy engine
treats as risk hints, plus a risk contribution.
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest
from .base import Detector, Finding

_BULK_THRESHOLD = 20

# A count that directly quantifies a collection noun ("500 promotional emails"),
# not a monetary amount ($450.00) or an id (BK-001). The negative lookbehind drops
# currency/decimals; the count must be within ~2 words of the collection noun.
_BULK_QUANT_RE = re.compile(
    r"(?<![$\d.])\b(\d{2,})\s+(?:[a-z]+\s+){0,2}"
    r"(?:emails?|messages?|files?|records?|contacts?|threads?|rows?|items?|inboxe?s?)\b",
    re.IGNORECASE,
)
_AFFECTED_RE = re.compile(r"\baffected_items\s*[=:]\s*(\d+)", re.IGNORECASE)
_BULK_WORD_RE = re.compile(
    r"\b(?:bulk|in bulk|all (?:the )?(?:emails?|messages?|files?|records?|contacts?)|"
    r"every (?:email|message|file|record|contact)|mass (?:archive|delete|send))\b",
    re.IGNORECASE,
)
_DESTRUCTIVE_RE = re.compile(
    r"\b(?:delete|remove|erase|wipe|purge|drop|cancel|revoke|truncate|uninstall|"
    r"archive all|empty the|clear all)\b",
    re.IGNORECASE,
)
_SEND_VERB_RE = re.compile(
    r"\b(?:send|forward|email|post|publish|upload|share|submit|deliver)\b", re.IGNORECASE
)
_EXTERNAL_HINT_RE = re.compile(
    r"(?:@[\w.-]+\.\w+|\bcustomer\b|\bexternal\b|\bpublic\b|\bgist\b|\bslack\b|\brecipient\b|https?://)",
    re.IGNORECASE,
)


class ActionIntentDetector(Detector):
    name = "action_intent"

    def scan(self, req: ActionRequest) -> Finding:
        text = req.scan_text
        reasons: list[str] = []
        tags: set[str] = set()
        contribution = 0.0

        # --- bulk -------------------------------------------------------
        counts = [int(n) for n in _AFFECTED_RE.findall(text)]
        counts += [int(n) for n in _BULK_QUANT_RE.findall(text)]
        big = max(counts) if counts else 0
        if big >= _BULK_THRESHOLD or _BULK_WORD_RE.search(text):
            tags.add("bulk_action")
            reasons.append(f"Bulk operation detected ({big or 'many'} items)")
            contribution = max(contribution, 0.5)

        # --- destructive ------------------------------------------------
        if _DESTRUCTIVE_RE.search(text):
            tags.add("destructive_action")
            reasons.append("Destructive verb detected (delete/cancel/purge/...)")
            contribution = max(contribution, 0.7 if not req.rollback_available else 0.5)

        # --- external send ---------------------------------------------
        if _SEND_VERB_RE.search(text) and _EXTERNAL_HINT_RE.search(text):
            tags.add("external_send")
            reasons.append("Outbound send to an external recipient detected")
            contribution = max(contribution, 0.35)

        return self._finding(reasons=reasons, risk_contribution=contribution, tags=tags)
