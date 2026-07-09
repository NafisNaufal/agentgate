"""Source-code detector: flags source-code egress, especially to external targets.

Heuristic: count code-like signals (keywords, syntax, file extensions). On its own,
reading code is fine; the *risk* spikes when code is about to leave the boundary
(external send) - that combination is handled by the policy engine, but the detector
surfaces the source-code signal and tags it.
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate

CODE_KEYWORD_RE = re.compile(
    r"\b(?:def|class|import|from|return|function|const|let|var|public|private|"
    r"async|await|#include|package|fn|impl|struct|module\.exports|require)\b"
)
CODE_SYNTAX_RE = re.compile(r"(?:=>|::|->|\{\s*$|\);|\bself\b|\bconsole\.log\b|\bprintln!)")
CODE_EXT_RE = re.compile(r"\.(?:py|js|ts|jsx|tsx|java|go|rb|rs|c|cpp|cs|php|swift|kt|sh)\b")
CODENAME_RE = re.compile(r"\b(?:project|codename|internal)[-_ ][A-Z][A-Za-z0-9]{2,}\b")


class SourceCodeDetector(Detector):
    name = "source_code"

    def scan(self, req: ActionRequest) -> Finding:
        text = req.scan_text
        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()

        signals = (
            len(CODE_KEYWORD_RE.findall(text))
            + len(CODE_SYNTAX_RE.findall(text))
            + len(CODE_EXT_RE.findall(text))
        )
        code_like = signals >= 2 or "source_code" in req.risk_hint

        if code_like:
            tags.add("source_code")
            snippet = _first_code_line(text) or truncate(text)
            entities.append(SensitiveEntity("SOURCE_CODE", truncate(snippet), self.name, "MEDIUM"))
            reasons.append(f"Source code detected ({signals} code signals)")

        for m in CODENAME_RE.findall(text):
            entities.append(SensitiveEntity("INTERNAL_CODENAME", truncate(m), self.name, "MEDIUM"))
            reasons.append("Internal codename detected")

        # Base contribution; the policy engine escalates when combined with external_send.
        contribution = 0.0
        if code_like:
            contribution = 0.3
            # Escalate only on real egress: an explicit external_send hint (the tool
            # registry attaches this to gist/send tools) or a browser submit. A plain
            # API_CALL is NOT egress — github_read_file / github_commit are reads/writes,
            # not outbound sends, and must not be over-flagged.
            if "external_send" in req.risk_hint or req.action_type == "BROWSER_SUBMIT":
                contribution = 0.6
                reasons.append("Source code paired with an outbound/send action")
        return self._finding(
            entities=entities, reasons=reasons, risk_contribution=contribution, tags=tags
        )


def _first_code_line(text: str) -> str:
    for line in text.splitlines():
        if CODE_KEYWORD_RE.search(line) or CODE_SYNTAX_RE.search(line):
            return line.strip()
    return ""
