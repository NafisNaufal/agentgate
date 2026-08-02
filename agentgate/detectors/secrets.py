"""Secret detector: API keys, private keys, tokens, credentials, env files.

Covers the Code/data protection policy risks (PRD section 12).
"""

from __future__ import annotations

import re

from ..schemas import ActionRequest, SensitiveEntity
from .base import Detector, Finding, truncate

# Named, high-confidence key formats first.
PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    ("GITHUB_TOKEN", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "CRITICAL"),
    ("GITHUB_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "CRITICAL"),
    ("OPENAI_KEY", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "CRITICAL"),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "CRITICAL"),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), "CRITICAL"),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "HIGH"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "HIGH"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "CRITICAL"),
]

# Generic "KEY = value" style assignments (lower confidence).
ASSIGN_RE = re.compile(
    r"(?i)\b([a-z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key))\b"
    r"\s*[:=]\s*[\"']?([^\s\"']{6,})"
)
# Matches .env, secrets.env, prod.env.local, path/.env, credentials.json, etc.
ENV_FILE_RE = re.compile(r"(?i)(?:^|[\\/.\w-])[\w.-]*\.env(?:\.[a-z]+)?\b|\bcredentials(?:\.json)?\b")


class SecretDetector(Detector):
    name = "secret"

    def scan(self, req: ActionRequest) -> Finding:
        text = req.scan_text
        entities: list[SensitiveEntity] = []
        reasons: list[str] = []
        tags: set[str] = set()

        for kind, pat, sev in PATTERNS:
            for m in pat.findall(text):
                snippet = m if isinstance(m, str) else m[0]
                entities.append(SensitiveEntity(kind, _mask(snippet), self.name, sev))

        for name, _val in ASSIGN_RE.findall(text):
            entities.append(
                SensitiveEntity("CREDENTIAL_ASSIGNMENT", truncate(name) + "=•••", self.name, "HIGH")
            )

        # Accessing an env / credentials file is itself a risk signal.
        if ENV_FILE_RE.search(text) or ENV_FILE_RE.search(req.target):
            entities.append(SensitiveEntity("ENV_FILE", truncate(req.target or ".env"), self.name, "HIGH"))
            reasons.append("Action touches an environment/credentials file")

        if entities:
            tags.add("source_code")  # secrets typically co-occur with code/data egress
            kinds = sorted({e.kind for e in entities})
            reasons.append(f"Secret/credential material detected: {', '.join(kinds)}")

        has_critical = any(e.severity == "CRITICAL" for e in entities)
        contribution = 0.0
        if entities:
            contribution = 0.85 if has_critical else 0.55
        return self._finding(
            entities=entities, reasons=reasons, risk_contribution=contribution, tags=tags
        )


def _mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return s[:2] + "•••"
    return s[:4] + "…" + s[-2:]
