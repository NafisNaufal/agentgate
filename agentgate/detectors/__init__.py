"""Detectors: turn raw action text into structured sensitive-entity findings.

Each detector is a small, independently testable unit. The decision engine runs all
of them over an ActionRequest and aggregates their findings.
"""

import os

from .base import Detector, Finding
from .pii import PIIDetector
from .secrets import SecretDetector
from .source_code import SourceCodeDetector
from .payment_phishing import PaymentPhishingDetector
from .prompt_injection import PromptInjectionDetector
from .intent import ActionIntentDetector
from .injection_llm import HybridPromptInjectionDetector

# Zero-dependency default: regex-only, no network/model calls, always available.
DEFAULT_DETECTORS: list[Detector] = [
    PIIDetector(),
    SecretDetector(),
    SourceCodeDetector(),
    PaymentPhishingDetector(),
    PromptInjectionDetector(),
    ActionIntentDetector(),
]


def get_default_detectors(llm_injection: bool | None = None) -> list[Detector]:
    """Build the default detector list, optionally with the Gemma-backed hybrid
    prompt-injection detector in place of the regex-only one.

    llm_injection: True/False to force it; None (default) reads the
    AGENTGATE_LLM_INJECTION_DETECTOR env var (any non-empty value enables it).
    Requires a local Ollama server with the model pulled - see injection_llm.py.
    """
    if llm_injection is None:
        llm_injection = bool(os.environ.get("AGENTGATE_LLM_INJECTION_DETECTOR"))
    if not llm_injection:
        return list(DEFAULT_DETECTORS)
    return [
        PIIDetector(),
        SecretDetector(),
        SourceCodeDetector(),
        PaymentPhishingDetector(),
        HybridPromptInjectionDetector(),
        ActionIntentDetector(),
    ]


__all__ = [
    "Detector",
    "Finding",
    "PIIDetector",
    "SecretDetector",
    "SourceCodeDetector",
    "PaymentPhishingDetector",
    "PromptInjectionDetector",
    "ActionIntentDetector",
    "HybridPromptInjectionDetector",
    "DEFAULT_DETECTORS",
    "get_default_detectors",
]
