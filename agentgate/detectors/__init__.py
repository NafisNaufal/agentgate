"""Detectors: turn raw action text into structured sensitive-entity findings.

Each detector is a small, independently testable unit. The decision engine runs all
of them over an ActionRequest and aggregates their findings.

DEFAULT_DETECTORS is the regex-only set - no network/model calls, always available.
Four architectures are supported:

  "regex"     - regex-only, zero dependencies, always available.
  "hybrid"    - regex fast-path, LLM fallback only when regex finds nothing.
  "llm_first" - prompt-injection goes through the LLM directly; other detectors
                remain regex-based.
  "full_llm"  - ALL detectors use the local LLM (100% LLM, zero regex).
                DEFAULT architecture: if Ollama isn't running, all detectors fail
                safe to "no finding" rather than crashing.
"""

import os

from .base import Detector, Finding
from .pii import PIIDetector
from .secrets import SecretDetector
from .source_code import SourceCodeDetector
from .payment_phishing import PaymentPhishingDetector
from .prompt_injection import PromptInjectionDetector
from .intent import ActionIntentDetector
from .injection_hybrid import HybridPromptInjectionDetector
from .injection_llm_first import LLMFirstInjectionDetector
from .llm_detectors import (
    LLMPIIDetector,
    LLMSecretDetector,
    LLMSourceCodeDetector,
    LLMPaymentPhishingDetector,
    LLMActionIntentDetector,
)

# Zero-dependency detector set: regex-only, no network/model calls, always available.
DEFAULT_DETECTORS: list[Detector] = [
    PIIDetector(),
    SecretDetector(),
    SourceCodeDetector(),
    PaymentPhishingDetector(),
    PromptInjectionDetector(),
    ActionIntentDetector(),
]

_ARCHITECTURES = {"regex", "hybrid", "llm_first", "full_llm"}


def get_default_detectors(architecture: str | None = None) -> list[Detector]:
    """Build the detector list for a given architecture.

    architecture: one of "regex", "hybrid", "llm_first", "full_llm". None reads
    the AGENTGATE_DETECTOR_ARCHITECTURE env var, defaulting to "full_llm" if unset.
    LLM-based architectures use a local Ollama server if one is running, but never
    require it to be - they fail safe to a "no finding" result if Ollama is
    unreachable.
    """
    if architecture is None:
        architecture = os.environ.get("AGENTGATE_DETECTOR_ARCHITECTURE", "full_llm")
    if architecture not in _ARCHITECTURES:
        raise ValueError(f"Unknown architecture {architecture!r}; expected one of {_ARCHITECTURES}")

    if architecture == "regex":
        return list(DEFAULT_DETECTORS)

    if architecture == "full_llm":
        return [
            LLMPIIDetector(),
            LLMSecretDetector(),
            LLMSourceCodeDetector(),
            LLMPaymentPhishingDetector(),
            LLMFirstInjectionDetector(),
            LLMActionIntentDetector(),
        ]

    injection_cls = HybridPromptInjectionDetector if architecture == "hybrid" else LLMFirstInjectionDetector
    return [
        PIIDetector(),
        SecretDetector(),
        SourceCodeDetector(),
        PaymentPhishingDetector(),
        injection_cls(),
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
    "LLMFirstInjectionDetector",
    "LLMPIIDetector",
    "LLMSecretDetector",
    "LLMSourceCodeDetector",
    "LLMPaymentPhishingDetector",
    "LLMActionIntentDetector",
    "DEFAULT_DETECTORS",
    "get_default_detectors",
]
