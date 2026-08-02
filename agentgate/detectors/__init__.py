"""Detectors: turn raw action text into structured sensitive-entity findings.

Each detector is a small, independently testable unit. The decision engine runs all
of them over an ActionRequest and aggregates their findings.

DEFAULT_DETECTORS is the regex-only set - no network/model calls, always available.
Two LLM-based architectures augment prompt-injection detection specifically (see
benchmarks/detector_bakeoff.py for the measured accuracy/latency numbers that
motivated the choice):

  "hybrid"    - regex fast-path, LLM fallback only when regex finds nothing.
                DEFAULT architecture: if Ollama isn't running, this fails safe and
                behaves exactly like plain regex - nothing breaks without it.
  "llm_first" - every action goes through the LLM directly, no regex fast-path.
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

# Zero-dependency detector set: regex-only, no network/model calls, always available.
DEFAULT_DETECTORS: list[Detector] = [
    PIIDetector(),
    SecretDetector(),
    SourceCodeDetector(),
    PaymentPhishingDetector(),
    PromptInjectionDetector(),
    ActionIntentDetector(),
]

_ARCHITECTURES = {"regex", "hybrid", "llm_first"}


def get_default_detectors(architecture: str | None = None) -> list[Detector]:
    """Build the detector list for a given injection-detection architecture.

    architecture: one of "regex", "hybrid" (default), "llm_first". None reads the
    AGENTGATE_DETECTOR_ARCHITECTURE env var, defaulting to "hybrid" if unset.
    "hybrid" and "llm_first" use a local Ollama server if one is running, but never
    require it to be - both fail safe to a "no finding" result (same as regex would
    give) if Ollama is unreachable.
    """
    if architecture is None:
        architecture = os.environ.get("AGENTGATE_DETECTOR_ARCHITECTURE", "hybrid")
    if architecture not in _ARCHITECTURES:
        raise ValueError(f"Unknown architecture {architecture!r}; expected one of {_ARCHITECTURES}")

    if architecture == "regex":
        return list(DEFAULT_DETECTORS)

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
    "DEFAULT_DETECTORS",
    "get_default_detectors",
]
