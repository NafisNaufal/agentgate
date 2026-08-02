"""Detectors: turn raw action text into structured sensitive-entity findings.

Each detector is a small, independently testable unit. The decision engine runs all
of them over an ActionRequest and aggregates their findings.

DEFAULT_DETECTORS is the zero-dependency, regex-only set - no network/model calls,
always available. Three LLM-based architectures for the fuzzy detection categories
(prompt injection, primarily) were built and benchmarked (see
benchmarks/detector_bakeoff.py) rather than picked by guess:

  A. "hybrid"    - regex fast-path, LLM fallback only when regex finds nothing
  B. "llm_first" - every action goes through the LLM directly, no regex fast-path
  C. "unified"   - one LLM call classifies across ALL categories, replacing the
                   regex detector list entirely rather than augmenting it

All three require a local Ollama server; DEFAULT_DETECTORS is unaffected if you
don't opt in.
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
from .unified_llm import UnifiedLLMDetector

# Zero-dependency default: regex-only, no network/model calls, always available.
DEFAULT_DETECTORS: list[Detector] = [
    PIIDetector(),
    SecretDetector(),
    SourceCodeDetector(),
    PaymentPhishingDetector(),
    PromptInjectionDetector(),
    ActionIntentDetector(),
]

_ARCHITECTURES = {"regex", "hybrid", "llm_first", "unified"}


def get_default_detectors(architecture: str | None = None) -> list[Detector]:
    """Build the detector list for a given injection-detection architecture.

    architecture: one of "regex" (default), "hybrid", "llm_first", "unified".
    None reads the AGENTGATE_DETECTOR_ARCHITECTURE env var, defaulting to "regex"
    if unset. All non-"regex" options require a local Ollama server - see
    benchmarks/detector_bakeoff.py for the measured accuracy/latency trade-offs
    that motivated "hybrid" as the recommended default when an LLM is available.
    """
    if architecture is None:
        architecture = os.environ.get("AGENTGATE_DETECTOR_ARCHITECTURE", "regex")
    if architecture not in _ARCHITECTURES:
        raise ValueError(f"Unknown architecture {architecture!r}; expected one of {_ARCHITECTURES}")

    if architecture == "regex":
        return list(DEFAULT_DETECTORS)

    if architecture == "unified":
        # Replaces the whole detector list with one multi-category LLM call.
        return [UnifiedLLMDetector(), ActionIntentDetector()]

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
    "UnifiedLLMDetector",
    "DEFAULT_DETECTORS",
    "get_default_detectors",
]
