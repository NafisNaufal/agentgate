"""The sole production detector suite: full local-LLM classification via Ollama."""

from __future__ import annotations

from typing import Any

from .base import Detector, Finding
from .llm_detectors import (
    LLMActionIntentDetector,
    LLMPaymentPhishingDetector,
    LLMPIIDetector,
    LLMSecretDetector,
    LLMSourceCodeDetector,
)
from .llm_prompt_injection import LLMPromptInjectionDetector


def get_default_detectors(
    *,
    model: str | None = None,
    host: str | None = None,
    timeout: float | None = None,
    extra_options: dict[str, Any] | None = None,
) -> list[Detector]:
    """Build a fresh full-LLM detector suite.

    Legacy regex/hybrid implementations remain in the repository for historical
    benchmarks and deterministic sanitization patterns, but are not reachable through
    normal runtime configuration.
    """
    options = {
        "model": model,
        "host": host,
        "timeout": timeout,
        "extra_options": extra_options,
    }
    return [
        LLMPIIDetector(**options),
        LLMSecretDetector(**options),
        LLMSourceCodeDetector(**options),
        LLMPaymentPhishingDetector(**options),
        LLMPromptInjectionDetector(**options),
        LLMActionIntentDetector(**options),
    ]


__all__ = [
    "Detector",
    "Finding",
    "LLMPIIDetector",
    "LLMSecretDetector",
    "LLMSourceCodeDetector",
    "LLMPaymentPhishingDetector",
    "LLMPromptInjectionDetector",
    "LLMActionIntentDetector",
    "get_default_detectors",
]
