"""Detectors: turn raw action text into structured sensitive-entity findings.

Each detector is a small, independently testable unit. The decision engine runs all
of them over an ActionRequest and aggregates their findings.
"""

from .base import Detector, Finding
from .pii import PIIDetector
from .secrets import SecretDetector
from .source_code import SourceCodeDetector
from .payment_phishing import PaymentPhishingDetector
from .prompt_injection import PromptInjectionDetector
from .intent import ActionIntentDetector

DEFAULT_DETECTORS: list[Detector] = [
    PIIDetector(),
    SecretDetector(),
    SourceCodeDetector(),
    PaymentPhishingDetector(),
    PromptInjectionDetector(),
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
    "DEFAULT_DETECTORS",
]
