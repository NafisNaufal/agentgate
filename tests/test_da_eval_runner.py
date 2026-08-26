from __future__ import annotations

import unittest

from agentgate.schemas import Decision, DecisionResponse, RiskLevel, SensitiveEntity
from benchmarks.da_eval_runner import evaluate_cases


class FakeAuditStore:
    def __init__(self, completeness: float = 1.0) -> None:
        self._completeness = completeness

    def completeness(self) -> float:
        return self._completeness


class BrokenAuditStore:
    def completeness(self) -> float:
        raise RuntimeError("audit read failed")


class FakePolicyEngine:
    def __init__(self) -> None:
        self.rules = [
            {"id": "policy.used"},
            {"id": "policy.unused"},
        ]


class FakeDecisionEngine:
    def __init__(self, responses: dict[str, DecisionResponse]) -> None:
        self.responses = responses
        self.policy_engine = FakePolicyEngine()
        self.audit_store = FakeAuditStore(0.8)
        self.requests = []

    def evaluate(self, request):
        self.requests.append(request)
        return self.responses[request.action_type]


def _case(
    case_id: str,
    action_type: str,
    expected_decision: str,
    expected_risk_level: str,
    *,
    source: str = "da_approved",
    entity_kinds: list[str] | None = None,
) -> dict:
    return {
        "id": case_id,
        "title": case_id,
        "user_instruction": "evaluate this proposal",
        "expectation_source": source,
        "expected_decision": expected_decision,
        "expected_risk_level": expected_risk_level,
        "expected_entity_kinds": entity_kinds or [],
        "action_request": {"action_type": action_type},
    }


def _response(
    decision: Decision,
    risk_level: RiskLevel,
    *,
    policies: list[str] | None = None,
    entities: list[SensitiveEntity] | None = None,
) -> DecisionResponse:
    return DecisionResponse(
        decision=decision,
        risk_level=risk_level,
        risk_score=0.5,
        reasons=["test reason"],
        triggered_policies=policies or [],
        sensitive_entities=entities or [],
        audit_id="aud_test",
    )


class TestDAEvaluationRunner(unittest.TestCase):
    def test_reports_prd_metrics_and_separates_inferred_expectations(self) -> None:
        cases = [
            _case("SAFE", "safe", "ALLOW", "LOW"),
            _case("UNSAFE", "unsafe", "BLOCK", "CRITICAL"),
            _case("APPROVAL", "approval", "NEED_APPROVAL", "HIGH"),
            _case("BENIGN", "benign", "ALLOW", "LOW"),
            _case("SENSITIVE", "sensitive", "BLOCK", "CRITICAL", entity_kinds=["EMAIL"]),
            _case("INFERRED", "inferred", "ALLOW", "LOW", source="inferred"),
        ]
        engine = FakeDecisionEngine(
            {
                "safe": _response(Decision.ALLOW, RiskLevel.LOW, policies=["policy.used"]),
                "unsafe": _response(Decision.ALLOW, RiskLevel.LOW),
                "approval": _response(Decision.ASK_USER, RiskLevel.MEDIUM),
                "benign": _response(Decision.BLOCK, RiskLevel.CRITICAL),
                "sensitive": _response(
                    Decision.BLOCK,
                    RiskLevel.CRITICAL,
                    entities=[SensitiveEntity("EMAIL", "[REDACTED_EMAIL]", "test")],
                ),
                "inferred": _response(Decision.ALLOW, RiskLevel.LOW),
            }
        )

        report = evaluate_cases(cases, engine)

        self.assertFalse(report["ok"])
        self.assertEqual(report["summary"]["total"], 6)
        self.assertEqual(report["summary"]["matched"], 3)
        self.assertEqual(report["metrics"]["action_evaluation_completion_rate"]["value"], 1.0)
        self.assertAlmostEqual(
            report["metrics"]["unsafe_auto_allow_rate"]["value"], 1 / 3, places=3
        )
        self.assertAlmostEqual(
            report["metrics"]["false_block_rate"]["value"], 1 / 3, places=3
        )
        self.assertEqual(report["metrics"]["approval_routing_accuracy"]["value"], 1.0)
        self.assertEqual(report["metrics"]["sensitive_data_detection_recall"]["value"], 1.0)
        self.assertEqual(report["metrics"]["policy_coverage"]["value"], 0.5)
        self.assertEqual(report["metrics"]["audit_completeness"]["value"], 0.8)
        self.assertIsNone(report["metrics"]["task_success"])
        self.assertEqual(
            report["headline_metrics"]["unsafe_auto_allow_rate"]["denominator"], 3
        )
        self.assertEqual(report["metrics_by_expectation_source"]["inferred"]["total"], 1)

    def test_risk_mismatch_is_a_failed_case_and_json_safe(self) -> None:
        cases = [_case("RISK", "risk", "ALLOW", "LOW")]
        engine = FakeDecisionEngine(
            {"risk": _response(Decision.ALLOW, RiskLevel.MEDIUM)}
        )

        report = evaluate_cases(cases, engine)

        self.assertFalse(report["ok"])
        self.assertEqual(report["summary"]["matched"], 0)
        self.assertEqual(report["cases"][0]["decision_match"], True)
        self.assertEqual(report["cases"][0]["risk_match"], False)
        self.assertEqual(report["cases"][0]["match"], False)

    def test_invalid_case_is_reported_and_fails_without_evaluating(self) -> None:
        engine = FakeDecisionEngine({})
        cases = [{"id": "INVALID", "title": "missing request"}]

        report = evaluate_cases(cases, engine)

        self.assertFalse(report["ok"])
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertIn("action_request", report["cases"][0]["error"])
        self.assertEqual(engine.requests, [])

    def test_audit_metric_failure_fails_the_run(self) -> None:
        engine = FakeDecisionEngine(
            {"safe": _response(Decision.ALLOW, RiskLevel.LOW)}
        )
        engine.audit_store = BrokenAuditStore()

        report = evaluate_cases([_case("SAFE", "safe", "ALLOW", "LOW")], engine)

        self.assertFalse(report["ok"])
        self.assertIn("audit read failed", report["metrics"]["audit_completeness"]["error"])


if __name__ == "__main__":
    unittest.main()
