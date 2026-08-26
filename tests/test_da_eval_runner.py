from __future__ import annotations

import unittest

from agentgate.schemas import Decision, DecisionResponse, RiskLevel, SensitiveEntity
from benchmarks.da_eval_runner import evaluate_cases


class FakeAuditStore:
    def __init__(self, completeness: float = 1.0) -> None:
        self._completeness = completeness

    def completeness(self) -> float:
        return self._completeness

    def get(self, audit_id: str) -> dict:
        return {
            "audit_id": audit_id,
            "timestamp": 1.0,
            "request": {"action_type": "API_CALL"},
            "response": {"decision": "ALLOW", "reasons": ["clean"]},
            "execution_status": "pending",
        }


class BrokenAuditStore:
    def get(self, audit_id: str) -> dict:
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


class RaisingDecisionEngine(FakeDecisionEngine):
    def evaluate(self, request):
        raise RuntimeError("evaluation failed")


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
            _case("SAFE", "API_CALL", "ALLOW", "LOW"),
            _case("UNSAFE", "FILE_READ", "BLOCK", "CRITICAL"),
            _case("APPROVAL", "BROWSER_SUBMIT", "NEED_APPROVAL", "HIGH"),
            _case("BENIGN", "BROWSER_OPEN", "ALLOW", "LOW"),
            _case("SENSITIVE", "FILE_DELETE", "BLOCK", "CRITICAL", entity_kinds=["EMAIL"]),
            _case("INFERRED", "BROWSER_CLICK", "ALLOW", "LOW", source="inferred"),
        ]
        engine = FakeDecisionEngine(
            {
                "API_CALL": _response(Decision.ALLOW, RiskLevel.LOW, policies=["policy.used"]),
                "FILE_READ": _response(Decision.ALLOW, RiskLevel.LOW),
                "BROWSER_SUBMIT": _response(Decision.ASK_USER, RiskLevel.MEDIUM),
                "BROWSER_OPEN": _response(Decision.BLOCK, RiskLevel.CRITICAL),
                "FILE_DELETE": _response(
                    Decision.BLOCK,
                    RiskLevel.CRITICAL,
                    entities=[SensitiveEntity("EMAIL", "[REDACTED_EMAIL]", "test")],
                ),
                "BROWSER_CLICK": _response(Decision.ALLOW, RiskLevel.LOW),
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
        self.assertEqual(report["metrics"]["audit_completeness"]["value"], 1.0)
        self.assertIsNone(report["metrics"]["task_success"])
        self.assertEqual(
            report["headline_metrics"]["unsafe_auto_allow_rate"]["denominator"], 3
        )
        self.assertEqual(report["metrics_by_expectation_source"]["inferred"]["total"], 1)

    def test_risk_mismatch_is_a_failed_case_and_json_safe(self) -> None:
        cases = [_case("RISK", "API_CALL", "ALLOW", "LOW")]
        engine = FakeDecisionEngine(
            {"API_CALL": _response(Decision.ALLOW, RiskLevel.MEDIUM)}
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
            {"API_CALL": _response(Decision.ALLOW, RiskLevel.LOW)}
        )
        engine.audit_store = BrokenAuditStore()

        report = evaluate_cases([_case("SAFE", "API_CALL", "ALLOW", "LOW")], engine)

        self.assertFalse(report["ok"])
        self.assertIn("audit read failed", report["metrics"]["audit_completeness"]["error"])

    def test_unknown_action_type_is_an_invalid_case(self) -> None:
        engine = FakeDecisionEngine({})
        case = _case("INVALID", "NOT_AN_ACTION", "ALLOW", "LOW")

        report = evaluate_cases([case], engine)

        self.assertFalse(report["ok"])
        self.assertIn("unknown action_type", report["cases"][0]["error"])
        self.assertEqual(engine.requests, [])

    def test_fail_closed_detector_response_is_still_a_runtime_failure(self) -> None:
        response = _response(Decision.NEED_APPROVAL, RiskLevel.HIGH)
        response.evaluation_error = "LLM detector is unavailable. Ollama is offline."
        engine = FakeDecisionEngine({"API_CALL": response})

        report = evaluate_cases(
            [_case("OUTAGE", "API_CALL", "NEED_APPROVAL", "HIGH")], engine
        )

        self.assertFalse(report["ok"])
        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["summary"]["mismatches"], 0)

    def test_failed_sensitive_case_stays_in_recall_denominator(self) -> None:
        engine = RaisingDecisionEngine({})

        report = evaluate_cases(
            [
                _case(
                    "SENSITIVE",
                    "API_CALL",
                    "BLOCK",
                    "CRITICAL",
                    entity_kinds=["SOURCE_CODE"],
                )
            ],
            engine,
        )

        recall = report["metrics"]["sensitive_data_detection_recall"]
        self.assertEqual(recall["value"], 0.0)
        self.assertEqual(recall["denominator"], 1)


if __name__ == "__main__":
    unittest.main()
