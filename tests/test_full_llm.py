from __future__ import annotations

import json
import unittest
from typing import Any, Mapping
from unittest.mock import patch

from agentgate.cli import build_parser
from agentgate.decision import DecisionEngine
from agentgate.detectors import (
    LLMPaymentPhishingDetector,
    LLMPIIDetector,
    LLMSourceCodeDetector,
    get_default_detectors,
)
from agentgate.detectors.base import Detector
from agentgate.detectors.base import Finding
from agentgate.detectors.llm_client import LLMUnavailable, chat_json
from agentgate.executors import ExecutionResult, ExecutorRegistry
from agentgate.loop import AgentLoop
from agentgate.planner import ReplayPlanner
from agentgate.router import DecisionRouter
from agentgate.schemas import ActionRequest, Decision, SensitiveEntity


class FakeResponse:
    def __init__(self, value: Any) -> None:
        self.body = json.dumps(value).encode("utf-8")

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None


class TestLLMClient(unittest.TestCase):
    @patch("agentgate.detectors.llm_client.urllib.request.urlopen")
    def test_valid_structured_response(self, urlopen):
        urlopen.return_value = FakeResponse(
            {"message": {"content": json.dumps({"has_pii": False, "items": []})}}
        )
        result = chat_json("system", "TEXT: hello", model="test-model", timeout=2)
        self.assertEqual(result, {"has_pii": False, "items": []})
        request = urlopen.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(body["format"], "json")
        self.assertFalse(body["stream"])
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 2.0)

    @patch("agentgate.detectors.llm_client.urllib.request.urlopen")
    def test_non_object_model_output_is_rejected(self, urlopen):
        urlopen.return_value = FakeResponse({"message": {"content": "[]"}})
        with self.assertRaises(LLMUnavailable):
            chat_json("system", "TEXT: hello")

    @patch("agentgate.detectors.llm_client.urllib.request.urlopen", side_effect=TimeoutError())
    def test_timeout_is_controlled(self, _urlopen):
        with self.assertRaisesRegex(LLMUnavailable, "unavailable or returned an invalid"):
            chat_json("system", "TEXT: hello")

    def test_invalid_host_is_controlled(self):
        with self.assertRaisesRegex(LLMUnavailable, "full HTTP"):
            chat_json("system", "TEXT: hello", host="not-a-url")


class TestFullLLMFailureHandling(unittest.TestCase):
    @patch("agentgate.detectors.llm_client.chat_json", side_effect=LLMUnavailable("offline"))
    def test_unavailable_runtime_needs_approval(self, _chat):
        result = DecisionEngine().evaluate(
            ActionRequest(action_type="API_CALL", payload_summary="sensitive action")
        )
        self.assertEqual(result.decision, Decision.NEED_APPROVAL)
        self.assertIn("Ensure Ollama is running", " ".join(result.reasons))

    def test_malformed_detector_schema_needs_approval(self):
        with patch(
            "agentgate.detectors.llm_client.chat_json",
            return_value={"has_pii": "false", "items": []},
        ):
            result = DecisionEngine(detectors=[LLMPIIDetector()]).evaluate(
                ActionRequest(action_type="API_CALL", payload_summary="hello")
            )
        self.assertEqual(result.decision, Decision.NEED_APPROVAL)

    def test_true_flag_with_empty_items_needs_approval(self):
        with patch(
            "agentgate.detectors.llm_client.chat_json",
            return_value={"has_pii": True, "items": []},
        ):
            result = DecisionEngine(detectors=[LLMPIIDetector()]).evaluate(
                ActionRequest(action_type="API_CALL", payload_summary="hello")
            )
        self.assertEqual(result.decision, Decision.NEED_APPROVAL)

    def test_trusted_hints_apply_without_scan_text(self):
        source = DecisionEngine(detectors=[LLMSourceCodeDetector()]).evaluate(
            ActionRequest(
                action_type="API_CALL",
                risk_hint=["source_code", "external_send"],
            )
        )
        payment = DecisionEngine(detectors=[LLMPaymentPhishingDetector()]).evaluate(
            ActionRequest(
                action_type="API_CALL",
                risk_hint=["payment_related", "external_send"],
            )
        )
        self.assertEqual(source.decision, Decision.NEED_APPROVAL)
        self.assertEqual(payment.decision, Decision.NEED_APPROVAL)

    def test_contradictory_source_and_intent_responses_fail_closed(self):
        source_response = {
            "has_code": False,
            "has_codename": False,
            "language": "python",
            "confidence": 0.9,
        }
        intent_response = {
            "is_bulk": False,
            "estimated_count": 1000,
            "is_destructive": False,
            "is_external_send": False,
            "confidence": 0.9,
        }
        with patch(
            "agentgate.detectors.llm_client.chat_json",
            return_value=source_response,
        ):
            source = DecisionEngine(detectors=[LLMSourceCodeDetector()]).evaluate(
                ActionRequest(action_type="API_CALL", payload_summary="archive data")
            )
        from agentgate.detectors import LLMActionIntentDetector

        with patch(
            "agentgate.detectors.llm_client.chat_json",
            return_value=intent_response,
        ):
            intent = DecisionEngine(detectors=[LLMActionIntentDetector()]).evaluate(
                ActionRequest(action_type="API_CALL", payload_summary="archive data")
            )
        self.assertEqual(source.decision, Decision.NEED_APPROVAL)
        self.assertEqual(intent.decision, Decision.NEED_APPROVAL)

    def test_unexpected_detector_error_needs_approval(self):
        class BrokenDetector(Detector):
            name = "broken"

            def scan(self, req):
                raise RuntimeError("boom")

        result = DecisionEngine(detectors=[BrokenDetector()]).evaluate(
            ActionRequest(action_type="API_CALL", payload_summary="hello")
        )
        self.assertEqual(result.decision, Decision.NEED_APPROVAL)
        self.assertIn("failed", " ".join(result.reasons))

    def test_generic_secret_egress_is_blocked(self):
        class GenericSecretDetector(Detector):
            name = "secret"

            def scan(self, req):
                return Finding(
                    detector=self.name,
                    entities=[
                        SensitiveEntity(
                            "GENERIC_SECRET",
                            "[REDACTED_GENERIC_SECRET]",
                            self.name,
                            "HIGH",
                        )
                    ],
                    risk_contribution=0.55,
                    tags={"source_code"},
                )

        result = DecisionEngine(detectors=[GenericSecretDetector()]).evaluate(
            ActionRequest(action_type="API_CALL", risk_hint=["external_send"])
        )
        self.assertEqual(result.decision, Decision.BLOCK)

    def test_semantic_secret_is_opaque_in_run_serialization(self):
        class SemanticSecretDetector(Detector):
            name = "secret"

            def scan(self, req):
                return Finding(
                    detector=self.name,
                    entities=[
                        SensitiveEntity(
                            "GENERIC_SECRET",
                            "[REDACTED_GENERIC_SECRET]",
                            self.name,
                            "CRITICAL",
                        )
                    ],
                    risk_contribution=0.85,
                )

        loop = AgentLoop(
            ReplayPlanner([{
                "action_type": "API_CALL",
                "arguments": {
                    "tool_name": "github_create_issue",
                    "title": "The passphrase is hunter2",
                },
            }]),
            decider=DecisionEngine(detectors=[SemanticSecretDetector()]),
        )
        serialized = json.dumps(loop.run("Publish the passphrase hunter2").to_dict())
        self.assertNotIn("hunter2", serialized)
        self.assertIn("[REDACTED_SENSITIVE_CONTENT]", serialized)

    def test_immediate_terminal_cannot_expose_semantic_secret_task(self):
        class SemanticSecretDetector(Detector):
            name = "secret"

            def scan(self, req):
                if "hunter2" not in req.scan_text:
                    return Finding(detector=self.name)
                return Finding(
                    detector=self.name,
                    entities=[
                        SensitiveEntity(
                            "GENERIC_SECRET",
                            "[REDACTED_GENERIC_SECRET]",
                            self.name,
                            "CRITICAL",
                        )
                    ],
                    risk_contribution=0.85,
                )

        result = AgentLoop(
            ReplayPlanner([{"action_type": "DONE", "arguments": {"result_summary": "done"}}]),
            decider=DecisionEngine(detectors=[SemanticSecretDetector()]),
        ).run("Task contains passphrase hunter2")
        self.assertNotIn("hunter2", json.dumps(result.to_dict()))

    def test_internal_codename_egress_requires_approval_and_is_masked(self):
        response = {
            "has_code": False,
            "has_codename": True,
            "language": "",
            "confidence": 0.9,
        }
        with patch(
            "agentgate.detectors.llm_client.chat_json",
            return_value=response,
        ):
            result = DecisionEngine(detectors=[LLMSourceCodeDetector()]).evaluate(
                ActionRequest(
                    action_type="API_CALL",
                    payload_summary="Discuss Project ApolloZeus",
                    risk_hint=["external_send"],
                )
            )
        self.assertEqual(result.decision, Decision.NEED_APPROVAL)
        self.assertEqual(
            result.sensitive_entities[0].snippet,
            "[REDACTED_INTERNAL_CODENAME]",
        )

    @patch("agentgate.detectors.llm_client.chat_json", side_effect=LLMUnavailable("offline"))
    def test_unavailable_runtime_never_dispatches(self, _chat):
        class RecordingExecutor:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
                self.calls += 1
                return ExecutionResult(True, "success", "unexpected")

        executor = RecordingExecutor()
        registry = ExecutorRegistry()
        registry.register_action("FILE_READ", executor)
        loop = AgentLoop(
            ReplayPlanner(
                [{"action_type": "FILE_READ", "arguments": {"path": "public/readme.txt"}}]
            ),
            DecisionRouter(registry, execute=True),
        )
        result = loop.run("read file")
        self.assertEqual(result.status, "awaiting_approval")
        self.assertEqual(executor.calls, 0)

    def test_default_engine_uses_only_full_llm_suite(self):
        engine = DecisionEngine()
        self.assertEqual(
            [type(detector) for detector in engine.detectors],
            [type(detector) for detector in get_default_detectors()],
        )

    def test_cli_has_no_architecture_selector(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["run", "booking_message", "--architecture", "regex"])


if __name__ == "__main__":
    unittest.main()
