from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agentgate.decision import DecisionEngine
from agentgate.schemas import ActionRequest
from benchmarks.raw_vs_guarded import (
    BenchmarkError,
    _BenchmarkAuditStore,
    _percentile,
    deterministic_detectors,
    format_table,
    run_benchmark,
)
from tests.fake_audit import FakeAuditStore
from tests.fake_llm import fake_chat_json


class TestRawVsGuardedBenchmark(unittest.TestCase):
    def test_benchmark_audit_store_redacts_sensitive_requests(self):
        store = _BenchmarkAuditStore()
        request = ActionRequest(
            action_type="API_CALL",
            raw_payload="Contact john@example.com",
        )
        with patch("agentgate.decision.build_audit_store", FakeAuditStore):
            decision = DecisionEngine(
                detectors=deterministic_detectors(),
                audit_store=store,
            ).evaluate(request)

        self.assertNotIn("john@example.com", json.dumps(store.records))
        self.assertTrue(decision.audit_id)

    def test_deterministic_benchmark_measures_all_cases_and_stages(self):
        report = run_benchmark(runs=3, warmups=1, executor_latency_ms=0)

        self.assertEqual(report.mode, "deterministic")
        self.assertEqual(len(report.cases), 4)
        for case in report.cases:
            with self.subTest(case=case.name):
                self.assertEqual(case.raw["samples"], 3)
                self.assertEqual(case.guarded["samples"], 3)
                self.assertEqual(len(case.actual_decisions), 3)
                self.assertFalse(case.errors)
                self.assertEqual(case.guarded["stages"]["total"]["samples"], 3)
                self.assertEqual(case.guarded["stages"]["request_build"]["samples"], 3)
                self.assertEqual(case.guarded["stages"]["audit_write"]["samples"], 3)
                self.assertEqual(case.guarded["stages"]["router"]["samples"], 3)
                self.assertEqual(case.guarded["stages"]["executor"]["samples"], 3)

    def test_sanitized_cases_reach_the_guarded_executor_with_redacted_content(self):
        report = run_benchmark(runs=1, warmups=0, executor_latency_ms=0)

        sanitized = {
            case.name: case
            for case in report.cases
            if case.expected_decision == "SANITIZE"
        }
        self.assertEqual(set(sanitized), {"sanitized_api_send", "sanitized_browser_type"})
        for case in sanitized.values():
            self.assertEqual(case.actual_decisions, ["SANITIZE"])
            self.assertFalse(case.errors)

    def test_stage_timing_callback_covers_each_production_detector(self):
        timings: dict[str, list[float]] = {}

        def record(stage: str, milliseconds: float) -> None:
            timings.setdefault(stage, []).append(milliseconds)

        with patch("agentgate.decision.build_audit_store", FakeAuditStore), patch(
            "agentgate.detectors.llm_client.chat_json", side_effect=fake_chat_json
        ):
            engine = DecisionEngine(
                detectors=deterministic_detectors(),
                timing_sink=record,
            )
            engine.evaluate(
                ActionRequest(
                    action_type="BROWSER_SNAPSHOT",
                    payload_summary="read a safe local page",
                )
            )

        for name in (
            "pii",
            "secret",
            "source_code",
            "payment_phishing",
            "prompt_injection",
            "action_intent",
        ):
            self.assertEqual(len(timings[f"detector:{name}"]), 1)
        for stage in (
            "policy",
            "risk_scoring",
            "decision_resolution",
            "sanitization",
            "audit_write",
        ):
            self.assertEqual(len(timings[stage]), 1)

    def test_report_is_json_serializable_and_threshold_is_report_only(self):
        report = run_benchmark(runs=1, warmups=0, executor_latency_ms=0)
        encoded = json.dumps(report.to_dict())
        self.assertIn('"thresholds"', encoded)
        self.assertIn("Overhead P95", format_table(report))

    def test_json_output_path_is_writable_by_the_cli_contract(self):
        from benchmarks.raw_vs_guarded import main

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "raw-vs-guarded.json"
            self.assertEqual(
                main(
                    [
                        "--runs",
                        "1",
                        "--warmups",
                        "0",
                        "--executor-latency-ms",
                        "1",
                        "--json-out",
                        str(output),
                    ]
                ),
                0,
            )
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text())["runs"], 1)

    def test_explicitly_empty_case_selection_is_rejected(self):
        with self.assertRaises(BenchmarkError):
            run_benchmark(runs=1, warmups=0, cases=())


class TestBenchmarkMath(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(_percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(_percentile([1, 2, 3, 4], 95), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
