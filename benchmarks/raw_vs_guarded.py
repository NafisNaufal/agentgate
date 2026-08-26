"""Measure direct execution against the complete guarded execution path.

The default mode is deterministic and safe for CI. ``--live`` keeps the benchmark
cases and report shape identical but uses the configured production detectors and audit
store. Both modes use an in-process executor, so the benchmark never performs an
external side effect by accident.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.audit import STAGE_ACTION, build_audit_store
from agentgate.decision import DecisionEngine
from agentgate.detectors import get_default_detectors
from agentgate.detectors.base import Detector, Finding
from agentgate.executors import ExecutionResult, ExecutorRegistry
from agentgate.executors.base import safe_value
from agentgate.planner.base import Proposal
from agentgate.router import DecisionRouter
from agentgate.schemas import ActionRequest, Decision, SensitiveEntity
from agentgate.tools import ToolRegistry


API_OVERHEAD_TARGET_PERCENT = 20.0
DEFAULT_RUNS = 30
DEFAULT_WARMUPS = 1
DEFAULT_EXECUTOR_LATENCY_MS = 5.0


class BenchmarkError(RuntimeError):
    """Raised when the benchmark cannot produce a valid measurement."""


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    kind: str
    proposal: Proposal
    expected_decision: Decision


def default_cases() -> tuple[BenchmarkCase, ...]:
    """Return comparable API and browser cases covering clean and sanitized paths."""
    return (
        BenchmarkCase(
            name="clean_api_read",
            kind="api",
            proposal=Proposal(
                action_type="API_CALL",
                arguments={
                    "tool_name": "github_read_repo",
                    "owner": "octo",
                    "repo": "benchmark",
                },
                domain="code_security",
                target_system="GitHub",
                rationale="Read repository metadata for a permitted inspection",
            ),
            expected_decision=Decision.ALLOW,
        ),
        BenchmarkCase(
            name="sanitized_api_send",
            kind="api",
            proposal=Proposal(
                action_type="API_CALL",
                arguments={
                    "tool_name": "github_create_issue_comment",
                    "owner": "octo",
                    "repo": "benchmark",
                    "issue_number": 1,
                    "body": "Contact john@example.com about the benchmark.",
                },
                domain="code_security",
                target_system="GitHub",
                rationale="Post a permitted benchmark comment",
            ),
            expected_decision=Decision.SANITIZE,
        ),
        BenchmarkCase(
            name="clean_browser_open",
            kind="browser",
            proposal=Proposal(
                action_type="BROWSER_OPEN",
                arguments={"url": "http://localhost:8000"},
                domain="booking_style",
                target_system="browser",
                rationale="Open the local benchmark page",
            ),
            expected_decision=Decision.ALLOW,
        ),
        BenchmarkCase(
            name="sanitized_browser_type",
            kind="browser",
            proposal=Proposal(
                action_type="BROWSER_TYPE",
                arguments={
                    "element_id": "1",
                    "value": "Contact john@example.com about the benchmark.",
                },
                domain="booking_style",
                target_system="browser",
                risk_hint=["external_send"],
                rationale="Type a permitted message into the local benchmark page",
            ),
            expected_decision=Decision.SANITIZE,
        ),
    )


class _DeterministicDetector(Detector):
    """Small deterministic detector set used for repeatable pipeline measurements."""

    def __init__(self, name: str):
        self.name = name

    def scan(self, req: ActionRequest) -> Finding:
        if self.name != "pii":
            return self._finding()
        if not re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", req.scan_text):
            return self._finding()
        return self._finding(
            entities=[SensitiveEntity("EMAIL", "[REDACTED_EMAIL]", self.name, "MEDIUM")],
            reasons=["PII / customer data detected: EMAIL"],
            risk_contribution=0.25,
        )


def deterministic_detectors() -> list[Detector]:
    """Return the six detector stages without requiring Ollama."""
    return [_DeterministicDetector(name) for name in (
        "pii",
        "secret",
        "source_code",
        "payment_phishing",
        "prompt_injection",
        "action_intent",
    )]


class _BenchmarkAuditStore:
    """In-memory audit store for deterministic, offline benchmark runs."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._next_id = 0

    def record(
        self,
        req: ActionRequest,
        decision: Any,
        stage: str = STAGE_ACTION,
    ) -> str:
        self._next_id += 1
        audit_id = f"bench_{self._next_id:06d}"
        decision.audit_id = audit_id
        self.records.append(
            {
                "audit_id": audit_id,
                "stage": stage,
                "request": safe_value(req.to_dict()),
                "response": safe_value(decision.to_dict()),
                "execution_status": "pending",
                "execution_result": None,
            }
        )
        return audit_id

    def update(
        self,
        audit_id: str,
        *,
        execution_status: str | None = None,
        reviewer_status: str | None = None,
        execution_result: dict[str, Any] | None = None,
    ) -> None:
        del reviewer_status
        for record in self.records:
            if record["audit_id"] != audit_id:
                continue
            if execution_status is not None:
                record["execution_status"] = execution_status
            if execution_result is not None:
                record["execution_result"] = execution_result
            return

    def close(self) -> None:
        pass


class _BenchmarkExecutor:
    def __init__(self, latency_ms: float, timing_sink: Callable[[str, float], None]):
        self.latency_ms = latency_ms
        self.timing_sink = timing_sink
        self.last_arguments: dict[str, Any] | None = None
        self.last_duration_ms = 0.0

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        started = time.perf_counter()
        try:
            self.last_arguments = copy.deepcopy(dict(arguments))
            if self.latency_ms:
                time.sleep(self.latency_ms / 1000)
            return ExecutionResult(
                True,
                "success",
                f"Benchmark {action_type} execution completed",
                data={"benchmark": True},
            )
        finally:
            self.last_duration_ms = (time.perf_counter() - started) * 1000
            self.timing_sink("executor", self.last_duration_ms)


class _TimingCollector:
    def __init__(self) -> None:
        self.samples: dict[str, list[float]] = {}

    def record(self, stage: str, milliseconds: float) -> None:
        self.samples.setdefault(stage, []).append(milliseconds)

    def merge(self, other: "_TimingCollector") -> None:
        for stage, values in other.samples.items():
            self.samples.setdefault(stage, []).extend(values)


@dataclass
class _ArmMeasurements:
    timings: _TimingCollector = field(default_factory=_TimingCollector)
    decisions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class CaseReport:
    name: str
    kind: str
    expected_decision: str
    actual_decisions: list[str]
    raw: dict[str, Any]
    guarded: dict[str, Any]
    overhead_p50_percent: float | None
    overhead_p95_percent: float | None
    added_p50_ms: float
    added_p95_ms: float
    slowest_stage: str | None
    threshold_violation: bool
    errors: list[str]

    @property
    def passed(self) -> bool:
        return not self.errors and not self.threshold_violation

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "expected_decision": self.expected_decision,
            "actual_decisions": self.actual_decisions,
            "raw": self.raw,
            "guarded": self.guarded,
            "overhead_p50_percent": self.overhead_p50_percent,
            "overhead_p95_percent": self.overhead_p95_percent,
            "added_p50_ms": self.added_p50_ms,
            "added_p95_ms": self.added_p95_ms,
            "slowest_stage": self.slowest_stage,
            "threshold_violation": self.threshold_violation,
            "errors": self.errors,
            "passed": self.passed,
        }


@dataclass
class BenchmarkReport:
    mode: str
    runs: int
    warmups_discarded: int
    executor_latency_ms: float
    cases: list[CaseReport]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "runs": self.runs,
            "warmups_discarded": self.warmups_discarded,
            "executor_latency_ms": self.executor_latency_ms,
            "thresholds": {"api_overhead_percent": API_OVERHEAD_TARGET_PERCENT},
            "cases": [case.to_dict() for case in self.cases],
        }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise BenchmarkError("Cannot calculate a percentile with no samples")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile / 100 * len(ordered)))
    return round(ordered[rank - 1], 4)


def _stage_report(timings: _TimingCollector) -> dict[str, Any]:
    return {
        stage: {
            "samples": len(values),
            "p50_ms": _percentile(values, 50),
            "p95_ms": _percentile(values, 95),
        }
        for stage, values in sorted(timings.samples.items())
    }


def _arm_report(measurements: _ArmMeasurements) -> dict[str, Any]:
    total = measurements.timings.samples.get("total", [])
    if not total:
        raise BenchmarkError("Arm produced no total timing samples")
    return {
        "samples": len(total),
        "p50_ms": _percentile(total, 50),
        "p95_ms": _percentile(total, 95),
        "stages": _stage_report(measurements.timings),
        "decisions": measurements.decisions,
        "errors": measurements.errors,
    }


def _percentage(guarded: float, raw: float) -> float | None:
    if raw <= 0:
        return None
    return round((guarded - raw) / raw * 100, 4)


def _build_router(executor: _BenchmarkExecutor) -> DecisionRouter:
    registry = ExecutorRegistry()
    for tool_name in ("github_read_repo", "github_create_issue_comment"):
        registry.register_tool(tool_name, executor)
    for action_type in ("BROWSER_OPEN", "BROWSER_TYPE"):
        registry.register_action(action_type, executor)
    return DecisionRouter(registry, execute=True)


def _build_engine(
    live: bool,
    timing_sink: Callable[[str, float], None],
) -> DecisionEngine:
    if live:
        return DecisionEngine(detectors=get_default_detectors(), timing_sink=timing_sink)
    return DecisionEngine(
        detectors=deterministic_detectors(),
        audit_store=_BenchmarkAuditStore(),
        timing_sink=timing_sink,
    )


def _run_raw(
    case: BenchmarkCase,
    executor: _BenchmarkExecutor,
    measurements: _ArmMeasurements,
) -> None:
    started = time.perf_counter()
    try:
        result = executor.execute(case.proposal.action_type, copy.deepcopy(case.proposal.arguments))
        if not result.success:
            measurements.errors.append(f"raw executor failed: {result.status}")
    except Exception as exc:
        measurements.errors.append(f"raw executor failed: {exc}")
    finally:
        measurements.timings.record("total", (time.perf_counter() - started) * 1000)


def _run_guarded(
    case: BenchmarkCase,
    engine: DecisionEngine,
    router: DecisionRouter,
    measurements: _ArmMeasurements,
) -> None:
    collector = _TimingCollector()
    engine.timing_sink = collector.record
    executor = router.executors.resolve(case.proposal.action_type, case.proposal.arguments)
    if not isinstance(executor, _BenchmarkExecutor):
        raise BenchmarkError(f"No benchmark executor for {case.name}")
    started = time.perf_counter()
    try:
        prep_started = time.perf_counter()
        case.proposal.validate()
        request = case.proposal.to_action_request(ToolRegistry())
        collector.record("request_build", (time.perf_counter() - prep_started) * 1000)
        decision = engine.evaluate(request)
        measurements.decisions.append(decision.decision.value)
        route_started = time.perf_counter()
        outcome = router.route(request, decision, copy.deepcopy(case.proposal.arguments))
        route_ms = (time.perf_counter() - route_started) * 1000
        # The router owns dispatch, so subtract the executor sample to keep the
        # stage breakdown additive rather than counting executor time twice.
        collector.record("router", max(0.0, route_ms - executor.last_duration_ms))
        if decision.audit_id:
            audit_started = time.perf_counter()
            engine.audit_store.update(
                decision.audit_id,
                execution_status=outcome.status,
                execution_result=(
                    outcome.execution_result.to_dict()
                    if outcome.execution_result
                    else None
                ),
            )
            collector.record("audit_update", (time.perf_counter() - audit_started) * 1000)
        if outcome.status != "executed":
            measurements.errors.append(
                f"guarded {case.name} ended with status {outcome.status!r}"
            )
        if (
            case.expected_decision == Decision.SANITIZE
            and isinstance(executor.last_arguments, dict)
            and "john@example.com" in json.dumps(executor.last_arguments)
        ):
            measurements.errors.append("sanitized action sent the original email address")
    except Exception as exc:
        measurements.errors.append(f"guarded execution failed: {exc}")
    finally:
        collector.record("total", (time.perf_counter() - started) * 1000)
        measurements.timings.merge(collector)


def _case_report(
    case: BenchmarkCase,
    raw: _ArmMeasurements,
    guarded: _ArmMeasurements,
) -> CaseReport:
    raw_report = _arm_report(raw)
    guarded_report = _arm_report(guarded)
    raw_p50 = raw_report["p50_ms"]
    raw_p95 = raw_report["p95_ms"]
    guarded_p50 = guarded_report["p50_ms"]
    guarded_p95 = guarded_report["p95_ms"]
    guarded_stages = guarded_report["stages"]
    stage_candidates = [stage for stage in guarded_stages if stage != "total"]
    slowest_stage = (
        max(stage_candidates, key=lambda stage: guarded_stages[stage]["p95_ms"])
        if stage_candidates
        else None
    )
    errors = [*raw.errors, *guarded.errors]
    errors.extend(
        f"guarded decision was {decision}, expected {case.expected_decision.value}"
        for decision in guarded.decisions
        if decision != case.expected_decision.value
    )
    overhead_p50 = _percentage(guarded_p50, raw_p50)
    overhead_p95 = _percentage(guarded_p95, raw_p95)
    threshold_violation = (
        case.kind == "api"
        and overhead_p95 is not None
        and overhead_p95 > API_OVERHEAD_TARGET_PERCENT
    )
    return CaseReport(
        name=case.name,
        kind=case.kind,
        expected_decision=case.expected_decision.value,
        actual_decisions=guarded.decisions,
        raw=raw_report,
        guarded=guarded_report,
        overhead_p50_percent=overhead_p50,
        overhead_p95_percent=overhead_p95,
        added_p50_ms=round(guarded_p50 - raw_p50, 4),
        added_p95_ms=round(guarded_p95 - raw_p95, 4),
        slowest_stage=slowest_stage,
        threshold_violation=threshold_violation,
        errors=errors,
    )


def run_benchmark(
    *,
    runs: int = DEFAULT_RUNS,
    warmups: int = DEFAULT_WARMUPS,
    live: bool = False,
    executor_latency_ms: float = DEFAULT_EXECUTOR_LATENCY_MS,
    cases: tuple[BenchmarkCase, ...] | None = None,
) -> BenchmarkReport:
    if runs < 1:
        raise BenchmarkError("runs must be at least 1")
    if warmups < 0:
        raise BenchmarkError("warmups cannot be negative")
    if executor_latency_ms < 0:
        raise BenchmarkError("executor latency cannot be negative")
    selected_cases = default_cases() if cases is None else cases
    if not selected_cases:
        raise BenchmarkError("at least one benchmark case is required")

    engine = _build_engine(live, lambda _stage, _milliseconds: None)
    audit_store = engine.audit_store
    reports: list[CaseReport] = []
    try:
        for case in selected_cases:
            raw_measurements = _ArmMeasurements()
            guarded_measurements = _ArmMeasurements()
            raw_executor = _BenchmarkExecutor(
                executor_latency_ms,
                raw_measurements.timings.record,
            )
            guarded_executor = _BenchmarkExecutor(
                executor_latency_ms,
                guarded_measurements.timings.record,
            )
            guarded_router = _build_router(guarded_executor)
            for iteration in range(warmups + runs):
                raw = _ArmMeasurements()
                guarded = _ArmMeasurements()
                raw_executor.timing_sink = raw.timings.record
                guarded_executor.timing_sink = guarded.timings.record
                if iteration % 2 == 0:
                    _run_raw(case, raw_executor, raw)
                    _run_guarded(case, engine, guarded_router, guarded)
                else:
                    _run_guarded(case, engine, guarded_router, guarded)
                    _run_raw(case, raw_executor, raw)
                if iteration >= warmups:
                    raw_measurements.timings.merge(raw.timings)
                    raw_measurements.decisions.extend(raw.decisions)
                    raw_measurements.errors.extend(raw.errors)
                    guarded_measurements.timings.merge(guarded.timings)
                    guarded_measurements.decisions.extend(guarded.decisions)
                    guarded_measurements.errors.extend(guarded.errors)
            reports.append(_case_report(case, raw_measurements, guarded_measurements))
    finally:
        close = getattr(audit_store, "close", None)
        if callable(close):
            close()
    return BenchmarkReport(
        mode="live" if live else "deterministic",
        runs=runs,
        warmups_discarded=warmups,
        executor_latency_ms=executor_latency_ms,
        cases=reports,
    )


def format_table(report: BenchmarkReport) -> str:
    lines = [
        f"Mode: {report.mode} | runs: {report.runs} | warmups discarded: {report.warmups_discarded}",
        "",
        "Case                  Raw P50   Raw P95   Guarded P50   Guarded P95   Added P95   Overhead P95   Slowest stage",
        "-" * 119,
    ]
    for case in report.cases:
        overhead = (
            f"{case.overhead_p95_percent:.2f}%"
            if case.overhead_p95_percent is not None
            else "n/a"
        )
        lines.append(
            f"{case.name:<21} {case.raw['p50_ms']:>8.2f} {case.raw['p95_ms']:>9.2f} "
            f"{case.guarded['p50_ms']:>12.2f} {case.guarded['p95_ms']:>13.2f} "
            f"{case.added_p95_ms:>11.2f} {overhead:>14} {case.slowest_stage or 'n/a'}"
        )
        if case.errors:
            lines.append(f"  errors: {'; '.join(case.errors)}")
        if case.threshold_violation:
            lines.append(f"  threshold: API overhead exceeds {API_OVERHEAD_TARGET_PERCENT:.0f}%")
    return "\n".join(lines)


def _select_cases(filters: list[str] | None) -> tuple[BenchmarkCase, ...]:
    cases = default_cases()
    if not filters:
        return cases
    selected = tuple(case for case in cases if any(value in case.name for value in filters))
    if not selected:
        raise BenchmarkError(f"No benchmark case matches {filters}")
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare raw and guarded AgentGate execution")
    parser.add_argument("--live", action="store_true", help="use real detectors and the configured audit store")
    parser.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    parser.add_argument("--warmups", type=int, default=DEFAULT_WARMUPS)
    parser.add_argument("--executor-latency-ms", type=float, default=DEFAULT_EXECUTOR_LATENCY_MS)
    parser.add_argument("--case", action="append", help="case-name substring; repeatable")
    parser.add_argument("--json", action="store_true", help="print JSON instead of the table")
    parser.add_argument("--json-out", type=Path, help="also write the JSON report to this path")
    args = parser.parse_args(argv)
    try:
        report = run_benchmark(
            runs=args.runs,
            warmups=args.warmups,
            live=args.live,
            executor_latency_ms=args.executor_latency_ms,
            cases=_select_cases(args.case),
        )
    except Exception as exc:
        print(f"Benchmark failed: {exc}")
        return 1

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report.to_dict(), indent=2) if args.json else format_table(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
