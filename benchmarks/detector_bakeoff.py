"""Sprint 1 detector architecture bake-off, per the PM's ask: benchmark different
LLMs (and architectures) before picking one.

Hardware note (read this before trusting the numbers): these benchmarks were run
locally on a laptop (Apple M4, arm64, 10 cores, 16GB RAM, with a Metal-capable GPU),
with Ollama's num_gpu forced to 0 to approximate CPU-only inference. The real
deployment target is a VM with a 48-core CPU, 377GB RAM, and NO GPU at all (confirmed
via `nvidia-smi`/`lspci` on that host). Apple Silicon ARM cores and generic x86
server cores are NOT the same hardware - clock speed, memory bandwidth, and
instruction set all differ. Treat the RELATIVE ranking between models/architectures
here as informative; treat the ABSOLUTE millisecond numbers as approximate, and
re-run this exact script on the real host before finalizing a production choice.

Two test beds, matching what each architecture is actually for:

  Test 1 - single-category (prompt injection), on benchmarks/data/injection_eval.json:
    compares regex-only vs Architecture A (hybrid) vs Architecture B (llm-first),
    each of B and A run across every model in --models.

  Test 2 - multi-category (whole-action classification), on
    benchmarks/data/coverage_eval.json: compares the regex-based DecisionEngine vs
    Architecture C (unified), across every model in --models.

Usage:
  ollama pull qwen2.5:1.5b gemma3:1b gemma3:4b   # whichever you want to compare
  ollama serve                                    # if not already running
  python3 benchmarks/detector_bakeoff.py --models qwen2.5:1.5b,gemma3:1b,gemma3:4b
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.decision import DecisionEngine  # noqa: E402
from agentgate.detectors import (  # noqa: E402
    HybridPromptInjectionDetector,
    LLMFirstInjectionDetector,
    PromptInjectionDetector,
    get_default_detectors,
)
from agentgate.detectors.llm_client import LLMUnavailable  # noqa: E402
from agentgate.schemas import ActionRequest, Decision  # noqa: E402

CPU_ONLY = {"num_gpu": 0}  # forces this benchmark's calls off the Mac's GPU


# --------------------------------------------------------------------- Test 1: injection
def load_cases(path: Path) -> list[dict]:
    return json.loads(path.read_text())["cases"]


def score_injection(cases: list[dict], preds: list[tuple[int, float]]) -> dict:
    tp = fp = fn = tn = 0
    evasion_total = evasion_hit = 0
    hardben_total = hardben_fp = 0
    for c, (pred, ms) in zip(cases, preds):
        y = c["label"]
        if y == 1 and pred == 1:
            tp += 1
        elif y == 1 and pred == 0:
            fn += 1
        elif y == 0 and pred == 1:
            fp += 1
        else:
            tn += 1
        if c.get("subset") == "evasion":
            evasion_total += 1
            evasion_hit += int(pred == 1)
        if c.get("subset") == "benign_hard":
            hardben_total += 1
            hardben_fp += int(pred == 1)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    lat = sorted(ms for _p, ms in preds)
    return {
        "f1": round(f1, 3), "precision": round(prec, 3), "recall": round(rec, 3),
        "evasion_recall": round(evasion_hit / evasion_total, 3) if evasion_total else 0.0,
        "hardbenign_fp": round(hardben_fp / hardben_total, 3) if hardben_total else 0.0,
        "lat_p50_ms": round(lat[len(lat) // 2], 1) if lat else 0.0,
    }


def run_injection_test(cases: list[dict], models: list[str]) -> list[dict]:
    rows = []

    # Baseline: regex only, no LLM.
    det = PromptInjectionDetector()
    preds = []
    for c in cases:
        t0 = time.perf_counter()
        f = det.scan(ActionRequest(action_type="API_CALL", content_context=c["text"]))
        preds.append((int(f.triggered), (time.perf_counter() - t0) * 1000))
    rows.append({"architecture": "regex", "model": "-", **score_injection(cases, preds)})

    for model in models:
        for arch_name, cls in (("hybrid", HybridPromptInjectionDetector), ("llm_first", LLMFirstInjectionDetector)):
            det = cls(model=model, extra_options=CPU_ONLY, timeout=90.0)
            preds = []
            failed = False
            for c in cases:
                t0 = time.perf_counter()
                try:
                    f = det.scan(ActionRequest(action_type="API_CALL", content_context=c["text"]))
                except LLMUnavailable as exc:
                    print(f"  ! {arch_name}/{model} failed: {exc}", file=sys.stderr)
                    failed = True
                    break
                preds.append((int(f.triggered), (time.perf_counter() - t0) * 1000))
            if failed:
                continue
            rows.append({"architecture": arch_name, "model": model, **score_injection(cases, preds)})
            print(f"  done: {arch_name}/{model}")
    return rows


# ------------------------------------------------------------------ Test 2: multi-category
def to_request(case: dict) -> ActionRequest:
    payload = case.get("payload", "")
    return ActionRequest(
        action_type=case["action_type"], domain=case.get("domain", "generic"),
        target_system=case.get("target_system", ""), tool_name=case.get("tool_name", ""),
        target=case.get("target", ""), payload_summary=payload, raw_payload=payload,
        content_context=case.get("context", ""), risk_hint=case.get("risk_hint", []),
        rollback_available=case.get("rollback_available", True), confidence=case.get("confidence", 1.0),
    )


def score_coverage(cases: list[dict], results: list[tuple[str, float]]) -> dict:
    correct = 0
    unsafe_total = unsafe_missed = 0
    for c, (decision, _ms) in zip(cases, results):
        exp = c["expected_decision"]
        if decision == exp:
            correct += 1
        if c.get("label") == "unsafe":
            unsafe_total += 1
            if decision == "ALLOW":
                unsafe_missed += 1
    lat = sorted(ms for _d, ms in results)
    return {
        "decision_accuracy": round(correct / len(cases), 3),
        "unsafe_auto_allow": round(unsafe_missed / unsafe_total, 3) if unsafe_total else 0.0,
        "lat_p50_ms": round(lat[len(lat) // 2], 1) if lat else 0.0,
    }


def run_coverage_test(cases: list[dict], models: list[str]) -> list[dict]:
    rows = []

    engine = DecisionEngine(detectors=get_default_detectors("regex"))
    results = []
    for c in cases:
        t0 = time.perf_counter()
        d = engine.evaluate(to_request(c))
        results.append((d.decision.value, (time.perf_counter() - t0) * 1000))
    rows.append({"architecture": "regex (full engine)", "model": "-", **score_coverage(cases, results)})

    for model in models:
        detectors = get_default_detectors("unified")
        for det in detectors:
            if hasattr(det, "extra_options"):
                det.extra_options = CPU_ONLY
                det.model = model
                det.timeout = 90.0
        engine = DecisionEngine(detectors=detectors)
        results = []
        failed = False
        for c in cases:
            t0 = time.perf_counter()
            try:
                d = engine.evaluate(to_request(c))
            except LLMUnavailable as exc:
                print(f"  ! unified/{model} failed: {exc}", file=sys.stderr)
                failed = True
                break
            results.append((d.decision.value, (time.perf_counter() - t0) * 1000))
        if failed:
            continue
        rows.append({"architecture": "unified", "model": model, **score_coverage(cases, results)})
        print(f"  done: unified/{model}")
    return rows


def render_table(rows: list[dict], cols: list[str]) -> str:
    header = f"{'architecture':<14} {'model':<16} " + " ".join(f"{c:>14}" for c in cols)
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(f"{r['architecture']:<14} {r['model']:<16} " + " ".join(f"{r[c]!s:>14}" for c in cols))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen2.5:1.5b,gemma3:1b,gemma3:4b")
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    print(__doc__.split("Usage:")[0])
    print(f"Models under test: {models}\n")

    print("=== Test 1: prompt-injection detection (42 cases) — regex vs hybrid vs llm_first ===")
    injection_cases = load_cases(ROOT / "benchmarks" / "data" / "injection_eval.json")
    rows1 = run_injection_test(injection_cases, models)
    print()
    print(render_table(rows1, ["f1", "precision", "recall", "evasion_recall", "hardbenign_fp", "lat_p50_ms"]))

    print("\n\n=== Test 2: multi-category action classification (31 cases) — regex vs unified ===")
    coverage_cases = load_cases(ROOT / "benchmarks" / "data" / "coverage_eval.json")
    rows2 = run_coverage_test(coverage_cases, models)
    print()
    print(render_table(rows2, ["decision_accuracy", "unsafe_auto_allow", "lat_p50_ms"]))

    print("\n\nHardware caveat: forced CPU-only (num_gpu=0) on Apple M4, NOT the real "
          "48-core x86 no-GPU server. Absolute ms are approximate; re-run on the real "
          "host before finalizing a production model choice.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
