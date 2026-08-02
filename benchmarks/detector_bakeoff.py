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

Single-category (prompt injection) test, on benchmarks/data/injection_eval.json:
compares regex-only vs Architecture A (hybrid) vs Architecture B (llm-first), each
run across every model in --models.

Usage:
  ollama pull qwen2.5:1.5b gemma3:1b gemma3:4b   # whichever you want to compare
  ollama serve                                    # if not already running
  python3 benchmarks/detector_bakeoff.py --models qwen2.5:1.5b,gemma3:1b,gemma3:4b
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agentgate.detectors import (  # noqa: E402
    HybridPromptInjectionDetector,
    LLMFirstInjectionDetector,
    PromptInjectionDetector,
)
from agentgate.detectors.llm_client import LLMUnavailable  # noqa: E402
from agentgate.schemas import ActionRequest  # noqa: E402

CPU_ONLY = {"num_gpu": 0}  # forces this benchmark's calls off the Mac's GPU


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


_INJECTION_ARCHS = {"hybrid": HybridPromptInjectionDetector, "llm_first": LLMFirstInjectionDetector}


def run_injection_test(cases: list[dict], models: list[str], architectures: list[str] | None = None) -> list[dict]:
    rows = []
    architectures = architectures or list(_INJECTION_ARCHS)

    # Baseline: regex only, no LLM.
    det = PromptInjectionDetector()
    preds = []
    for c in cases:
        t0 = time.perf_counter()
        f = det.scan(ActionRequest(action_type="API_CALL", content_context=c["text"]))
        preds.append((int(f.triggered), (time.perf_counter() - t0) * 1000))
    rows.append({"architecture": "regex", "model": "-", **score_injection(cases, preds)})

    for model in models:
        for arch_name in architectures:
            cls = _INJECTION_ARCHS[arch_name]
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


def render_table(rows: list[dict], cols: list[str]) -> str:
    header = f"{'architecture':<14} {'model':<16} " + " ".join(f"{c:>14}" for c in cols)
    lines = [header, "-" * len(header)]
    for r in rows:
        lines.append(f"{r['architecture']:<14} {r['model']:<16} " + " ".join(f"{r[c]!s:>14}" for c in cols))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen2.5:1.5b,gemma3:1b,gemma3:4b")
    ap.add_argument(
        "--architectures", default="hybrid,llm_first",
        help="comma-separated subset of hybrid,llm_first to run",
    )
    args = ap.parse_args()
    models = [m.strip() for m in args.models.split(",") if m.strip()]
    architectures = [a.strip() for a in args.architectures.split(",") if a.strip()]

    print(__doc__.split("Usage:")[0])
    print(f"Models under test: {models}")
    print(f"Architectures under test: {architectures}\n")

    print("=== Prompt-injection detection (42 cases) — regex vs " + " vs ".join(architectures) + " ===")
    injection_cases = load_cases(ROOT / "benchmarks" / "data" / "injection_eval.json")
    rows = run_injection_test(injection_cases, models, architectures)
    print()
    print(render_table(rows, ["f1", "precision", "recall", "evasion_recall", "hardbenign_fp", "lat_p50_ms"]))

    print("\n\nHardware caveat: forced CPU-only (num_gpu=0) on Apple M4, NOT the real "
          "48-core x86 no-GPU server. Absolute ms are approximate; re-run on the real "
          "host before finalizing a production model choice.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
