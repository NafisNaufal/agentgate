# AgentGate

**A pre-action guardrail for AI agent tool calls.**

Modern AI agents don't just answer questions — they take real actions: sending
emails, clicking buttons, reading files, calling APIs. AgentGate sits between an
agent deciding to act and the action actually happening: every proposed tool call is
evaluated first, and only safe ones proceed.

```
task → planner proposes a tool call → AgentGate evaluates it → router enforces
       → allow / block / need approval / sanitize / ask user
```

The full lifecycle works end to end: a detector suite, policy engine, risk scoring,
and sanitizer are all implemented and wired into the CLI. Real execution connectors
and persistent audit storage are still ahead — see [Status](#status).

## Setup from scratch

Requires **Python 3.10+**. Pure stdlib, no third-party dependencies — the default
(regex-based) detectors need nothing beyond a clone.

```bash
git clone https://github.com/NafisNaufal/agentgate.git
cd agentgate
```

**Option A — run the setup script** (checks Python, installs [Ollama](https://ollama.com)
if it's missing, pulls the default LLM-detector model, smoke-tests both the regex
and hybrid paths):

```bash
./scripts/setup.sh              # macOS / Linux
./scripts/setup.sh --no-ollama  # skip Ollama entirely if you only want the regex default
```
```powershell
.\scripts\setup.ps1              # Windows (PowerShell)
.\scripts\setup.ps1 -NoOllama    # skip Ollama entirely if you only want the regex default
```

**Option B — do it manually.** For the regex-only default, nothing but the clone is
needed:

```bash
python3 -m agentgate list
python3 -m agentgate tools
python3 -m agentgate run booking_message
python3 -m agentgate eval API_CALL --payload "key AKIAIOSFODNN7EXAMPLE"
python3 -m unittest discover -s tests
```

To also use the LLM-based detector architectures (`hybrid` / `llm_first` /
`unified` — see [Detector architectures](#detector-architectures)), install Ollama
first, then pull a model:

| OS | Install Ollama |
|---|---|
| macOS | `brew install ollama`, or download from [ollama.com/download](https://ollama.com/download) |
| Linux | `curl -fsSL https://ollama.com/install.sh \| sh` |
| Windows | `winget install --id Ollama.Ollama -e`, or download from [ollama.com/download](https://ollama.com/download) |

```bash
ollama serve                # if it isn't already running as a background service
ollama pull qwen2.5:1.5b    # the model this project's bake-off recommends (see below)
```

## How it works

- **`schemas.py`** — the two contracts everything is built around: `ActionRequest`
  (a proposed action, normalized) and `DecisionResponse` (allow/block/approve/
  sanitize/ask, with reasons).
- **`action_space.py`** — a closed vocabulary of action verbs; anything outside it
  is rejected before evaluation.
- **`planner/`** — proposes the next action. A deterministic scenario-replay
  planner (no API key needed) and an optional live LLM planner.
- **`detectors/`** — six detectors (PII, secrets, source code, payment/phishing,
  prompt injection, action-intent) plus three LLM-based architectures for the
  fuzzy detection categories — see [Detector architectures](#detector-architectures).
- **`policy/`** — declarative JSON policy packs per domain, matched against
  detector findings.
- **`risk.py`** — combines detector findings into a risk score and band.
- **`sanitizer.py`** — redacts detected sensitive content for `SANITIZE` decisions.
- **`decision.py`** — ties detectors + policy + risk + sanitizer together into one
  `DecisionResponse`.
- **`router.py`** — enforces the decision so a risky action is never silently
  allowed to proceed.
- **`loop.py`** — the function-calling loop, built from scratch.
- **`tools.py`** — the shape of a tool registry, with illustrative entries; not yet
  consulted by the loop or planner.

## Detector architectures

The regex-based detectors are the zero-dependency default. Three additional
architectures use a local LLM (via [Ollama](https://ollama.com)) for the fuzzy
detection categories where rules alone miss paraphrased attacks:

| Architecture | How it works | Select with |
|---|---|---|
| `regex` (default) | No LLM at all | — |
| `hybrid` | Regex fast-path; LLM only when regex finds nothing | `--architecture hybrid` |
| `llm_first` | Every action goes through the LLM directly | `--architecture llm_first` |
| `unified` | One LLM call classifies across all risk categories at once | `--architecture unified` |

Select an architecture with the `--architecture` flag on `run`/`eval`, or set it
once for the whole shell via `AGENTGATE_DETECTOR_ARCHITECTURE`:

```bash
python -m agentgate eval API_CALL --context "some text" --architecture hybrid
# or:
export AGENTGATE_DETECTOR_ARCHITECTURE=hybrid
python -m agentgate run booking_message
```

To pick which model the LLM architectures call, either pull a different model and
set `AGENTGATE_LLM_DETECTOR_MODEL` (defaults to `gemma3:4b` if unset), or point at
a non-default Ollama host with `OLLAMA_HOST`:

```bash
ollama pull gemma3:4b
export AGENTGATE_LLM_DETECTOR_MODEL=gemma3:4b
```

**Note:** `hybrid` still needs Ollama running — it only *skips* the LLM call when
regex already resolves a case, it isn't LLM-free. If Ollama isn't reachable, every
LLM-backed architecture fails safe (falls back to "no finding" for that detector
rather than crashing), so a misconfigured Ollama setup degrades silently instead of
erroring — worth checking `ollama serve` is actually running if `hybrid`/`llm_first`
results look like plain regex.

### Bake-off results

Measured with `benchmarks/detector_bakeoff.py` against 42 labeled prompt-injection
cases and 31 labeled multi-category action cases.

**Hardware caveat:** run locally on an Apple M4 laptop (arm64, 10 cores, 16GB RAM,
Metal GPU) with Ollama's `num_gpu` forced to `0` to approximate CPU-only inference.
The real deployment target is a 48-core x86 VM, 377GB RAM, **no GPU at all**
(confirmed via `nvidia-smi` / `lspci` on that host). Apple Silicon and generic x86
server cores are not the same hardware — treat the *relative* ranking between
models/architectures below as informative, and the *absolute* millisecond numbers
as approximate only. Re-run this exact script on the real host before finalizing a
production model choice.

**Test 1 — prompt injection (regex vs. hybrid vs. llm_first):**

| architecture | model | f1 | precision | recall | evasion_recall | hardbenign_fp | p50 latency |
|---|---|---|---|---|---|---|---|
| regex | – | 0.625 | 1.0 | 0.455 | 0.0 | 0.0 | 0.0ms |
| hybrid | qwen2.5:1.5b | 0.952 | 1.0 | 0.909 | 0.833 | 0.0 | 387.5ms |
| llm_first | qwen2.5:1.5b | 0.842 | 1.0 | 0.727 | 0.833 | 0.0 | 392.5ms |
| hybrid | gemma3:1b | 0.733 | 0.579 | 1.0 | 1.0 | 0.875 | 556.3ms |
| llm_first | gemma3:1b | 0.733 | 0.579 | 1.0 | 1.0 | 0.875 | 568.1ms |
| hybrid | gemma3:4b | 0.957 | 0.917 | 1.0 | 1.0 | 0.25 | 2055.0ms |
| llm_first | gemma3:4b | 0.957 | 0.917 | 1.0 | 1.0 | 0.25 | 1972.0ms |

**Test 2 — multi-category action classification (regex engine vs. unified):**

| architecture | model | decision accuracy | unsafe auto-allow | p50 latency |
|---|---|---|---|---|
| regex (full engine) | – | 0.968 | 0.0 | 0.2ms |
| unified | qwen2.5:1.5b | 0.742 | 0.143 | 527.1ms |
| unified | gemma3:1b | 0.677 | 0.095 | 1015.0ms |
| unified | gemma3:4b | 0.806 | 0.0 | 3181.6ms |

**Reading it:**
- Regex alone never has a false positive (precision 1.0) but misses over half of
  paraphrased/evasion-style injections (recall 0.455, evasion_recall 0.0) — this is
  exactly the gap the LLM architectures exist to close.
- `hybrid` + `qwen2.5:1.5b` is the standout: regex's fast path already resolves the
  easy cases, so only the ambiguous remainder goes to the LLM — recall jumps to
  0.909 and evasion_recall to 0.833, zero false positives on hard-benign text, at
  ~388ms p50. `llm_first` with the same model does worse (recall 0.727) despite
  paying the same per-call latency, because it never gets the benefit of regex's
  certain matches.
- `gemma3:1b` is not viable at either architecture — it flags 87.5% of hard-benign
  cases as injections (hardbenign_fp 0.875), which would make the guardrail
  unusable in practice.
- `gemma3:4b` gets the best raw accuracy (perfect recall, F1 0.957) but at 5-6x the
  latency of qwen2.5:1.5b — a real trade-off, not a clear win, especially before
  re-measuring on the real (slower per-core, but far more parallel) server hardware.
- `unified` (one LLM call replacing the whole detector layer) underperforms the
  plain regex `DecisionEngine` on every model tested, and two of the three models
  produce a nonzero unsafe-auto-allow rate — the one metric this project's PRD
  treats as a hard target of 0%. This architecture is not recommended as a
  replacement for the regex-based decision engine; LLM detectors are better used to
  augment specific weak spots (like `hybrid` does for prompt injection) than to
  replace the whole layer.

**Working recommendation:** keep `regex` as the zero-dependency default, and use
`hybrid` with a small model (`qwen2.5:1.5b`) as the opt-in upgrade for
prompt-injection coverage. `gemma3:4b` is a fallback if the extra latency is
acceptable for higher recall. Avoid `unified` and avoid `gemma3:1b` in any
architecture. This should be re-validated once the script is run on the actual
deployment VM.

## Project layout

```
agentgate/
  schemas.py         ActionRequest / DecisionResponse contracts
  action_space.py     registered action vocabulary + validator
  detectors/           six regex detectors + three LLM architectures
  policy/               policy engine + JSON packs
  risk.py              risk scoring
  sanitizer.py         redaction for SANITIZE decisions
  decision.py          DecisionEngine: detectors + policy + risk + sanitizer
  router.py            decision enforcement
  loop.py              function-calling loop
  tools.py             tool registry shape (defined, not yet wired in)
  planner/              planner interface, replay planner, optional LLM planner
  cli.py               CLI demo (list / tools / run / eval)
scenarios/            demo scenarios for the replay planner
benchmarks/           detector architecture bake-off + labeled eval data
scripts/              setup.sh / setup.ps1 - one-command environment setup
tests/                unittest suite
```

## Design notes

**Known risks in a custom agent loop, and how each is handled here:**
- *An untrusted planner proposes something unsafe, or doesn't flag its own risk* —
  the planner only proposes; the DecisionEngine judges independently.
- *Malformed or off-vocabulary tool calls* — rejected by `action_space.py` before
  they ever reach evaluation.
- *A run that never terminates* — bounded by `max_steps`, plus explicit `DONE`/
  `FAIL` terminal actions.
- *The planner itself fails* (a live LLM call times out or errors) — caught in
  `loop.py`, turned into a failed run with a clear reason, not an uncaught
  exception.
- *Schema drift as more pieces get added* — the `ActionRequest` /
  `DecisionResponse` contract in `schemas.py` is meant to stay stable.

**Latency budget:** target is P95 ≤ 250ms for rule-based evaluation. Regex-based
evaluation runs in low single-digit milliseconds. LLM-based detector architectures
are opt-in specifically because they cost real latency — see
[Bake-off results](#bake-off-results) above for measured numbers (~388ms p50 for
the recommended hybrid + qwen2.5:1.5b combination, CPU-only on the benchmark
laptop).

**Evaluation metrics (defined, measured once a labeled harness lands):** completion
rate, decision accuracy, unsafe auto-allow rate (target 0%), false-block rate,
approval-routing accuracy, sensitive-data detection recall.

## Status

**Working now:** the full lifecycle (propose → validate → evaluate → enforce) runs
end to end via the CLI. Detectors, policy engine, risk scoring, sanitizer, and
decision engine are implemented and tested. Three LLM-based detector architectures
are built and benchmarked (opt-in, not the default).

**In progress / planned next:**
- Wiring the tool registry into the planner, with a full tool catalog and
  per-tool safety defaults.
- Real execution connectors (Gmail, GitHub, Stripe, browser automation) behind a
  stable executor interface, and an approval queue for `NEED_APPROVAL` decisions —
  both Data Engineering scope, built against the existing decision contract.
- Persistent audit storage.
- A labeled evaluation harness with test data reviewed independently of whoever
  implements the detectors, to keep the accuracy numbers honest.

## Optional: live LLM planner

```bash
export AGENTGATE_LLM_PROVIDER=gemini   # or openai | anthropic | openrouter
export AGENTGATE_LLM_API_KEY=...
```

The LLM only proposes actions — it never decides whether one is safe.
