"""Shared local-LLM client for the detector architectures in this package.

Talks to a local Ollama server (``ollama serve``) over its HTTP API. Used by all
three LLM-based detector architectures (hybrid, llm-first, unified) so the request/
retry/fail-safe logic lives in exactly one place.

Fails safe by design: callers get a `LLMUnavailable` exception on any network/parse
problem and are expected to degrade to a non-LLM fallback rather than crash
evaluation. A guardrail must not become a single point of failure.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class LLMUnavailable(RuntimeError):
    """Raised when the local LLM can't be reached or returns something unusable."""


def chat_json(
    system_prompt: str,
    user_content: str,
    *,
    model: str | None = None,
    host: str | None = None,
    timeout: float = 30.0,
    extra_options: dict | None = None,
) -> dict:
    """Call the local Ollama chat API, asking for a JSON object back.

    Returns the parsed JSON dict. Raises LLMUnavailable on any failure (network,
    timeout, unparseable response) so callers can fail safe.

    extra_options merges into Ollama's per-request ``options`` (e.g. pass
    ``{"num_gpu": 0}`` to force CPU-only inference for that call - used by the
    detector benchmark to get honest no-GPU numbers; production code leaves this
    unset so it uses GPU acceleration when available).
    """
    model = model or os.environ.get("AGENTGATE_LLM_DETECTOR_MODEL", "gemma3:4b")
    host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    options = {"temperature": 0}
    if extra_options:
        options.update(extra_options)

    body = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": options,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    }
    req = urllib.request.Request(
        host + "/api/chat",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as fh:
            raw = json.loads(fh.read().decode())["message"]["content"]
    except (urllib.error.URLError, OSError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
        raise LLMUnavailable(str(exc)) from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"model returned unparseable JSON: {raw[:200]!r}") from exc
