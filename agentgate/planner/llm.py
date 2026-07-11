"""LLMPlanner: optional real-LLM planner.

Pluggable client for Gemini / OpenRouter / OpenAI / Anthropic. Uses only the stdlib
(urllib) so there is no extra dependency. Reads provider + key from env:

    AGENTGATE_LLM_PROVIDER = openrouter | openai | gemini | anthropic
    AGENTGATE_LLM_API_KEY  = <key>
    AGENTGATE_LLM_MODEL    = <model id>  (optional)

The LLM is asked to return a single JSON proposal in the AgentGate action space. If no
key is configured, instantiation raises - the demo defaults to ReplayPlanner instead.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from .base import Planner, Proposal

_ENDPOINTS = {
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "openai": "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
}
_DEFAULT_MODELS = {
    "openrouter": "openai/gpt-4o-mini",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-3-5-haiku-latest",
    "gemini": "gemini-2.5-flash",
}

_SYSTEM = (
    "You are the planner inside AgentGate. Given a task and the current observation, "
    "propose exactly ONE next tool call as JSON with keys: action_type (one of "
    "API_CALL, BROWSER_OPEN, BROWSER_SNAPSHOT, BROWSER_CLICK, BROWSER_TYPE, "
    "BROWSER_SELECT, BROWSER_SUBMIT, BROWSER_SCREENSHOT, FILE_READ, ASK_USER, DONE, "
    "FAIL), arguments (object), rationale (string), confidence (0-1), domain, "
    "target_system, risk_hint (array). For API_CALL, arguments MUST include tool_name "
    "(e.g. gmail_archive, github_create_gist) and a payload string. For FILE_READ "
    "include path; for BROWSER_* include the documented args. Respond with JSON only."
)


class LLMPlanner(Planner):
    def __init__(self, provider: str | None = None, api_key: str | None = None, model: str | None = None):
        self.provider = (provider or os.environ.get("AGENTGATE_LLM_PROVIDER", "openrouter")).lower()
        self.api_key = api_key or os.environ.get("AGENTGATE_LLM_API_KEY", "")
        self.model = model or os.environ.get("AGENTGATE_LLM_MODEL", _DEFAULT_MODELS.get(self.provider, ""))
        if self.provider not in _ENDPOINTS:
            raise ValueError(f"Unsupported provider '{self.provider}'")
        if not self.api_key:
            raise RuntimeError(
                "No AGENTGATE_LLM_API_KEY set. Use the default ReplayPlanner, or export a key."
            )

    def propose(self, task: str, observation: dict | None = None) -> Proposal:
        user = f"TASK: {task}\nOBSERVATION: {json.dumps(observation or {})}"
        raw = self._call(user)
        data = _extract_json(raw)
        return Proposal(
            action_type=data.get("action_type", "FAIL"),
            arguments=data.get("arguments", {}),
            rationale=data.get("rationale", ""),
            confidence=float(data.get("confidence", 0.5)),
            domain=data.get("domain", "generic"),
            target_system=data.get("target_system", ""),
            risk_hint=data.get("risk_hint", []),
        )

    # --- transport -------------------------------------------------------
    def _call(self, user: str) -> str:
        if self.provider == "anthropic":
            url = _ENDPOINTS[self.provider]
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            body = {
                "model": self.model,
                "max_tokens": 512,
                "system": _SYSTEM,
                "messages": [{"role": "user", "content": user}],
            }
            resp = self._post(url, headers, body)
            return resp["content"][0]["text"]

        if self.provider == "gemini":
            url = _ENDPOINTS[self.provider].format(model=self.model) + f"?key={self.api_key}"
            body = {
                "system_instruction": {"parts": [{"text": _SYSTEM}]},
                "contents": [{"parts": [{"text": user}]}],
            }
            resp = self._post(url, {"content-type": "application/json"}, body)
            return resp["candidates"][0]["content"]["parts"][0]["text"]

        # openai / openrouter (OpenAI-compatible)
        url = _ENDPOINTS[self.provider]
        headers = {"Authorization": f"Bearer {self.api_key}", "content-type": "application/json"}
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
        }
        resp = self._post(url, headers, body)
        return resp["choices"][0]["message"]["content"]

    @staticmethod
    def _post(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as fh:  # noqa: S310 - trusted endpoints
            return json.loads(fh.read().decode())


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1:
        text = text[start : end + 1]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"action_type": "FAIL", "arguments": {}, "rationale": "Unparseable planner output"}
