"""Guarded Gmail API executor using only the Python standard library.

Implements the three Gmail tools in the PRD's Sprint 1 connector baseline:
``gmail_search`` (read-only), ``gmail_archive`` (reversible label change), and
``gmail_send`` (irreversible external send).

Like the GitHub executor, this holds the access token inside the transport and
redacts it from every summary, error, and returned field, because executor output
becomes audit-log content and a planner observation.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from base64 import urlsafe_b64encode
from email.headerregistry import Address
from email.message import EmailMessage
from typing import Any, Callable, Mapping

from ..sanitizer import sanitize
from .base import ExecutionResult
from .google_auth import AuthError, access_token

GMAIL_TOOLS = {"gmail_search", "gmail_archive", "gmail_send"}

API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
_MAX_RESPONSE_BYTES = 2_500_000
_MAX_SEARCH_RESULTS = 100
# Gmail's batchModify accepts up to 1000 ids per call, which is what makes a
# 320-message archive one request instead of 320.
_MAX_BATCH_IDS = 1000


class GmailExecutor:
    """Execute the AgentGate Gmail tool vocabulary through the Gmail REST API."""

    def __init__(
        self,
        timeout: float = 15.0,
        opener: Callable[..., Any] | None = None,
        token_provider: Callable[[], str] | None = None,
    ) -> None:
        self.timeout = timeout
        self._opener = opener or urllib.request.urlopen
        self._token_provider = token_provider or access_token
        self._token = ""

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        tool_name = str(arguments.get("tool_name", ""))
        if action_type != "API_CALL" or tool_name not in GMAIL_TOOLS:
            return self._failure("unsupported_action", "Unsupported Gmail tool")
        try:
            self._token = self._token_provider()
            return getattr(self, f"_{tool_name}")(arguments)
        except AuthError as exc:
            return self._failure("configuration_error", str(exc))
        except _ArgumentsError as exc:
            return self._failure("invalid_arguments", str(exc))
        except urllib.error.HTTPError as exc:
            return self._http_failure(exc)
        except urllib.error.URLError as exc:
            return self._failure("network_error", f"Gmail request failed: {exc.reason}")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError) as exc:
            return self._failure("invalid_response", f"Gmail returned an invalid response: {exc}")
        except OSError as exc:
            return self._failure("network_error", f"Gmail request failed: {exc}")
        except Exception as exc:
            return self._failure("executor_error", f"Gmail executor failed: {exc}")
        finally:
            self._token = ""

    # --- tools -----------------------------------------------------------

    def _gmail_search(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        query = _required_text(arguments, "q")
        max_results = _bounded_int(arguments.get("max_results", 10), 1, _MAX_SEARCH_RESULTS)
        data = self._request(
            "GET", "/messages?" + urllib.parse.urlencode({"q": query, "maxResults": max_results})
        )
        ids = [m.get("id") for m in data.get("messages", []) if isinstance(m, dict)]
        return self._success(
            f"Gmail search matched {len(ids)} message(s)",
            {"message_ids": ids, "result_size_estimate": data.get("resultSizeEstimate")},
        )

    def _gmail_archive(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        ids = _message_ids(arguments)
        # One batch call, not one request per message.
        self._request(
            "POST", "/messages/batchModify", {"ids": ids, "removeLabelIds": ["INBOX"]}
        )
        return self._success(
            f"Archived {len(ids)} message(s) by removing the INBOX label",
            {"archived": len(ids), "message_ids": ids},
        )

    def _gmail_send(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        message = EmailMessage()
        message["To"] = _address_list(arguments, "to", required=True)
        if arguments.get("cc"):
            message["Cc"] = _address_list(arguments, "cc")
        if arguments.get("bcc"):
            message["Bcc"] = _address_list(arguments, "bcc")
        message["Subject"] = _header_value(arguments, "subject")
        message.set_content(_required_text(arguments, "body"))
        raw = urlsafe_b64encode(message.as_bytes()).decode("ascii")
        data = self._request("POST", "/messages/send", {"raw": raw})
        return self._success(
            "Gmail message sent",
            {"id": data.get("id"), "thread_id": data.get("threadId")},
        )

    # --- transport -------------------------------------------------------

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            API_BASE + path,
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "AgentGate/0.3",
            },
        )
        with self._opener(request, timeout=self.timeout) as response:
            raw = _read_limited(response, _MAX_RESPONSE_BYTES)
        data = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def _http_failure(self, exc: urllib.error.HTTPError) -> ExecutionResult:
        message = f"Gmail API returned HTTP {exc.code}"
        try:
            body = json.loads(_read_limited(exc, 64_000).decode("utf-8"))
            detail = body.get("error", {}).get("message") if isinstance(body, dict) else None
            if detail:
                message += f": {detail}"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError):
            pass
        return self._failure("api_error", message)

    def _success(self, summary: str, data: dict[str, Any]) -> ExecutionResult:
        return ExecutionResult(True, "success", self._safe_text(summary), data=self._redact(data))

    def _failure(self, status: str, error: str) -> ExecutionResult:
        return ExecutionResult(
            False, status, "Gmail action was not completed", error=self._safe_text(error)
        )

    def _safe_text(self, text: Any) -> str:
        value = str(text)
        if self._token:
            value = value.replace(self._token, "[REDACTED_GOOGLE_TOKEN]")
        return sanitize(value)[:2_000]

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._safe_text(value)
        if isinstance(value, dict):
            return {self._safe_text(key): self._redact(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact(item) for item in value]
        return value


class _ArgumentsError(ValueError):
    pass


def _required_text(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _ArgumentsError(f"{key} must be a non-empty string")
    return value.strip()


def _header_value(arguments: Mapping[str, Any], key: str) -> str:
    """Reject CR/LF in a header so a payload cannot smuggle extra MIME headers."""
    value = _required_text(arguments, key)
    if "\n" in value or "\r" in value:
        raise _ArgumentsError(f"{key} must not contain line breaks")
    return value


def _address_list(arguments: Mapping[str, Any], key: str, required: bool = False) -> str:
    raw = arguments.get(key)
    if isinstance(raw, str):
        candidates = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, list):
        candidates = [str(part).strip() for part in raw]
    elif required:
        raise _ArgumentsError(f"{key} must be an address or a list of addresses")
    else:
        return ""
    addresses = [c for c in candidates if c]
    if required and not addresses:
        raise _ArgumentsError(f"{key} must contain at least one address")
    for address in addresses:
        if "\n" in address or "\r" in address:
            raise _ArgumentsError(f"{key} must not contain line breaks")
        try:
            local, _, domain = address.rpartition("@")
            Address(username=local, domain=domain)
        except (ValueError, IndexError) as exc:
            raise _ArgumentsError(f"{key} contains an invalid address") from exc
        if not local or not domain:
            raise _ArgumentsError(f"{key} contains an invalid address")
    return ", ".join(addresses)


def _message_ids(arguments: Mapping[str, Any]) -> list[str]:
    raw = arguments.get("message_ids")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        raise _ArgumentsError("message_ids must be a non-empty list of message ids")
    if len(raw) > _MAX_BATCH_IDS:
        raise _ArgumentsError(f"message_ids exceeds the {_MAX_BATCH_IDS}-id batch limit")
    ids: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise _ArgumentsError("message_ids must contain non-empty strings")
        ids.append(item.strip())
    return ids


def _bounded_int(value: Any, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise _ArgumentsError("max_results must be an integer") from exc
    if not low <= number <= high:
        raise _ArgumentsError(f"max_results must be between {low} and {high}")
    return number


def _read_limited(response: Any, limit: int) -> bytes:
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"Gmail response exceeds the {limit}-byte limit")
    return raw
