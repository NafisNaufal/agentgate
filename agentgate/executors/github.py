"""Guarded GitHub REST API executor using only the Python standard library."""

from __future__ import annotations

import base64
import binascii
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

from ..sanitizer import sanitize
from .base import ExecutionResult


_GITHUB_TOOLS = {
    "github_read_repo",
    "github_read_file",
    "github_create_issue",
    "github_create_issue_comment",
    "github_create_gist",
}
_MAX_RESPONSE_BYTES = 2_500_000
_MAX_FILE_BYTES = 1_048_576


class GitHubExecutor:
    """Execute the AgentGate GitHub tool vocabulary through GitHub's REST API."""

    def __init__(
        self,
        token: str | None = None,
        api_url: str | None = None,
        timeout: float = 15.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self._token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")
        self.api_url = (api_url or os.environ.get("GITHUB_API_URL", "https://api.github.com")).rstrip("/")
        self.timeout = timeout
        self._configuration_error = _validate_api_url(self.api_url)
        self._api_origin = _origin(self.api_url) if self._configuration_error is None else ("", "", None)
        self._opener = opener or urllib.request.build_opener(
            _SameOriginRedirectHandler(self._api_origin)
        ).open

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        tool_name = str(arguments.get("tool_name", ""))
        if action_type != "API_CALL" or tool_name not in _GITHUB_TOOLS:
            return self._failure("unsupported_action", "Unsupported GitHub tool")
        if self._configuration_error:
            return self._failure("configuration_error", self._configuration_error)
        if not self._token:
            return self._failure("configuration_error", "GITHUB_TOKEN is not configured")

        try:
            handler = getattr(self, f"_{tool_name}")
            return handler(arguments)
        except _ArgumentsError as exc:
            return self._failure("invalid_arguments", str(exc))
        except urllib.error.HTTPError as exc:
            return self._http_failure(exc)
        except urllib.error.URLError as exc:
            return self._failure("network_error", f"GitHub request failed: {exc.reason}")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError) as exc:
            return self._failure("invalid_response", f"GitHub returned an invalid response: {exc}")
        except OSError as exc:
            return self._failure("network_error", f"GitHub request failed: {exc}")
        except Exception as exc:
            return self._failure("executor_error", f"GitHub executor failed: {exc}")

    def _github_read_repo(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        owner, repo = self._repo(arguments)
        data = self._request("GET", f"/repos/{_segment(owner)}/{_segment(repo)}")
        safe = _select(
            data,
            "id",
            "name",
            "full_name",
            "private",
            "html_url",
            "description",
            "default_branch",
            "archived",
            "disabled",
            "visibility",
            "permissions",
        )
        if isinstance(data.get("owner"), dict):
            safe["owner"] = _select(data["owner"], "login", "id", "type")
        return self._success("Repository metadata retrieved", safe)

    def _github_read_file(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        owner, repo = self._repo(arguments)
        path = _required_text(arguments, "path").lstrip("/")
        if not path:
            raise _ArgumentsError("path must not be empty")
        query = ""
        ref = arguments.get("ref")
        if ref is not None and str(ref):
            query = "?" + urllib.parse.urlencode({"ref": str(ref)})
        encoded_path = urllib.parse.quote(path, safe="/")
        data = self._request(
            "GET",
            f"/repos/{_segment(owner)}/{_segment(repo)}/contents/{encoded_path}{query}",
        )
        if not isinstance(data, dict) or data.get("type") != "file":
            raise ValueError("requested repository path is not a file")
        if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
            raise ValueError("repository file did not contain base64 content")
        try:
            raw = base64.b64decode("".join(data["content"].split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("repository file contained invalid base64") from exc
        if len(raw) > _MAX_FILE_BYTES:
            raise ValueError(f"repository file exceeds the {_MAX_FILE_BYTES}-byte limit")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("repository file is not valid UTF-8 text") from exc
        safe = _select(data, "name", "path", "sha", "size", "html_url", "download_url")
        safe["encoding"] = "utf-8"
        safe["content"] = content
        return self._success("Repository file retrieved", safe)

    def _github_create_issue(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        owner, repo = self._repo(arguments)
        body = arguments.get("body", "")
        if not isinstance(body, str):
            raise _ArgumentsError("body must be text")
        payload = {
            "title": _required_text(arguments, "title"),
            "body": body,
        }
        data = self._request("POST", f"/repos/{_segment(owner)}/{_segment(repo)}/issues", payload)
        return self._success("GitHub issue created", _select(data, "id", "number", "title", "state", "html_url"))

    def _github_create_issue_comment(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        owner, repo = self._repo(arguments)
        issue_number = arguments.get("issue_number")
        if type(issue_number) is not int or issue_number <= 0:
            raise _ArgumentsError("issue_number must be a positive integer")
        payload = {"body": _required_text(arguments, "body")}
        data = self._request(
            "POST",
            f"/repos/{_segment(owner)}/{_segment(repo)}/issues/{issue_number}/comments",
            payload,
        )
        return self._success("GitHub issue comment created", _select(data, "id", "html_url", "created_at", "updated_at"))

    def _github_create_gist(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        raw_files = arguments.get("files")
        if not isinstance(raw_files, dict) or not raw_files:
            raise _ArgumentsError("files must be a non-empty mapping")
        files: dict[str, dict[str, str]] = {}
        for name, value in raw_files.items():
            if not isinstance(name, str) or not name:
                raise _ArgumentsError("gist filenames must be non-empty strings")
            content = value.get("content") if isinstance(value, dict) else value
            if not isinstance(content, str):
                raise _ArgumentsError("each gist file must contain text content")
            files[name] = {"content": content}
        description = arguments.get("description", "")
        public = arguments.get("public", False)
        if not isinstance(description, str):
            raise _ArgumentsError("description must be text")
        if not isinstance(public, bool):
            raise _ArgumentsError("public must be true or false")
        payload = {
            "description": description,
            "public": public,
            "files": files,
        }
        data = self._request("POST", "/gists", payload)
        return self._success("GitHub gist created", _select(data, "id", "html_url", "public", "description", "created_at"))

    def _repo(self, arguments: Mapping[str, Any]) -> tuple[str, str]:
        return _required_text(arguments, "owner"), _required_text(arguments, "repo")

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            self.api_url + path,
            data=body,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "User-Agent": "AgentGate/0.2",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with self._opener(request, timeout=self.timeout) as response:
            final_url = response.geturl() if hasattr(response, "geturl") else request.full_url
            if _origin(final_url) != self._api_origin:
                raise ValueError("GitHub response redirected to a different origin")
            raw = _read_limited(response, _MAX_RESPONSE_BYTES)
        data = json.loads(raw.decode("utf-8")) if raw else {}
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return self._redact(data)

    def _http_failure(self, exc: urllib.error.HTTPError) -> ExecutionResult:
        message = f"GitHub API returned HTTP {exc.code}"
        try:
            body = json.loads(_read_limited(exc, 64_000).decode("utf-8"))
            if isinstance(body, dict) and body.get("message"):
                message += f": {body['message']}"
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            pass
        return self._failure("api_error", message)

    def _success(self, summary: str, data: dict[str, Any]) -> ExecutionResult:
        return ExecutionResult(True, "success", summary, data=self._redact(data))

    def _failure(self, status: str, error: str) -> ExecutionResult:
        return ExecutionResult(False, status, "GitHub action was not completed", error=self._safe_text(error))

    def _safe_text(self, text: Any) -> str:
        value = str(text)
        if self._token:
            value = value.replace(self._token, "[REDACTED_GITHUB_TOKEN]")
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


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int | None]) -> None:
        self.allowed_origin = allowed_origin

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if _origin(newurl) != self.allowed_origin:
            raise urllib.error.HTTPError(
                req.full_url,
                code,
                "Cross-origin GitHub redirect blocked",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _required_text(arguments: Mapping[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _ArgumentsError(f"{key} must be a non-empty string")
    return value.strip()


def _segment(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _select(data: Mapping[str, Any], *keys: str) -> dict[str, Any]:
    return {key: data[key] for key in keys if key in data}


def _validate_api_url(url: str) -> str | None:
    try:
        parsed = urllib.parse.urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError:
        return "GITHUB_API_URL is not a valid URL"
    if not hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return "GITHUB_API_URL must be an HTTP(S) API base without credentials, query, or fragment"
    loopback = hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        return "GITHUB_API_URL must use HTTPS (HTTP is allowed only for loopback testing)"
    return None


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


def _read_limited(response: Any, limit: int) -> bytes:
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"GitHub response exceeds the {limit}-byte limit")
    return raw
