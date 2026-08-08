"""Optional Playwright browser executor with compact planner-safe snapshots."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from ..sanitizer import sanitize
from ..schemas import ActionRequest
from .base import ExecutionResult


BROWSER_ACTIONS = {
    "BROWSER_OPEN",
    "BROWSER_SNAPSHOT",
    "BROWSER_CLICK",
    "BROWSER_TYPE",
    "BROWSER_SELECT",
    "BROWSER_SUBMIT",
    "BROWSER_SCREENSHOT",
}
_INTERACTIVE_SELECTOR = (
    "a[href],button,input,textarea,select,[contenteditable='true'],"
    "[role='button'],[role='link'],[role='textbox'],[role='checkbox'],"
    "[role='radio'],[role='combobox'],[role='menuitem']"
)
_MAX_ELEMENTS = 50
_MAX_VISIBLE_TEXT = 4_000

_SNAPSHOT_SCRIPT = f"""
(snapshotPrefix) => {{
  const selector = {repr(_INTERACTIVE_SELECTOR)};
  const visible = (el) => {{
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' &&
      rect.width > 0 && rect.height > 0;
  }};
  const inferRole = (el) => {{
    if (el.getAttribute('role')) return el.getAttribute('role');
    const tag = el.tagName.toLowerCase();
    if (tag === 'a') return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'textarea') return 'textbox';
    if (tag === 'input') {{
      const type = (el.type || 'text').toLowerCase();
      if (type === 'image') return 'submit';
      if (['checkbox', 'radio', 'button', 'submit'].includes(type)) return type;
      return 'textbox';
    }}
    return tag;
  }};
  const all = Array.from(document.querySelectorAll(selector));
  const elements = [];
  for (let index = 0; index < all.length && elements.length < {_MAX_ELEMENTS}; index++) {{
    const el = all[index];
    if (!visible(el)) continue;
    const labels = el.labels ? Array.from(el.labels).map((label) => label.innerText).join(' ') : '';
    const label = el.getAttribute('aria-label') || labels || el.getAttribute('placeholder') || '';
    const text = (el.innerText || el.textContent || '').trim();
    const type = (el.getAttribute('type') || el.tagName.toLowerCase()).toLowerCase();
    const value = 'value' in el ? String(el.value || '') : '';
    const href = el.href || el.getAttribute('href') || '';
    const formAction = el.formAction || el.form?.action || el.getAttribute('action') || '';
    const method = el.formMethod || el.form?.method || el.getAttribute('method') || '';
    const marker = `${{snapshotPrefix}}-${{elements.length}}`;
    el.setAttribute('data-agentgate-id', marker);
    elements.push({{
      marker,
      role: inferRole(el),
      type,
      label: label.slice(0, 160),
      text: text.slice(0, 160),
      value: value.slice(0, 160),
      href: href.slice(0, 500),
      form_action: formAction.slice(0, 500),
      method: method.slice(0, 20),
      disabled: Boolean(el.disabled),
    }});
  }}
  return {{
    visible_text: (document.body?.innerText || '').slice(0, {_MAX_VISIBLE_TEXT * 2}),
    elements,
  }};
}}
"""

_FINGERPRINT_SCRIPT = """
(el) => {
  const labels = el.labels ? Array.from(el.labels).map((label) => label.innerText).join(' ') : '';
  const tag = el.tagName.toLowerCase();
  let role = el.getAttribute('role') || '';
  if (!role && tag === 'a') role = 'link';
  if (!role && tag === 'button') role = 'button';
  if (!role && tag === 'select') role = 'combobox';
  if (!role && tag === 'textarea') role = 'textbox';
  if (!role && tag === 'input') {
    const inputType = (el.type || 'text').toLowerCase();
    role = ['checkbox', 'radio', 'button', 'submit'].includes(inputType) ? inputType : 'textbox';
  }
  return {
    role,
    type: (el.getAttribute('type') || el.tagName.toLowerCase()).toLowerCase(),
    label: (el.getAttribute('aria-label') || labels || el.getAttribute('placeholder') || '').slice(0, 160),
    text: (el.innerText || el.textContent || '').trim().slice(0, 160),
    href: (el.href || el.getAttribute('href') || '').slice(0, 500),
    form_action: (el.formAction || el.form?.action || el.getAttribute('action') || '').slice(0, 500),
    method: (el.formMethod || el.form?.method || el.getAttribute('method') || '').slice(0, 20),
    disabled: Boolean(el.disabled),
  };
}
"""


class PlaywrightExecutor:
    """Maintain one browser/context/page session for guarded browser actions."""

    def __init__(
        self,
        *,
        headless: bool | None = None,
        allowed_origins: str | Iterable[str] | None = None,
        screenshot_dir: str | Path | None = None,
        timeout_ms: int = 15_000,
        page: Any | None = None,
        playwright_factory: Callable[[], Any] | None = None,
        allow_injected_page_for_tests: bool = False,
    ) -> None:
        self.headless = _env_bool("AGENTGATE_BROWSER_HEADLESS", True) if headless is None else headless
        configured_origins = allowed_origins
        if configured_origins is None:
            configured_origins = os.environ.get(
                "AGENTGATE_BROWSER_ALLOWED_ORIGINS",
                "http://localhost:3000,http://127.0.0.1:3000",
            )
        if isinstance(configured_origins, str):
            configured_origins = configured_origins.split(",")
        self.allowed_origins = {
            _configured_origin(origin.strip())
            for origin in configured_origins
            if origin.strip()
        }
        configured_dir = screenshot_dir or os.environ.get(
            "AGENTGATE_SCREENSHOT_DIR", "./artifacts/screenshots"
        )
        self.screenshot_dir = Path(configured_dir).expanduser().resolve()
        self.timeout_ms = timeout_ms
        self._page = page
        self._allow_injected_page_for_tests = allow_injected_page_for_tests
        self._playwright_factory = playwright_factory
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._context: Any | None = None
        self._selector_map: dict[str, Any] = {}
        self._element_metadata: dict[str, dict[str, Any]] = {}

    def enrich_request(
        self,
        request: ActionRequest,
        arguments: Mapping[str, Any],
    ) -> ActionRequest:
        """Attach trusted snapshot context that the planner cannot omit."""
        element_id = str(arguments.get("element_id", ""))
        metadata = self._element_metadata.get(element_id)
        if not metadata:
            return request
        context = "Browser element: " + " | ".join(
            str(metadata.get(key, ""))
            for key in (
                "role",
                "type",
                "label",
                "text",
                "href",
                "form_action",
                "method",
                "page_url",
            )
        )
        risk_hints = list(dict.fromkeys([*request.risk_hint, *metadata.get("risk_hint", [])]))
        return replace(
            request,
            target_system="browser",
            content_context="\n".join(part for part in (request.content_context, context) if part),
            risk_hint=risk_hints,
            rollback_available=(
                False
                if {"destructive_action", "form_submit"} & set(risk_hints)
                else request.rollback_available
            ),
        )

    def execute(self, action_type: str, arguments: Mapping[str, Any]) -> ExecutionResult:
        if action_type not in BROWSER_ACTIONS:
            return self._failure("unsupported_action", "Unsupported browser action")
        try:
            if action_type == "BROWSER_OPEN":
                return self._open(arguments)
            page = self._ensure_page()
            if action_type == "BROWSER_SNAPSHOT":
                return self._snapshot(page)
            if action_type == "BROWSER_CLICK":
                return self._click(page, arguments)
            if action_type == "BROWSER_TYPE":
                return self._type(page, arguments)
            if action_type == "BROWSER_SELECT":
                return self._select(page, arguments)
            if action_type == "BROWSER_SUBMIT":
                return self._submit(page, arguments)
            return self._screenshot(page)
        except _BrowserFailure as exc:
            return self._failure(exc.status, str(exc))
        except Exception as exc:
            return self._exception_failure(exc)

    def _open(self, arguments: Mapping[str, Any]) -> ExecutionResult:
        url = arguments.get("url")
        if not isinstance(url, str) or not url:
            raise _BrowserFailure("invalid_arguments", "BROWSER_OPEN requires a URL")
        self._validate_url(url)
        page = self._ensure_page()
        page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        self._validate_url(str(page.url))
        self._clear_elements()
        return ExecutionResult(
            True,
            "success",
            "Browser page opened",
            data={"url": _safe_text(page.url, 2_000), "title": _safe_text(page.title(), 300)},
        )

    def _snapshot(self, page: Any) -> ExecutionResult:
        self._validate_current_page(page, allow_blank=True)
        snapshot_token = uuid.uuid4().hex
        raw = page.evaluate(_SNAPSHOT_SCRIPT, snapshot_token)
        if not isinstance(raw, dict) or not isinstance(raw.get("elements"), list):
            raise _BrowserFailure("invalid_snapshot", "Browser returned an invalid snapshot")

        self._clear_elements()
        elements: list[dict[str, Any]] = []
        for record in raw["elements"][:_MAX_ELEMENTS]:
            if not isinstance(record, dict) or not isinstance(record.get("marker"), str):
                continue
            element_id = str(len(elements) + 1)
            marker = record["marker"]
            locator = page.locator(f'[data-agentgate-id="{marker}"]')
            handle = locator.element_handle()
            if handle is None:
                continue
            self._selector_map[element_id] = handle
            type_name = _safe_text(record.get("type", ""), 40).lower()
            value = "[REDACTED]" if type_name == "password" else _safe_text(record.get("value", ""), 80)
            context = " ".join(
                str(record.get(key, ""))
                for key in ("role", "type", "label", "text", "href", "form_action", "method")
            )
            risk_hints = _risk_hints(context)
            role = _safe_text(record.get("role", ""), 40)
            if type_name in {"submit", "image"} or (
                role == "button" and bool(record.get("form_action"))
            ):
                risk_hints = list(dict.fromkeys([*risk_hints, "external_send", "form_submit"]))
            metadata = {
                "role": role,
                "type": type_name,
                "label": _safe_text(record.get("label", ""), 160),
                "text": _safe_text(record.get("text", ""), 160),
                "href": _safe_text(record.get("href", ""), 500),
                "form_action": _safe_text(record.get("form_action", ""), 500),
                "method": _safe_text(record.get("method", ""), 20),
                "risk_hint": risk_hints,
                "page_url": str(page.url),
                "fingerprint": {
                    "role": str(record.get("role", "")),
                    "type": str(record.get("type", "")).lower(),
                    "label": str(record.get("label", "")),
                    "text": str(record.get("text", "")),
                    "href": str(record.get("href", "")),
                    "form_action": str(record.get("form_action", "")),
                    "method": str(record.get("method", "")),
                    "disabled": bool(record.get("disabled", False)),
                },
            }
            self._element_metadata[element_id] = metadata
            elements.append(
                {
                    "element_id": element_id,
                    "role": metadata["role"],
                    "type": type_name,
                    "label": metadata["label"],
                    "text": metadata["text"],
                    "value_preview": value,
                    "risk_hint": metadata["risk_hint"],
                }
            )

        visible_text = " ".join(str(raw.get("visible_text", "")).split())
        snapshot = {
            "url": _safe_text(page.url, 2_000),
            "title": _safe_text(page.title(), 300),
            "visible_text": _safe_text(visible_text, _MAX_VISIBLE_TEXT),
            "interactive_elements": elements,
        }
        return ExecutionResult(True, "success", "Browser snapshot captured", data=snapshot)

    def _click(self, page: Any, arguments: Mapping[str, Any]) -> ExecutionResult:
        locator = self._mapped(page, arguments)
        metadata = self._element_metadata.get(str(arguments.get("element_id", "")), {})
        if "form_submit" in metadata.get("risk_hint", []):
            raise _BrowserFailure(
                "submit_requires_guarded_action",
                "Submit-capable controls must use BROWSER_SUBMIT",
            )
        locator.click(timeout=self.timeout_ms)
        self._validate_current_page(page)
        self._clear_elements()
        return ExecutionResult(
            True,
            "success",
            "Browser element clicked",
            data={"url": _safe_text(page.url, 2_000)},
        )

    def _type(self, page: Any, arguments: Mapping[str, Any]) -> ExecutionResult:
        value = arguments.get("value")
        if not isinstance(value, str):
            raise _BrowserFailure("invalid_arguments", "BROWSER_TYPE requires a text value")
        locator = self._mapped(page, arguments)
        locator.fill(value, timeout=self.timeout_ms)
        self._validate_current_page(page)
        return ExecutionResult(True, "success", "Text entered into browser element")

    def _select(self, page: Any, arguments: Mapping[str, Any]) -> ExecutionResult:
        option = arguments.get("option")
        if not isinstance(option, (str, list)):
            raise _BrowserFailure("invalid_arguments", "BROWSER_SELECT requires an option")
        locator = self._mapped(page, arguments)
        locator.select_option(option, timeout=self.timeout_ms)
        self._validate_current_page(page)
        self._clear_elements()
        return ExecutionResult(True, "success", "Browser option selected")

    def _submit(self, page: Any, arguments: Mapping[str, Any]) -> ExecutionResult:
        locator = self._mapped(page, arguments)
        tag_name = str(locator.evaluate("(el) => el.tagName.toLowerCase()"))
        if tag_name == "form":
            locator.evaluate("(el) => el.requestSubmit()")
        else:
            locator.click(timeout=self.timeout_ms)
        self._validate_current_page(page)
        self._clear_elements()
        return ExecutionResult(
            True,
            "success",
            "Browser form submitted",
            data={"url": _safe_text(page.url, 2_000)},
        )

    def _screenshot(self, page: Any) -> ExecutionResult:
        self._validate_current_page(page, allow_blank=True)
        try:
            self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise _BrowserFailure("artifact_error", f"Unable to create screenshot directory: {exc}") from exc
        path = self.screenshot_dir / f"screenshot-{uuid.uuid4().hex}.png"
        page.screenshot(path=str(path), full_page=False, timeout=self.timeout_ms)
        return ExecutionResult(
            True,
            "success",
            "Browser screenshot saved",
            data={"path": str(path), "url": _safe_text(page.url, 2_000)},
        )

    def _mapped(self, page: Any, arguments: Mapping[str, Any]) -> Any:
        self._validate_current_page(page)
        element_id = str(arguments.get("element_id", ""))
        locator = self._selector_map.get(element_id)
        metadata = self._element_metadata.get(element_id)
        if locator is None or metadata is None or str(page.url) != metadata.get("page_url"):
            raise _BrowserFailure(
                "stale_element",
                "Unknown or stale element_id; capture a new browser snapshot",
            )
        try:
            if not locator.is_visible(timeout=self.timeout_ms):
                raise _BrowserFailure("stale_element", "Mapped browser element is no longer visible")
            fingerprint = locator.evaluate(_FINGERPRINT_SCRIPT)
            if fingerprint != metadata["fingerprint"]:
                raise _BrowserFailure("stale_element", "Mapped browser element changed after snapshot")
        except _BrowserFailure:
            raise
        except Exception as exc:
            raise _BrowserFailure("stale_element", "Mapped browser element is no longer available") from exc
        return locator

    def _ensure_page(self) -> Any:
        if self._page is not None:
            if self._playwright is None and not self._allow_injected_page_for_tests:
                raise _BrowserFailure(
                    "injected_page_not_allowed",
                    "Injected browser pages are disabled outside explicit test mode",
                )
            try:
                if not self._page.is_closed():
                    return self._page
            except AttributeError:
                return self._page
            raise _BrowserFailure("browser_closed", "Browser page is closed")

        try:
            factory = self._playwright_factory
            if factory is None:
                from playwright.sync_api import sync_playwright

                factory = sync_playwright
            self._playwright = factory().start()
            self._browser = self._playwright.chromium.launch(headless=self.headless)
            self._context = self._browser.new_context(
                service_workers="block",
                accept_downloads=False,
            )
            self._context.route("**/*", self._route_request)
            self._context.add_init_script(script=_network_guard_script(self.allowed_origins))
            self._page = self._context.new_page()
            self._page.set_default_timeout(self.timeout_ms)
            return self._page
        except ImportError as exc:
            raise _BrowserFailure(
                "dependency_missing",
                'Playwright is not installed; install AgentGate with the "browser" extra',
            ) from exc
        except _BrowserFailure:
            raise
        except Exception as exc:
            message = str(exc).lower()
            if "executable doesn't exist" in message:
                raise _BrowserFailure(
                    "browser_not_installed",
                    "Playwright Chromium is not installed; run: python -m playwright install chromium",
                ) from exc
            raise _BrowserFailure(
                "browser_start_failed",
                f"Unable to start Playwright Chromium: {type(exc).__name__}",
            ) from exc

    def _route_request(self, route: Any, request: Any) -> None:
        parsed = urlsplit(str(request.url))
        if getattr(request, "resource_type", "") in {"worker", "serviceworker"}:
            route.abort("blockedbyclient")
            return
        if parsed.scheme in {"about", "blob", "data"}:
            route.continue_()
            return
        try:
            self._validate_url(str(request.url))
        except _BrowserFailure:
            route.abort("blockedbyclient")
            return
        route.continue_()

    def _validate_current_page(self, page: Any, *, allow_blank: bool = False) -> None:
        url = str(page.url)
        if allow_blank and url == "about:blank":
            return
        self._validate_url(url)

    def _validate_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise _BrowserFailure("url_not_allowed", "Only allowlisted HTTP(S) URLs may be opened")
        if parsed.username or parsed.password:
            raise _BrowserFailure("url_not_allowed", "Credentials in browser URLs are not allowed")
        origin = _normalize_origin(url)
        if origin not in self.allowed_origins:
            raise _BrowserFailure(
                "url_not_allowed",
                f"Browser origin {origin!r} is not in AGENTGATE_BROWSER_ALLOWED_ORIGINS",
            )

    def _exception_failure(self, exc: Exception) -> ExecutionResult:
        message = str(exc)
        lowered = message.lower()
        if "timeout" in lowered:
            status = "navigation_timeout"
        elif "closed" in lowered or "target page" in lowered:
            status = "browser_closed"
        elif "executable doesn't exist" in lowered:
            return self._failure(
                "browser_not_installed",
                "Playwright Chromium is not installed; run: python -m playwright install chromium",
            )
        else:
            status = "browser_error"
        return self._failure(status, f"Browser action failed: {message}")

    @staticmethod
    def _failure(status: str, error: str) -> ExecutionResult:
        return ExecutionResult(False, status, "Browser action was not completed", error=_safe_text(error, 2_000))

    def close(self) -> None:
        """Close owned Playwright resources; injected pages remain caller-owned."""
        for resource in (self._context, self._browser, self._playwright):
            if resource is None:
                continue
            try:
                resource.stop() if resource is self._playwright else resource.close()
            except Exception:
                pass
        self._clear_elements()
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    def _clear_elements(self) -> None:
        self._selector_map.clear()
        self._element_metadata.clear()


class _BrowserFailure(RuntimeError):
    def __init__(self, status: str, message: str) -> None:
        super().__init__(message)
        self.status = status


def _safe_text(value: Any, limit: int) -> str:
    return sanitize(str(value))[:limit]


def _risk_hints(text: str) -> list[str]:
    lowered = text.lower()
    hints: list[str] = []
    if any(word in lowered for word in ("send", "post", "publish", "share", "submit")):
        hints.append("external_send")
    if any(word in lowered for word in ("delete", "remove", "cancel", "purge", "revoke")):
        hints.append("destructive_action")
    if any(word in lowered for word in ("payment", "checkout", "purchase", "pay now")):
        hints.append("payment_related")
    return hints


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _configured_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.path not in {"", "/"}:
        raise ValueError("browser origins must not contain a path")
    return _normalize_origin(value)


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("browser origins must be full HTTP(S) URLs")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("browser origins must not contain credentials, query, or fragment")
    hostname = parsed.hostname.lower().rstrip(".")
    default_port = 80 if parsed.scheme == "http" else 443
    suffix = f":{parsed.port}" if parsed.port and parsed.port != default_port else ""
    return f"{parsed.scheme}://{hostname}{suffix}"


def _network_guard_script(allowed_origins: set[str]) -> str:
    origins = json.dumps(sorted(allowed_origins))
    return f"""
(() => {{
  const allowedOrigins = new Set({origins});
  const allowed = (value) => {{
    try {{
      const url = new URL(value, window.location.href);
      return ['http:', 'https:', 'ws:', 'wss:'].includes(url.protocol) &&
        allowedOrigins.has(url.origin.replace('ws:', 'http:').replace('wss:', 'https:'));
    }} catch (_) {{ return false; }}
  }};
  const NativeWebSocket = window.WebSocket;
  window.WebSocket = class extends NativeWebSocket {{
    constructor(url, protocols) {{
      if (!allowed(url)) throw new DOMException('WebSocket host blocked by AgentGate');
      super(url, ...(protocols === undefined ? [] : [protocols]));
    }}
  }};
  const NativeEventSource = window.EventSource;
  if (NativeEventSource) {{
    window.EventSource = class extends NativeEventSource {{
      constructor(url, options) {{
        if (!allowed(url)) throw new DOMException('EventSource host blocked by AgentGate');
        super(url, options);
      }}
    }};
  }}
  const blockedTransport = class {{
    constructor() {{ throw new DOMException('Direct peer transport blocked by AgentGate'); }}
  }};
  window.WebTransport = blockedTransport;
  window.RTCPeerConnection = blockedTransport;
  window.webkitRTCPeerConnection = blockedTransport;
}})();
"""
