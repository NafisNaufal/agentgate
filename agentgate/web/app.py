"""AgentGate Demo Console: a stdlib HTTP server over the same DecisionEngine the CLI uses.

Everything except /login and the OAuth callback requires a session. State-changing
endpoints additionally require a CSRF token header, which a cross-origin page cannot
set without a preflight the server never approves.

No third-party dependencies: http.server plus one embedded page.
"""

from __future__ import annotations

import json
import os
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..audit import STAGE_ACTION, AuditUnavailable, build_audit_store
from ..decision import DecisionEngine
from ..detectors.llm_client import resolve_model
from ..executors.google_auth import AuthError
from ..loop import AgentLoop
from ..planner import ReplayPlanner, get_planner
from ..router import DecisionRouter
from ..tools import ToolRegistry
from .auth import CSRF_HEADER, SESSION_COOKIE, SessionStore, check_password, load_password
from .jobs import JobManager
from .oauth import CALLBACK_PATH, GmailConnection, origin_is_oauth_capable
from .ui import PAGE

_MAX_BODY_BYTES = 64_000
_SCENARIO_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


class Console:
    """Shared application state. One instance per server."""

    def __init__(self) -> None:
        self.password = load_password()
        self.sessions = SessionStore()
        self.jobs = JobManager()
        self.gmail = GmailConnection()
        self.tools = ToolRegistry()
        # Fails loudly here if the audit store is unreachable, exactly as the CLI does.
        self.engine = DecisionEngine()

    # --- data ------------------------------------------------------------

    def scenarios(self) -> list[dict[str, Any]]:
        from importlib.resources import files

        out = []
        for path in sorted(files("agentgate").joinpath("scenarios").iterdir(), key=lambda p: p.name):
            if not path.name.endswith(".json"):
                continue
            data = json.loads(path.read_text())
            if "steps" not in data:
                continue
            out.append(
                {
                    "name": data["name"],
                    "title": data.get("title", ""),
                    "expected": data.get("expected", ""),
                    "description": data.get("description", ""),
                    "steps": len(data["steps"]),
                }
            )
        return out

    def load_scenario(self, name: str) -> dict[str, Any]:
        from importlib.resources import files

        if not _SCENARIO_NAME.match(name):
            raise ValueError("Unknown scenario")
        path = files("agentgate").joinpath("scenarios").joinpath(f"{name}.json")
        if not path.is_file():
            raise ValueError("Unknown scenario")
        return json.loads(path.read_text())

    def planner_available(self) -> bool:
        return bool(os.environ.get("AGENTGATE_LLM_API_KEY", "").strip())

    def status(self, origin: str) -> dict[str, Any]:
        try:
            model = resolve_model()
        except Exception as exc:
            model = f"unavailable: {exc}"
        return {
            "detector_model": model,
            "ollama_host": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            "audit": self.audit_summary(),
            "gmail": self.gmail.status(),
            "oauth_capable_origin": origin_is_oauth_capable(origin),
            "origin": origin,
            "planner_available": self.planner_available(),
            "tools": self.tools.names(),
            "busy": self.jobs.busy(),
        }

    def audit_summary(self) -> dict[str, Any]:
        try:
            rows = self.engine.audit_store._query(  # noqa: SLF001 - internal by design
                "SELECT decision, count(*) FROM agentgate_audit WHERE stage = %s GROUP BY 1",
                (STAGE_ACTION,),
            )
            return {"available": True, "by_decision": {d: n for d, n in rows}}
        except Exception as exc:
            return {"available": False, "detail": f"{type(exc).__name__}: {exc}"}

    def audit_rows(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.engine.audit_store._query(  # noqa: SLF001
            """
            SELECT audit_id, extract(epoch from created_at)::float8, stage, action_type, tool_name,
                   decision, risk_level, risk_score, execution_status, reviewer_status, reasons
            FROM agentgate_audit ORDER BY created_at DESC LIMIT %s
            """,
            (min(max(limit, 1), 200),),
        )
        return [
            {
                "audit_id": r[0],
                "at": r[1],
                "stage": r[2],
                "action_type": r[3],
                "tool_name": r[4],
                "decision": r[5],
                "risk_level": r[6],
                "risk_score": r[7],
                "execution_status": r[8],
                "reviewer_status": r[9],
                "reasons": r[10],
            }
            for r in rows
        ]

    def approvals(self) -> list[dict[str, Any]]:
        rows = self.engine.audit_store._query(  # noqa: SLF001
            """
            SELECT audit_id, extract(epoch from created_at)::float8, action_type, tool_name,
                   risk_level, risk_score, reasons, response
            FROM agentgate_audit
            WHERE stage = %s AND decision = 'NEED_APPROVAL' AND reviewer_status = 'none'
            ORDER BY created_at DESC LIMIT 50
            """,
            (STAGE_ACTION,),
        )
        return [
            {
                "audit_id": r[0],
                "at": r[1],
                "action_type": r[2],
                "tool_name": r[3],
                "risk_level": r[4],
                "risk_score": r[5],
                "reasons": r[6],
                "sanitized_payload": (r[7] or {}).get("sanitized_payload"),
            }
            for r in rows
        ]

    def review(self, audit_id: str, verdict: str) -> None:
        if verdict not in {"approved", "rejected"}:
            raise ValueError("verdict must be approved or rejected")
        if not re.match(r"^aud_[0-9a-f]{12}$", audit_id):
            raise ValueError("invalid audit id")
        # Reviewer decision only. The console does not execute the approved action:
        # nothing here re-enters the router, so approving cannot cause a side effect.
        self.engine.audit_store.update(audit_id, reviewer_status=verdict)

    # --- runs ------------------------------------------------------------

    def run_scenario(self, name: str):
        scenario = self.load_scenario(name)

        def build(on_step):
            loop = AgentLoop(
                ReplayPlanner(scenario["steps"]),
                DecisionRouter(),  # dry-run: the console never executes
                decider=self.engine,
                on_step=on_step,
            )
            return loop, scenario["task"]

        return self.jobs.submit(scenario.get("title", name), "scenario", build)

    def run_chat(self, task: str):
        if not self.planner_available():
            raise ValueError(
                "No LLM planner configured. Set AGENTGATE_LLM_PROVIDER and "
                "AGENTGATE_LLM_API_KEY to use free-text tasks, or run a scenario."
            )

        def build(on_step):
            loop = AgentLoop(
                get_planner("llm"),
                DecisionRouter(),  # dry-run
                decider=self.engine,
                on_step=on_step,
            )
            return loop, task

        return self.jobs.submit(task[:80], "chat", build)


def make_handler(console: Console):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AgentGate"
        sys_version = ""

        # --- helpers ---------------------------------------------------

        def _origin(self) -> str:
            host = self.headers.get("Host", "").strip()
            scheme = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
            return f"{scheme}://{host}" if host else "http://localhost"

        def _session_token(self) -> str | None:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name == SESSION_COOKIE:
                    return value
            return None

        def _authed(self) -> bool:
            return console.sessions.is_valid(self._session_token())

        def _csrf_ok(self) -> bool:
            expected = console.sessions.csrf_for(self._session_token())
            supplied = self.headers.get(CSRF_HEADER, "")
            return bool(expected) and bool(supplied) and expected == supplied

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return {}
            if length <= 0 or length > _MAX_BODY_BYTES:
                return {}
            try:
                return json.loads(self.rfile.read(length).decode("utf-8")) or {}
            except (ValueError, UnicodeDecodeError):
                return {}

        def _send(self, code: int, payload: Any, headers: dict[str, str] | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _html(self, code: int, body: str, headers: dict[str, str] | None = None) -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; form-action 'self'",
            )
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt: str, *args: Any) -> None:
            # Default logging prints the full request line; query strings here can carry
            # an OAuth authorization code.
            path = urlparse(self.path).path
            print(f'{self.address_string()} "{self.command} {path}" {args[1] if len(args) > 1 else ""}')

        # --- routing ---------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802
            route = urlparse(self.path)
            path, query = route.path, parse_qs(route.query)
            try:
                if path == "/":
                    return self._html(200, PAGE)
                if path == CALLBACK_PATH:
                    return self._oauth_callback(query)
                if path.startswith("/api/"):
                    if not self._authed():
                        return self._send(401, {"error": "not authenticated"})
                    return self._api_get(path, query)
                return self._send(404, {"error": "not found"})
            except Exception:
                traceback.print_exc()
                return self._send(500, {"error": "internal error"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                if path == "/api/login":
                    return self._login()
                if not self._authed():
                    return self._send(401, {"error": "not authenticated"})
                if not self._csrf_ok():
                    return self._send(403, {"error": "bad csrf token"})
                return self._api_post(path)
            except Exception:
                traceback.print_exc()
                return self._send(500, {"error": "internal error"})

        # --- endpoints -------------------------------------------------

        def _login(self) -> None:
            supplied = str(self._body().get("password", ""))
            if not check_password(supplied, console.password):
                return self._send(401, {"error": "incorrect password"})
            token, csrf = console.sessions.create()
            cookie = (
                f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200"
            )
            return self._send(200, {"ok": True, "csrf": csrf}, {"Set-Cookie": cookie})

        def _api_get(self, path: str, query: dict[str, list[str]]) -> None:
            if path == "/api/status":
                payload = console.status(self._origin())
                # A reload has a valid cookie but no CSRF token, since that is only
                # issued at login. Hand it back here so POSTs keep working.
                payload["csrf"] = console.sessions.csrf_for(self._session_token())
                return self._send(200, payload)
            if path == "/api/scenarios":
                return self._send(200, {"scenarios": console.scenarios()})
            if path == "/api/jobs":
                return self._send(200, {"jobs": console.jobs.recent()})
            if path.startswith("/api/jobs/"):
                job = console.jobs.get(path.rsplit("/", 1)[-1])
                return self._send(200, job.to_dict()) if job else self._send(
                    404, {"error": "unknown job"}
                )
            if path == "/api/audit":
                try:
                    limit = int(query.get("limit", ["50"])[0])
                except ValueError:
                    limit = 50
                return self._send(200, {"rows": console.audit_rows(limit)})
            if path == "/api/approvals":
                return self._send(200, {"approvals": console.approvals()})
            return self._send(404, {"error": "not found"})

        def _api_post(self, path: str) -> None:
            body = self._body()
            if path == "/api/logout":
                console.sessions.destroy(self._session_token())
                return self._send(
                    200,
                    {"ok": True},
                    {"Set-Cookie": f"{SESSION_COOKIE}=; Path=/; Max-Age=0"},
                )
            if path == "/api/run":
                if console.jobs.busy():
                    return self._send(409, {"error": "a run is already in progress"})
                try:
                    if body.get("scenario"):
                        job = console.run_scenario(str(body["scenario"]))
                    elif str(body.get("task", "")).strip():
                        job = console.run_chat(str(body["task"]).strip()[:2000])
                    else:
                        return self._send(400, {"error": "provide a scenario or a task"})
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(202, {"job": job.to_dict()})
            if path == "/api/review":
                try:
                    console.review(str(body.get("audit_id", "")), str(body.get("verdict", "")))
                except (ValueError, AuditUnavailable) as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(200, {"ok": True})
            if path == "/api/gmail/connect":
                try:
                    return self._send(200, {"url": console.gmail.start(self._origin())})
                except AuthError as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/api/gmail/disconnect":
                try:
                    console.gmail.disconnect()
                except AuthError as exc:
                    return self._send(400, {"error": str(exc)})
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})

        def _oauth_callback(self, query: dict[str, list[str]]) -> None:
            # Reached by Google's redirect, which cannot carry our session cookie
            # cross-site under SameSite=Strict, so this route is not session-gated.
            # It is safe: it only completes a flow the console itself started, and the
            # unguessable state must match one we issued.
            if query.get("error"):
                return self._html(400, _result_page(f"Authorization failed: {query['error'][0]}"))
            code = query.get("code", [""])[0]
            state = query.get("state", [""])[0]
            if not code or not state:
                return self._html(400, _result_page("Callback was missing code or state."))
            try:
                console.gmail.finish(self._origin(), code, state)
            except AuthError as exc:
                return self._html(400, _result_page(f"Could not connect Gmail: {exc}"))
            return self._html(200, _result_page("Gmail connected. You can close this tab."))

    return Handler


def _result_page(message: str) -> str:
    safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return (
        "<!doctype html><meta charset='utf-8'><title>AgentGate</title>"
        "<body style=\"font:15px system-ui;padding:3rem;max-width:40rem;margin:auto\">"
        f"<h2>AgentGate</h2><p>{safe}</p><p><a href='/'>Back to the console</a></p></body>"
    )


def serve(host: str = "127.0.0.1", port: int = 8080) -> None:
    console = Console()
    httpd = ThreadingHTTPServer((host, port), make_handler(console))
    scope = "all interfaces" if host == "0.0.0.0" else host  # noqa: S104 - user's choice
    print(f"AgentGate Demo Console on http://{host}:{port}  (bound to {scope})")
    print(f"Detector model: {console.status(f'http://{host}:{port}')['detector_model']}")
    print("Password auth is required; sessions are in memory.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
    finally:
        httpd.server_close()
