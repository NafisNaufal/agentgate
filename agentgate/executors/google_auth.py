"""Google OAuth2 for the Gmail executor, using only the standard library.

The consent step runs a loopback redirect server on 127.0.0.1: AgentGate prints a
consent URL carrying a random ``state``, Google redirects the browser back to the
local port with an authorization code, the code is exchanged for tokens, and the
tokens are written to a file that only the current user can read.

Access tokens are refreshed automatically. Nothing here ever puts a token, refresh
token, or client secret into an exception message - see ``AuthError``.

Configuration::

    GOOGLE_CLIENT_ID
    GOOGLE_CLIENT_SECRET
    GOOGLE_SCOPES        comma-separated
    GOOGLE_TOKEN_FILE    default ./token.json (gitignored)
    GOOGLE_OAUTH_PORT    loopback callback port; 0 (default) picks a free one

On a headless host pin GOOGLE_OAUTH_PORT and forward it from the machine that has a
browser, so Google's redirect to 127.0.0.1 reaches the flow:

    ssh -L 8765:127.0.0.1:8765 -p <port> user@host
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import time
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
DEFAULT_TOKEN_FILE = "token.json"
# Refresh slightly early so a token cannot expire mid-request.
_EXPIRY_MARGIN_SECONDS = 60


class AuthError(RuntimeError):
    """Google auth failed. Messages are safe to log - they never carry credentials."""


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: str
    scopes: tuple[str, ...]
    token_file: Path
    callback_port: int = 0


def load_config() -> GoogleOAuthConfig:
    missing = [
        name
        for name in ("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_SCOPES")
        if not os.environ.get(name, "").strip()
    ]
    if missing:
        raise AuthError(f"Missing Google OAuth environment variables: {', '.join(missing)}")
    scopes = tuple(s.strip() for s in os.environ["GOOGLE_SCOPES"].split(",") if s.strip())
    if not scopes:
        raise AuthError("GOOGLE_SCOPES must list at least one scope")
    return GoogleOAuthConfig(
        client_id=os.environ["GOOGLE_CLIENT_ID"].strip(),
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"].strip(),
        scopes=scopes,
        token_file=Path(os.environ.get("GOOGLE_TOKEN_FILE", DEFAULT_TOKEN_FILE)),
        callback_port=_callback_port(),
    )


def _callback_port() -> int:
    raw = os.environ.get("GOOGLE_OAUTH_PORT", "0").strip() or "0"
    try:
        port = int(raw)
    except ValueError:
        raise AuthError("GOOGLE_OAUTH_PORT must be an integer") from None
    if not 0 <= port <= 65535:
        raise AuthError("GOOGLE_OAUTH_PORT must be between 0 and 65535")
    return port


def access_token(config: GoogleOAuthConfig | None = None) -> str:
    """Return a valid access token, refreshing it first when it is close to expiry."""
    cfg = config or load_config()
    token = _read_token(cfg.token_file)
    if token is None:
        raise AuthError(
            f"No Google token at {cfg.token_file}. Run the consent flow first: "
            "python3 -m agentgate google-auth"
        )
    if token.get("expires_at", 0) > time.time() + _EXPIRY_MARGIN_SECONDS:
        return str(token["access_token"])
    if not token.get("refresh_token"):
        raise AuthError("Stored Google token has no refresh token; re-run the consent flow")
    refreshed = _post_form(
        {
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "refresh_token": token["refresh_token"],
            "grant_type": "refresh_token",
        }
    )
    merged = {
        "access_token": refreshed["access_token"],
        # Google usually omits refresh_token on refresh; keep the one we already have.
        "refresh_token": refreshed.get("refresh_token", token["refresh_token"]),
        "expires_at": time.time() + float(refreshed.get("expires_in", 3600)),
    }
    _write_token(cfg.token_file, merged)
    return str(merged["access_token"])


def run_consent_flow(config: GoogleOAuthConfig | None = None) -> Path:
    """Run the loopback consent flow and store the resulting tokens."""
    cfg = config or load_config()
    state = secrets.token_urlsafe(24)
    result: dict[str, str] = {}

    with ThreadingHTTPServer(("127.0.0.1", cfg.callback_port), _handler_for(result)) as server:
        redirect_uri = f"http://127.0.0.1:{server.server_port}/"
        query = urllib.parse.urlencode(
            {
                "client_id": cfg.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": " ".join(cfg.scopes),
                "state": state,
                "access_type": "offline",
                "prompt": "consent",
            }
        )
        url = f"{AUTH_ENDPOINT}?{query}"
        print(f"Open this URL to authorize AgentGate:\n\n  {url}\n")
        try:
            webbrowser.open(url)
        except Exception:
            pass  # headless is fine; the URL was printed above
        while not result:
            server.handle_request()

    if result.get("error"):
        raise AuthError(f"Consent failed: {result['error']}")
    if not result.get("code"):
        raise AuthError("Consent callback carried no authorization code")
    if not secrets.compare_digest(result.get("state", ""), state):
        raise AuthError("OAuth state mismatch; the callback may have been tampered with")

    token = _post_form(
        {
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "code": result["code"],
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
    )
    if not token.get("refresh_token"):
        raise AuthError("Google returned no refresh token; retry with prompt=consent")
    _write_token(
        cfg.token_file,
        {
            "access_token": token["access_token"],
            "refresh_token": token["refresh_token"],
            "expires_at": time.time() + float(token.get("expires_in", 3600)),
        },
    )
    return cfg.token_file


# --- internals -----------------------------------------------------------


def _handler_for(result: dict[str, str]) -> type[BaseHTTPRequestHandler]:
    """Build a one-shot callback handler bound to this flow's result dict.

    Deliberately not module-level state: two concurrent flows must not be able to
    read each other's authorization code.
    """

    class _CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            for key in ("code", "state", "error"):
                value = params.get(key, [""])[0]
                if value:
                    result[key] = value
            if not result:
                result["error"] = "callback carried no code, state, or error"
            body = (
                b"Authorization failed; you can close this window."
                if result.get("error")
                else b"Authorization complete. You can close this window."
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            pass  # keep the CLI quiet

    return _CallbackHandler


def _post_form(fields: dict[str, str], timeout: float = 30.0) -> dict[str, Any]:
    request = urllib.request.Request(
        TOKEN_ENDPOINT,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(1_048_576).decode("utf-8"))
    except Exception as exc:
        # Never interpolate `fields` - it holds the client secret and refresh token.
        raise AuthError(f"Google token endpoint request failed ({type(exc).__name__})") from None
    if not isinstance(payload, dict) or "access_token" not in payload:
        raise AuthError("Google token endpoint returned an unexpected response")
    return payload


def _read_token(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthError(f"Google token file at {path} is unreadable or malformed") from None
    if not isinstance(data, dict) or "access_token" not in data:
        raise AuthError(f"Google token file at {path} is missing an access token")
    return data


def _write_token(path: Path, token: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(token, indent=2))
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600: refresh tokens are long-lived
    except OSError:
        pass
