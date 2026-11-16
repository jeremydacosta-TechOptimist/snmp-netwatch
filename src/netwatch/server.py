"""Minimal HTTP server exposing the dashboard and a JSON API.

Only the Python standard library is used: :class:`http.server.ThreadingHTTPServer`
serves the rendered dashboard on ``/``, the monitoring summary as JSON on
``/api/summary``, a liveness probe on ``/api/health`` and a JSON 404 for every
unknown path. The server reads the same SQLite store the poller writes to, so a
running instance always shows the latest data after a refresh.
"""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from .alerting import Thresholds
from .clock import Clock, SystemClock
from .dashboard import render_dashboard
from .reporting import build_summary
from .storage import Store

__all__ = ["DashboardServer", "build_server"]

_CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
}


class DashboardServer:
    """Factory for a threaded HTTP server bound to a :class:`Store`."""

    def __init__(
        self,
        store: Store,
        host: str = "127.0.0.1",
        port: int = 8080,
        thresholds: Optional[Thresholds] = None,
        refresh_seconds: int = 30,
        clock: Optional[Clock] = None,
    ) -> None:
        self.store = store
        self.host = host
        self.port = int(port)
        self.thresholds = thresholds or Thresholds()
        self.refresh_seconds = int(refresh_seconds)
        self.clock = clock or store.clock or SystemClock()

    def build_server(self) -> ThreadingHTTPServer:
        """Create (but do not start) the HTTP server bound to the configured address."""

        store = self.store
        thresholds = self.thresholds
        refresh_seconds = self.refresh_seconds
        clock = self.clock

        class Handler(_DashboardHandler):
            _store = store
            _thresholds = thresholds
            _refresh_seconds = refresh_seconds
            _clock = clock

        server = ThreadingHTTPServer((self.host, self.port), Handler)
        server.daemon_threads = True
        return server

    def serve_forever(self) -> None:
        """Serve until interrupted; Ctrl+C shuts the server down cleanly."""

        server = self.build_server()
        host, port = server.server_address[:2]
        print(f"netwatch dashboard listening on http://{host}:{port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
            server.server_close()


class _DashboardHandler(BaseHTTPRequestHandler):
    """Request handler shared by the default and test-created servers."""

    _store: Store
    _thresholds: Thresholds
    _refresh_seconds: int
    _clock: Clock
    server_version = "netwatch/1.0"
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/":
            body = render_dashboard(
                self._store,
                thresholds=self._thresholds,
                generated_at=self._clock.utcnow(),
                refresh_seconds=self._refresh_seconds,
            ).encode("utf-8")
            self._send(HTTPStatus.OK, body, "html")
        elif path == "/api/summary":
            summary = build_summary(
                self._store, thresholds=self._thresholds, generated_at=self._clock.utcnow()
            )
            self._send_json(HTTPStatus.OK, summary)
        elif path == "/api/health":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "generated_at": self._clock.utcnow().isoformat(timespec="seconds"),
                    "samples": self._store.count_samples(),
                    "active_alerts": self._store.count_alerts(active_only=True),
                },
            )
        else:
            self._send_json(
                HTTPStatus.NOT_FOUND,
                {"error": "not found", "path": path},
            )

    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=False).encode("utf-8")
        self._send(status, body, "json")

    def _send(self, status: HTTPStatus, body: bytes, kind: str) -> None:
        self.send_response(int(status))
        self.send_header("Content-Type", _CONTENT_TYPES[kind])
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        """Keep the CLI output quiet; template argument names follow the stdlib."""


def build_server(
    store: Store,
    host: str = "127.0.0.1",
    port: int = 8080,
    thresholds: Optional[Thresholds] = None,
    refresh_seconds: int = 30,
    clock: Optional[Clock] = None,
) -> Tuple[DashboardServer, ThreadingHTTPServer]:
    """Convenience helper returning both the factory and its bound server."""

    factory = DashboardServer(
        store,
        host=host,
        port=port,
        thresholds=thresholds,
        refresh_seconds=refresh_seconds,
        clock=clock,
    )
    return factory, factory.build_server()
