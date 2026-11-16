"""Tests for the standard-library HTTP dashboard server and JSON API."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from typing import Tuple

from netwatch.clock import FixedClock
from netwatch.server import DashboardServer, build_server
from tests.helpers import StoreTestCase


class ServerTestCase(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        device = self.store.upsert_device("192.0.2.10", name="edge-sw01.example")
        interface = self.store.upsert_interface(
            device.id, 1, "Ethernet0/1", alias="uplink-core", speed_bps=1_000_000_000
        )
        self.clock.advance(1.0)
        self.store.record_sample(
            interface.id,
            self.clock.timestamp(),
            in_octets=1_000_000,
            out_octets=500_000,
            counter_bits=64,
            in_bps=100_000_000.0,
            out_bps=5_000_000.0,
            utilization_pct=10.0,
            oper_status=1,
        )
        self.server = DashboardServer(
            self.store, host="127.0.0.1", port=0, clock=self.clock, refresh_seconds=45
        )
        self.httpd = self.server.build_server()
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        def stop() -> None:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join(timeout=5)

        self.addCleanup(stop)
        host, port = self.httpd.server_address[:2]
        self.base_url = f"http://{host}:{port}"

    def fetch(self, path: str) -> Tuple[int, str, str]:
        with urllib.request.urlopen(self.base_url + path, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "")
            body = response.read().decode("utf-8")
            return response.status, content_type, body


class DashboardEndpointTests(ServerTestCase):
    def test_root_serves_html_dashboard(self) -> None:
        status, content_type, body = self.fetch("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", content_type)
        self.assertIn("netwatch dashboard", body)
        self.assertIn("Ethernet0/1", body)
        self.assertIn('<meta http-equiv="refresh" content="45">', body)
        self.assertNotIn("http://", body)
        self.assertNotIn("https://", body)

    def test_trailing_slash_is_normalized(self) -> None:
        status, _content_type, body = self.fetch("//")
        self.assertEqual(status, 200)
        self.assertIn("netwatch", body)

    def test_summary_api_returns_json(self) -> None:
        status, content_type, body = self.fetch("/api/summary")
        self.assertEqual(status, 200)
        self.assertIn("application/json", content_type)
        payload = json.loads(body)
        self.assertEqual(payload["totals"]["devices"], 1)
        self.assertEqual(payload["totals"]["interfaces"], 1)
        self.assertEqual(payload["totals"]["samples"], 1)
        self.assertEqual(payload["devices"][0]["address"], "192.0.2.10")
        self.assertEqual(payload["devices"][0]["interfaces"][0]["in_bps"], 100_000_000.0)
        self.assertEqual(payload["devices"][0]["interfaces"][0]["utilization_pct"], 10.0)
        self.assertEqual(payload["thresholds"]["utilization_pct"], 80.0)

    def test_health_api(self) -> None:
        status, _content_type, body = self.fetch("/api/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["samples"], 1)
        self.assertEqual(payload["active_alerts"], 0)

    def test_unknown_path_returns_json_404(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as context:
            self.fetch("/does-not-exist")
        error = context.exception
        self.assertEqual(error.code, 404)
        payload = json.loads(error.read().decode("utf-8"))
        self.assertEqual(payload["error"], "not found")


class ServerFactoryTests(unittest.TestCase):
    def test_build_server_helper(self) -> None:
        from netwatch.storage import Store

        clock = FixedClock()
        store = Store(":memory:", clock=clock)
        self.addCleanup(store.close)
        store.initialize()
        factory, httpd = build_server(store, port=0, clock=clock)
        try:
            self.assertIsInstance(factory, DashboardServer)
            self.assertEqual(httpd.server_address[0], "127.0.0.1")
            self.assertGreater(httpd.server_address[1], 0)
        finally:
            httpd.server_close()

    def test_invalid_bind_address_fails(self) -> None:
        from netwatch.storage import Store

        store = Store(":memory:")
        self.addCleanup(store.close)
        store.initialize()
        server = DashboardServer(store, host="203.0.113.254", port=0)
        with self.assertRaises(OSError):
            server.build_server()


if __name__ == "__main__":
    unittest.main()
