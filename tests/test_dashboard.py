"""Tests for the self-contained HTML dashboard and its SVG sparklines."""

from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone

from netwatch.dashboard import render_dashboard, sparkline_pair_svg, sparkline_points
from tests.helpers import StoreTestCase


class SparklineUnitTests(unittest.TestCase):
    def test_empty_series(self) -> None:
        self.assertEqual(sparkline_points([]), "")

    def test_single_value_is_a_flat_segment(self) -> None:
        points = sparkline_points([500.0], width=100, height=40, padding=2)
        first, second = points.split()
        self.assertEqual(first.split(",")[1], second.split(",")[1])
        self.assertNotEqual(first.split(",")[0], second.split(",")[0])

    def test_flat_series_uses_one_height(self) -> None:
        points = sparkline_points([10.0, 10.0, 10.0], width=100, height=40, padding=2)
        heights = {point.split(",")[1] for point in points.split()}
        self.assertEqual(len(heights), 1)

    def test_maximum_scales_the_series(self) -> None:
        points = sparkline_points([0.0, 50.0], width=100, height=40, padding=2, maximum=100.0)
        first, second = points.split()
        self.assertEqual(first, "2.0,38.0")
        self.assertEqual(second, "98.0,20.0")

    def test_pair_svg_contains_both_series(self) -> None:
        svg = sparkline_pair_svg([1.0, 2.0], [0.5, 0.7], 'if "<1>"')
        self.assertIn('class="spark-axis"', svg)
        self.assertIn('class="spark-in"', svg)
        self.assertIn('class="spark-out"', svg)
        self.assertIn("&lt;1&gt;", svg)
        self.assertNotIn("<1>", svg)


class DashboardTestCase(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.device = self.store.upsert_device("192.0.2.10", name="edge-sw01.example")
        self.interface = self.store.upsert_interface(
            self.device.id, 1, "Ethernet0/1", alias="uplink-core", speed_bps=1_000_000_000
        )
        self.interface = self.store.upsert_interface(
            self.device.id, 2, "Ethernet0/2", alias="server-farm", speed_bps=1_000_000_000
        )
        self.clock.advance(1.0)
        self.store.record_sample(
            self.interface.id,
            self.clock.timestamp(),
            in_octets=10_000_000,
            out_octets=5_000_000,
            counter_bits=64,
            in_bps=120_000_000.0,
            out_bps=10_000_000.0,
            utilization_pct=12.0,
            oper_status=1,
        )
        self.clock.advance(1.0)
        self.store.record_sample(
            self.interface.id,
            self.clock.timestamp(),
            in_octets=20_000_000,
            out_octets=9_000_000,
            counter_bits=64,
            in_bps=135_000_000.0,
            out_bps=9_500_000.0,
            utilization_pct=13.5,
            oper_status=2,
        )
        self.store.record_alert(
            device_id=self.device.id,
            interface_id=self.interface.id,
            kind="oper_status_down",
            severity="critical",
            message="Ethernet0/2 (server-farm): oper status is down (expected up)",
        )


class EmptyDashboardTests(StoreTestCase):
    def test_empty_dashboard_markers(self) -> None:
        document = render_dashboard(self.store)
        self.assertTrue(document.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>netwatch dashboard</title>", document)
        self.assertIn("No devices yet.", document)
        self.assertIn("No active alerts.", document)
        self.assertIn("0 device(s), 0 reachable", document)
        self.assertIn('<meta http-equiv="refresh" content="30">', document)
        self.assertTrue(document.rstrip().endswith("</html>"))

    def test_dashboard_is_fully_self_contained(self) -> None:
        document = render_dashboard(self.store)
        for marker in ("http://", "https://", "<script", "<link", "@import", "src="):
            self.assertNotIn(marker, document)
        self.assertIn("<style>", document)

    def test_custom_refresh_period(self) -> None:
        document = render_dashboard(self.store, refresh_seconds=15)
        self.assertIn('<meta http-equiv="refresh" content="15">', document)


class PopulatedDashboardTests(DashboardTestCase):
    def test_tables_and_values_are_rendered(self) -> None:
        document = render_dashboard(self.store)
        self.assertIn('id="devices"', document)
        self.assertIn('id="interfaces"', document)
        self.assertIn('id="alerts"', document)
        self.assertIn("192.0.2.10", document)
        self.assertIn("edge-sw01.example", document)
        self.assertIn("Ethernet0/1", document)
        self.assertIn("uplink-core", document)
        self.assertIn("1.00 Gbps", document)
        self.assertIn("135.00 Mbps", document)
        self.assertIn("13.5%", document)
        self.assertIn('<span class="bad">down</span>', document)

    def test_sparklines_are_inline_svg(self) -> None:
        document = render_dashboard(self.store)
        self.assertIn("<svg", document)
        self.assertIn('class="spark-in"', document)
        self.assertIn('class="spark-out"', document)
        self.assertIn('data-if-index="1"', document)
        self.assertNotIn("http://", document)
        self.assertNotIn("https://", document)

    def test_alert_section_lists_open_alerts(self) -> None:
        document = render_dashboard(self.store)
        self.assertIn("oper_status_down", document)
        self.assertIn("Ethernet0/2 (server-farm)", document)
        self.assertIn("1 active alert(s)", document)
        self.assertIn('<span class="bad">critical</span>', document)

    def test_values_are_html_escaped(self) -> None:
        self.store.upsert_interface(
            self.device.id, 9, '<script>alert("x")</script>', alias="<b>bold</b>"
        )
        document = render_dashboard(self.store)
        self.assertNotIn("<script>", document)
        self.assertIn("&lt;script&gt;", document)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt;", document)

    def test_generated_timestamp_is_deterministic(self) -> None:
        moment = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        first = render_dashboard(self.store, generated_at=moment)
        second = render_dashboard(self.store, generated_at=moment)
        self.assertEqual(first, second)
        self.assertIn("2026-01-02 03:04:05 UTC", first)

    def test_sample_limit_controls_sparkline_points(self) -> None:
        document = render_dashboard(self.store, sample_limit=1)
        points = re.findall(r'<polyline class="spark-in" points="([^"]*)"', document)
        self.assertTrue(points)
        # A single sample becomes a flat two-point segment.
        self.assertEqual(len(points[0].split()), 2)
        first, second = points[0].split()
        self.assertEqual(first.split(",")[1], second.split(",")[1])

    def test_interface_without_rates_shows_placeholder(self) -> None:
        interface = self.store.upsert_interface(self.device.id, 3, "Ethernet0/3", alias="spare")
        self.store.record_sample(
            interface.id,
            self.clock.timestamp(),
            in_octets=100,
            out_octets=50,
            counter_bits=64,
            in_bps=None,
            out_bps=None,
            utilization_pct=None,
            oper_status=1,
        )
        document = render_dashboard(self.store)
        self.assertIn("no rates yet", document)
        self.assertIn('data-if-index="3"', document)


if __name__ == "__main__":
    unittest.main()
