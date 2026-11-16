"""Tests for the reporting read models and text renderers."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from netwatch.alerting import Thresholds
from netwatch.poller import InterfaceReading, PollResult
from netwatch.reporting import (
    build_alerts_payload,
    build_summary,
    poll_result_to_dict,
    render_alerts,
    render_poll_result,
    render_report,
)
from tests.helpers import StoreTestCase


class ReportingTestCase(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.device = self.store.upsert_device("192.0.2.10", name="edge-sw01.example")
        self.interface = self.store.upsert_interface(
            self.device.id, 1, "Ethernet0/1", alias="uplink-core", speed_bps=1_000_000_000
        )
        self.clock.advance(1.0)
        self.store.record_sample(
            self.interface.id,
            self.clock.timestamp(),
            in_octets=1_000_000,
            out_octets=500_000,
            counter_bits=64,
            in_bps=150_000_000.0,
            out_bps=2_000_000.0,
            utilization_pct=15.0,
            oper_status=1,
        )
        self.clock.advance(1.0)
        self.alert = self.store.record_alert(
            device_id=self.device.id,
            interface_id=self.interface.id,
            kind="utilization",
            severity="warning",
            message="Ethernet0/1 (uplink-core): utilization 91.2% is at or above the 80.0% threshold",
            value=91.2,
            threshold=80.0,
        )


class EmptySummaryTests(StoreTestCase):
    def test_empty_summary(self) -> None:
        summary = build_summary(self.store)
        self.assertIn("generated_at", summary)
        self.assertEqual(summary["totals"]["devices"], 0)
        self.assertEqual(summary["totals"]["interfaces"], 0)
        self.assertEqual(summary["totals"]["samples"], 0)
        self.assertEqual(summary["totals"]["active_alerts"], 0)
        self.assertEqual(summary["devices"], [])
        self.assertEqual(summary["alerts"], [])
        json.dumps(summary)  # must be JSON serialisable


class SummaryTests(ReportingTestCase):
    def test_populated_summary(self) -> None:
        summary = build_summary(self.store)
        self.assertEqual(summary["totals"]["devices"], 1)
        self.assertEqual(summary["totals"]["reachable_devices"], 1)
        self.assertEqual(summary["totals"]["interfaces"], 1)
        self.assertEqual(summary["totals"]["samples"], 1)
        self.assertEqual(summary["totals"]["active_alerts"], 1)
        device = summary["devices"][0]
        self.assertEqual(device["address"], "192.0.2.10")
        self.assertEqual(device["name"], "edge-sw01.example")
        interface = device["interfaces"][0]
        self.assertEqual(interface["name"], "Ethernet0/1")
        self.assertEqual(interface["alias"], "uplink-core")
        self.assertEqual(interface["in_bps"], 150_000_000.0)
        self.assertEqual(interface["out_bps"], 2_000_000.0)
        self.assertEqual(interface["utilization_pct"], 15.0)
        self.assertEqual(interface["oper_status_text"], "up")
        self.assertEqual(interface["samples"], 1)
        alert = summary["alerts"][0]
        self.assertEqual(alert["kind"], "utilization")
        self.assertEqual(alert["severity"], "warning")
        self.assertEqual(alert["target"], "edge-sw01.example / Ethernet0/1 (uplink-core)")
        self.assertEqual(alert["device"], "192.0.2.10")
        self.assertEqual(alert["value"], 91.2)
        self.assertEqual(alert["threshold"], 80.0)

    def test_summary_echoes_thresholds_and_timestamp(self) -> None:
        moment = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
        summary = build_summary(self.store, Thresholds(utilization_pct=75.0), moment)
        self.assertEqual(summary["thresholds"]["utilization_pct"], 75.0)
        self.assertTrue(summary["thresholds"]["oper_status_down"])
        self.assertEqual(summary["generated_at"], "2026-03-04T05:06:07+00:00")


class PollResultSerialisationTests(unittest.TestCase):
    def test_poll_result_to_dict(self) -> None:
        moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
        result = PollResult(
            address="simulator",
            name="simsw01.example",
            reachable=True,
            polled_at=moment,
            duration_ms=12,
            sys_name="simsw01.example",
            sys_descr="NetWatch simulated agent",
            uptime_seconds=10.5,
            alerts_opened=1,
            interfaces=[
                InterfaceReading(
                    if_index=1,
                    name="Ethernet0/1",
                    alias="uplink",
                    oper_status=1,
                    speed_bps=1_000_000_000,
                    in_octets=10,
                    out_octets=20,
                    counter_bits=64,
                    in_bps=1000.0,
                    out_bps=2000.0,
                    utilization_pct=0.0002,
                )
            ],
        )
        payload = poll_result_to_dict(result)
        self.assertEqual(payload["address"], "simulator")
        self.assertTrue(payload["reachable"])
        self.assertEqual(payload["polled_at"], "2026-01-01T00:00:00+00:00")
        self.assertEqual(payload["interfaces"][0]["oper_status_text"], "up")
        self.assertEqual(payload["interfaces"][0]["counter_bits"], 64)
        json.dumps(payload)


class ReportTextTests(ReportingTestCase):
    def test_populated_report(self) -> None:
        text = render_report(self.store)
        self.assertIn("netwatch report -", text)
        self.assertIn("192.0.2.10", text)
        self.assertIn("edge-sw01.example", text)
        self.assertIn("Ethernet0/1", text)
        self.assertIn("uplink-core", text)
        self.assertIn("1.00 Gbps", text)
        self.assertIn("150.00 Mbps", text)
        self.assertIn("15.0%", text)
        self.assertIn("active alerts", text)
        self.assertIn("utilization 91.2%", text)
        self.assertIn("samples", text)

    def test_empty_report_explains_next_step(self) -> None:
        store = self.store
        empty = type(store)(self.db_path.parent / "empty.db", clock=self.clock)
        self.addCleanup(empty.close)
        empty.initialize()
        text = render_report(empty)
        self.assertIn("No devices have been polled yet", text)
        self.assertIn("netwatch poll --simulate", text)

    def test_report_is_plain_text(self) -> None:
        text = render_report(self.store)
        self.assertNotIn("<", text)
        self.assertNotIn("http", text.lower())


class AlertTextTests(ReportingTestCase):
    def test_alert_list(self) -> None:
        text = render_alerts(self.store)
        self.assertIn("utilization", text)
        self.assertIn("warning", text)
        self.assertIn("Ethernet0/1 (uplink-core)", text)
        self.assertIn("1 active alert(s), 0 resolved alert(s) in total", text)
        self.assertIn("active", text)

    def test_include_resolved_alerts(self) -> None:
        self.store.resolve_alert(self.alert.id)
        active_text = render_alerts(self.store)
        self.assertIn("no active alerts recorded", active_text)
        all_text = render_alerts(self.store, include_resolved=True)
        self.assertIn("resolved", all_text)
        self.assertIn("utilization", all_text)
        self.assertIn("0 active alert(s), 1 resolved alert(s) in total", active_text)

    def test_empty_alert_list(self) -> None:
        self.store.resolve_alert(self.alert.id)
        text = render_alerts(self.store)
        self.assertIn("no active alerts recorded", text)
        self.assertIn("0 active alert(s), 1 resolved alert(s) in total", text)

    def test_alerts_payload(self) -> None:
        payload = build_alerts_payload(self.store)
        self.assertEqual(payload["active"], 1)
        self.assertEqual(payload["resolved"], 0)
        self.assertEqual(payload["total"], 1)
        entry = payload["alerts"][0]
        self.assertEqual(entry["kind"], "utilization")
        self.assertEqual(entry["state"], "active")
        self.assertEqual(entry["target"], "edge-sw01.example / Ethernet0/1 (uplink-core)")
        json.dumps(payload)


class PollTextTests(unittest.TestCase):
    def _result(self, reachable: bool, error: str | None = None) -> PollResult:
        return PollResult(
            address="simulator",
            name="simsw01.example",
            reachable=reachable,
            polled_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_ms=3,
            interfaces=[]
            if not reachable
            else [
                InterfaceReading(
                    if_index=1,
                    name="Ethernet0/1",
                    alias="uplink-core",
                    oper_status=1,
                    speed_bps=1_000_000_000,
                    in_octets=1,
                    out_octets=2,
                    counter_bits=64,
                    in_bps=123_000_000.0,
                    out_bps=1_500_000.0,
                    utilization_pct=12.3,
                )
            ],
            sys_descr="simulated",
            uptime_seconds=65.0,
            error=error,
        )

    def test_reachable_poll_text(self) -> None:
        text = render_poll_result(self._result(True))
        self.assertIn("device simsw01.example (simulator) - reachable", text)
        self.assertIn("Ethernet0/1", text)
        self.assertIn("123.00 Mbps", text)
        self.assertIn("12.3%", text)
        self.assertIn("sysUpTime: 0d 00:01:05", text)

    def test_unreachable_poll_text(self) -> None:
        text = render_poll_result(self._result(False, "timeout"))
        self.assertIn("UNREACHABLE", text)
        self.assertIn("error: timeout", text)


if __name__ == "__main__":
    unittest.main()
