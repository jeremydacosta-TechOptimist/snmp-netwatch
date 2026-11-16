"""End-to-end integration tests across agent, poller, store and dashboard."""

from __future__ import annotations

import json
import unittest

from netwatch.agent import SimulatedDevice, SimulatedInterface, SnmpAgent
from netwatch.alerting import KIND_OPER_DOWN, KIND_UTILIZATION, Thresholds
from netwatch.clock import FixedClock
from netwatch.dashboard import render_dashboard
from netwatch.poller import Poller
from netwatch.reporting import build_alerts_payload, build_summary, render_report
from tests.helpers import StoreTestCase, unused_ports


class FullPipelineTests(StoreTestCase):
    """Agent -> poller -> SQLite -> alerts -> dashboard/report/API summary."""

    def setUp(self) -> None:
        super().setUp()
        self.agent_clock = FixedClock(start=self.clock.now())
        self.device = SimulatedDevice(clock=self.agent_clock)
        self.agent = SnmpAgent(self.device, host="127.0.0.1", port=0)
        self.host, self.port = self.agent.start()
        self.addCleanup(self.agent.stop)
        self.thresholds = Thresholds(utilization_pct=80.0)
        self.poller = Poller(self.store, self.thresholds, clock=self.clock)

    def poll(self):
        return self.poller.poll("simulator", host=self.host, port=self.port)

    def advance(self, seconds: float) -> None:
        self.clock.advance(seconds)
        self.agent_clock.advance(seconds)

    def test_full_monitoring_cycle(self) -> None:
        first = self.poll()
        self.assertTrue(first.reachable)
        self.assertEqual(len(first.interfaces), 3)
        self.assertEqual(self.store.count_samples(), 3)

        self.advance(30.0)
        second = self.poll()
        self.assertTrue(second.reachable)
        self.assertEqual(self.store.count_samples(), 6)
        self.assertTrue(all(reading.in_bps is not None for reading in second.interfaces[:2]))
        self.assertGreater(second.interfaces[0].utilization_pct or 0.0, 0.0)

        summary = build_summary(self.store, self.thresholds)
        self.assertEqual(summary["totals"]["devices"], 1)
        self.assertEqual(summary["totals"]["interfaces"], 3)
        self.assertEqual(summary["totals"]["samples"], 6)
        self.assertEqual(summary["totals"]["active_alerts"], 1)
        self.assertEqual(summary["alerts"][0]["kind"], KIND_OPER_DOWN)
        json.dumps(summary, allow_nan=False)

        dashboard = render_dashboard(self.store)
        self.assertIn("Ethernet0/3", dashboard)
        self.assertIn("<svg", dashboard)
        self.assertIn("oper_status_down", dashboard)
        self.assertIn("spark-in", dashboard)

        report = render_report(self.store)
        self.assertIn("Ethernet0/2", report)
        self.assertIn("oper status is down", report)

        payload = build_alerts_payload(self.store)
        self.assertEqual(payload["active"], 1)

    def test_threshold_alert_then_recovery(self) -> None:
        up_interfaces = [
            SimulatedInterface(
                index=index,
                name=name,
                alias="uplink",
                speed_bps=1_000_000_000,
                oper_status=1,
                in_utilization=0.5,
                out_utilization=0.4,
                swing=0.05,
            )
            for index, name in ((1, "Ethernet0/1"), (2, "Ethernet0/2"))
        ]
        self.device.interfaces = up_interfaces
        sensitive = Poller(self.store, Thresholds(utilization_pct=40.0), clock=self.clock)
        sensitive.poll("simulator", host=self.host, port=self.port)
        self.advance(60.0)
        sensitive.poll("simulator", host=self.host, port=self.port)
        utilization_alerts = [
            alert for alert in self.store.list_alerts() if alert.kind == KIND_UTILIZATION
        ]
        self.assertEqual(len(utilization_alerts), 2)
        self.assertTrue(all(alert.value is not None for alert in utilization_alerts))
        # Raise the threshold above the measured utilization: existing alerts resolve.
        recovered = Poller(self.store, Thresholds(utilization_pct=99.0), clock=self.clock)
        self.advance(30.0)
        recovered.poll("simulator", host=self.host, port=self.port)
        self.assertEqual(
            [alert for alert in self.store.list_alerts() if alert.kind == KIND_UTILIZATION], []
        )

    def test_simulator_session_reset_clears_history(self) -> None:
        self.poll()
        self.advance(10.0)
        self.poll()
        self.assertEqual(self.store.count_samples(), 6)
        device = self.store.get_device("simulator")
        assert device is not None
        removed = self.store.reset_samples_for_device(device.id)
        self.assertEqual(removed, 6)
        result = self.poll()
        self.assertTrue(result.reachable)
        self.assertTrue(all(reading.in_bps is None for reading in result.interfaces))
        self.assertEqual(self.store.count_samples(), 3)

    def test_unreachable_device_pipeline(self) -> None:
        closed_port = unused_ports()[0]
        poller = Poller(self.store, self.thresholds, clock=self.clock, timeout=0.2, retries=0)
        result = poller.poll("192.0.2.50", host="127.0.0.1", port=closed_port)
        self.assertFalse(result.reachable)
        summary = build_summary(self.store, self.thresholds)
        self.assertEqual(summary["totals"]["reachable_devices"], 0)
        self.assertEqual(summary["totals"]["active_alerts"], 1)
        self.assertEqual(summary["alerts"][0]["kind"], "device_unreachable")
        dashboard = render_dashboard(self.store)
        self.assertIn("192.0.2.50", dashboard)
        self.assertIn('<span class="bad"', dashboard)
        # Bring the same labelled device back through the working simulator endpoint.
        recovered = poller.poll("192.0.2.50", host=self.host, port=self.port)
        self.assertTrue(recovered.reachable)
        summary = build_summary(self.store, self.thresholds)
        self.assertEqual(summary["totals"]["reachable_devices"], 1)
        self.assertEqual(
            [alert for alert in summary["alerts"] if alert["kind"] == "device_unreachable"], []
        )


if __name__ == "__main__":
    unittest.main()
