"""Tests for rate computation and the polling engine against a real simulator."""

from __future__ import annotations

import unittest

from netwatch.agent import SimulatedDevice, SimulatedInterface, SnmpAgent
from netwatch.alerting import KIND_OPER_DOWN, KIND_UNREACHABLE, KIND_UTILIZATION, Thresholds
from netwatch.clock import FixedClock
from netwatch.poller import Poller, compute_rates, counter_delta, parse_endpoint
from netwatch.storage import Store
from tests.helpers import StoreTestCase, unused_ports


class CounterDeltaTests(unittest.TestCase):
    def test_regular_increase(self) -> None:
        self.assertEqual(counter_delta(1500, 1000, 32), 500)

    def test_counter32_wrap(self) -> None:
        self.assertEqual(counter_delta(500, 2**32 - 1000, 32), 1500)

    def test_counter64_range(self) -> None:
        self.assertEqual(counter_delta(2**63, 2**63 - 5, 64), 5)

    def test_invalid_counter_width(self) -> None:
        with self.assertRaises(ValueError):
            counter_delta(1, 0, 48)

    def test_out_of_range_counters_rejected(self) -> None:
        with self.assertRaises(ValueError):
            counter_delta(2**32, 0, 32)
        with self.assertRaises(ValueError):
            counter_delta(1, -1, 32)


class RateComputationTests(unittest.TestCase):
    def test_standard_interval(self) -> None:
        in_bps, out_bps, utilization = compute_rates(
            in_octets=1_250_000,
            out_octets=625_000,
            previous_in_octets=0,
            previous_out_octets=0,
            elapsed_seconds=10.0,
            speed_bps=10_000_000,
            counter_bits=64,
        )
        self.assertEqual(in_bps, 1_000_000.0)
        self.assertEqual(out_bps, 500_000.0)
        self.assertAlmostEqual(utilization or 0.0, 10.0)

    def test_utilization_uses_busier_direction(self) -> None:
        # 2 MB in 10 s = 1.6 Mbps on a 1 Mbps link: utilization can exceed 100%.
        _in, _out, utilization = compute_rates(2_000_000, 100, 0, 0, 10.0, 1_000_000)
        self.assertAlmostEqual(utilization or 0.0, 160.0)

    def test_unknown_speed_produces_no_utilization(self) -> None:
        in_bps, out_bps, utilization = compute_rates(1000, 500, 0, 0, 1.0, None)
        self.assertGreater(in_bps or 0.0, 0.0)
        self.assertGreater(out_bps or 0.0, 0.0)
        self.assertIsNone(utilization)

    def test_zero_interval_has_no_rates(self) -> None:
        self.assertEqual(compute_rates(1000, 500, 0, 0, 0.0, 1_000_000), (None, None, None))

    def test_counter32_wrap_is_handled(self) -> None:
        in_bps, _out_bps, _util = compute_rates(
            in_octets=500,
            out_octets=0,
            previous_in_octets=2**32 - 1000,
            previous_out_octets=0,
            elapsed_seconds=10.0,
            speed_bps=1_000_000,
            counter_bits=32,
        )
        self.assertEqual(in_bps, 1200.0)

    def test_counter64_reset_yields_no_rate(self) -> None:
        self.assertEqual(
            compute_rates(500, 0, 10**9, 0, 10.0, 1_000_000, counter_bits=64),
            (None, None, None),
        )


class EndpointParsingTests(unittest.TestCase):
    def test_default_port(self) -> None:
        self.assertEqual(parse_endpoint("192.0.2.10"), ("192.0.2.10", 161))

    def test_explicit_port(self) -> None:
        self.assertEqual(parse_endpoint("192.0.2.10:1161"), ("192.0.2.10", 1161))

    def test_hostname(self) -> None:
        self.assertEqual(parse_endpoint("lab-sw01.example:2161"), ("lab-sw01.example", 2161))

    def test_invalid_values(self) -> None:
        for value in ("", "   ", ":161", "host:0", "host:70000"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_endpoint(value)


class PollerTestCase(StoreTestCase):
    """Store plus a simulator whose clock is advanced together with the poll clock."""

    def setUp(self) -> None:
        super().setUp()
        self.agent_clock = FixedClock(start=self.clock.now())
        self.device = SimulatedDevice(clock=self.agent_clock)
        self.agent = SnmpAgent(self.device, host="127.0.0.1", port=0)
        self.host, self.port = self.agent.start()
        self.addCleanup(self.agent.stop)
        self.thresholds = Thresholds(utilization_pct=80.0)

    def make_poller(self, **kwargs) -> Poller:
        return Poller(self.store, self.thresholds, clock=self.clock, **kwargs)

    def poll(self, **kwargs):
        poller = self.make_poller()
        return poller.poll("simulator", host=self.host, port=self.port, **kwargs)

    def advance(self, seconds: float) -> None:
        self.clock.advance(seconds)
        self.agent_clock.advance(seconds)


class PollerIntegrationTests(PollerTestCase):
    def test_first_poll_discovers_interfaces_without_rates(self) -> None:
        result = self.poll()
        self.assertTrue(result.reachable)
        self.assertEqual(result.name, "simsw01.example")
        self.assertEqual(len(result.interfaces), 3)
        self.assertTrue(all(reading.in_bps is None for reading in result.interfaces))
        self.assertTrue(all(reading.counter_bits == 64 for reading in result.interfaces))
        self.assertEqual(self.store.count_samples(), 3)
        stored = self.store.get_device("simulator")
        assert stored is not None
        self.assertTrue(stored.reachable)

    def test_second_poll_computes_rates_and_utilization(self) -> None:
        self.poll()
        self.advance(10.0)
        result = self.poll()
        reading = result.interfaces[0]
        self.assertIsNotNone(reading.in_bps)
        self.assertIsNotNone(reading.utilization_pct)
        interface = self.device.interfaces[0]
        low = interface.speed_bps * (interface.in_utilization - interface.swing)
        high = interface.speed_bps * (interface.in_utilization + interface.swing)
        self.assertGreaterEqual(reading.in_bps or 0.0, low)
        self.assertLessEqual(reading.in_bps or 0.0, high)
        self.assertGreater(reading.utilization_pct or 0.0, 0.0)
        self.assertLess(reading.utilization_pct or 0.0, 100.0)

    def test_stored_counters_match_the_agent(self) -> None:
        self.poll()
        self.advance(7.0)
        self.poll()
        interface = self.store.get_interface(
            self.store.get_device("simulator").id, 1  # type: ignore[union-attr]
        )
        assert interface is not None
        sample = self.store.latest_sample(interface.id)
        assert sample is not None
        modelled_in, modelled_out = self.device.counters()[1]
        self.assertEqual(sample.in_octets, modelled_in)
        self.assertEqual(sample.out_octets, modelled_out)
        self.assertEqual(sample.counter_bits, 64)
        self.assertGreater(sample.in_bps or 0.0, 0.0)

    def test_oper_down_alert_opens_and_resolves(self) -> None:
        self.poll()
        active = [alert for alert in self.store.list_alerts() if alert.kind == KIND_OPER_DOWN]
        self.assertEqual(len(active), 1)
        self.assertIn("Ethernet0/3", active[0].message)
        self.assertEqual(active[0].severity, "critical")
        # Bring every interface up: the open alert must be resolved on the next poll.
        self.device.interfaces = [
            SimulatedInterface(
                index=index,
                name=name,
                alias=alias,
                speed_bps=1_000_000_000,
                oper_status=1,
                in_utilization=0.1,
                out_utilization=0.05,
                swing=0.02,
            )
            for index, name, alias in (
                (1, "Ethernet0/1", "uplink-core"),
                (2, "Ethernet0/2", "server-farm"),
                (3, "Ethernet0/3", "spare"),
            )
        ]
        self.advance(10.0)
        self.poll()
        self.assertEqual(self.store.count_alerts(active_only=True), 0)
        self.assertEqual(self.store.count_alerts(active_only=False), 1)

    def test_low_threshold_opens_utilization_alert_and_high_resolves(self) -> None:
        self.poll()
        self.advance(10.0)
        low = Poller(self.store, Thresholds(utilization_pct=5.0), clock=self.clock)
        low.poll("simulator", host=self.host, port=self.port)
        utilization_alerts = [
            alert for alert in self.store.list_alerts() if alert.kind == KIND_UTILIZATION
        ]
        self.assertGreaterEqual(len(utilization_alerts), 1)
        self.advance(10.0)
        high = Poller(self.store, Thresholds(utilization_pct=99.0), clock=self.clock)
        high.poll("simulator", host=self.host, port=self.port)
        remaining = [
            alert
            for alert in self.store.list_alerts()
            if alert.kind == KIND_UTILIZATION
        ]
        self.assertEqual(remaining, [])

    def test_vanished_interface_alerts_are_resolved(self) -> None:
        self.poll()
        self.assertEqual(
            len([alert for alert in self.store.list_alerts() if alert.kind == KIND_OPER_DOWN]), 1
        )
        self.device.interfaces = self.device.interfaces[:2]
        self.advance(10.0)
        self.poll()
        self.assertEqual(self.store.count_alerts(active_only=True), 0)

    def test_interface_metadata_is_stored(self) -> None:
        self.poll()
        device = self.store.get_device("simulator")
        assert device is not None
        interfaces = self.store.list_interfaces(device.id)
        self.assertEqual([interface.name for interface in interfaces], ["Ethernet0/1", "Ethernet0/2", "Ethernet0/3"])
        self.assertEqual(interfaces[0].alias, "uplink-core")
        self.assertEqual(interfaces[0].speed_bps, 1_000_000_000)

    def test_hc_absent_falls_back_to_counter32(self) -> None:
        self.store.close()
        store = Store(self.db_path, clock=self.clock)
        self.store = store  # let cleanup close the new store too
        self.addCleanup(store.close)
        store.initialize()
        device = SimulatedDevice(clock=self.agent_clock, support_hc_counters=False)
        agent = SnmpAgent(device, host="127.0.0.1", port=0)
        host, port = agent.start()
        self.addCleanup(agent.stop)
        poller = Poller(store, self.thresholds, clock=self.clock)
        poller.poll("simulator", host=host, port=port)
        self.advance(10.0)
        result = poller.poll("simulator", host=host, port=port)
        self.assertEqual(result.interfaces[0].counter_bits, 32)
        self.assertGreater(result.interfaces[0].in_bps or 0.0, 0.0)
        stored = store.latest_sample(
            store.get_interface(store.get_device("simulator").id, 1).id  # type: ignore[union-attr]
        )
        assert stored is not None
        self.assertEqual(stored.in_octets, device.counters()[1][0] % 2**32)

    def test_unreachable_device_and_recovery(self) -> None:
        closed_port = unused_ports()[0]
        poller = self.make_poller(timeout=0.2, retries=0)
        result = poller.poll("192.0.2.50", host="127.0.0.1", port=closed_port)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)
        stored = self.store.get_device("192.0.2.50")
        assert stored is not None
        self.assertFalse(stored.reachable)
        unreachable = [alert for alert in self.store.list_alerts() if alert.kind == KIND_UNREACHABLE]
        self.assertEqual(len(unreachable), 1)
        # The same labelled device becomes reachable at a working endpoint.
        recovered = poller.poll("192.0.2.50", host=self.host, port=self.port)
        self.assertTrue(recovered.reachable)
        remaining = [alert for alert in self.store.list_alerts() if alert.kind == KIND_UNREACHABLE]
        self.assertEqual(remaining, [])
        stored = self.store.get_device("192.0.2.50")
        assert stored is not None
        self.assertTrue(stored.reachable)

    def test_poll_defaults_host_to_address(self) -> None:
        poller = self.make_poller()
        result = poller.poll("127.0.0.1", port=self.port)
        self.assertTrue(result.reachable)

    def test_poll_reports_duration_and_sysinfo(self) -> None:
        result = self.poll()
        self.assertGreaterEqual(result.duration_ms, 0)
        self.assertEqual(result.uptime_seconds, 0.0)
        self.assertIn("NetWatch simulated", result.sys_descr or "")

    def test_poll_uses_named_device_rows(self) -> None:
        result = self.poll(name="override-name")
        self.assertEqual(result.name, "simsw01.example")  # sysName wins after the first poll
        device = self.store.get_device("simulator")
        assert device is not None
        self.assertEqual(device.name, "simsw01.example")


if __name__ == "__main__":
    unittest.main()
