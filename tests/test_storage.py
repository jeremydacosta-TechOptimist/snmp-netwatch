"""Tests for SQLite persistence: schema, devices, samples, alerts, retention."""

from __future__ import annotations

import unittest

from netwatch.storage import Store, StoreError, parse_timestamp
from tests.helpers import StoreTestCase


def _sample_kwargs(clock, in_octets: int = 1000, out_octets: int = 500, **overrides):
    values = dict(
        sampled_at=clock.timestamp(),
        in_octets=in_octets,
        out_octets=out_octets,
        counter_bits=64,
        in_bps=800.0,
        out_bps=400.0,
        utilization_pct=0.8,
        oper_status=1,
    )
    values.update(overrides)
    return values


class SchemaTests(StoreTestCase):
    def test_schema_tables_and_version(self) -> None:
        self.assertEqual(
            self.store.table_names(), ["alerts", "devices", "interfaces", "samples"]
        )
        self.assertEqual(self.store.schema_version(), 1)

    def test_initialize_is_idempotent(self) -> None:
        self.store.initialize()
        self.assertEqual(self.store.schema_version(), 1)
        self.assertEqual(len(self.store.table_names()), 4)

    def test_foreign_keys_are_enforced(self) -> None:
        connection = self.store.connect()
        with self.assertRaises(Exception):
            connection.execute(
                "INSERT INTO interfaces (device_id, if_index, name, created_at, updated_at) "
                "VALUES (999, 1, 'x', 'now', 'now')"
            )

    def test_state_survives_reopen(self) -> None:
        device = self.store.upsert_device("192.0.2.10", name="edge")
        interface = self.store.upsert_interface(device.id, 1, "Ethernet0/1")
        self.store.record_sample(interface.id, **_sample_kwargs(self.clock))
        self.store.close()
        reopened = Store(self.db_path, clock=self.clock)
        self.addCleanup(reopened.close)
        reopened.initialize()
        self.assertEqual(reopened.list_devices()[0].address, "192.0.2.10")
        self.assertEqual(reopened.count_samples(), 1)


class DeviceTests(StoreTestCase):
    def test_upsert_device_insert_then_update(self) -> None:
        device = self.store.upsert_device("192.0.2.10", name="edge-1", community="public")
        self.assertTrue(device.reachable)
        self.assertEqual(device.name, "edge-1")
        self.clock.advance(1.0)
        updated = self.store.upsert_device("192.0.2.10", name="edge-1-renamed", community="lab")
        self.assertEqual(updated.id, device.id)
        self.assertEqual(updated.name, "edge-1-renamed")
        self.assertEqual(updated.community, "lab")
        self.assertEqual(len(self.store.list_devices()), 1)

    def test_upsert_device_empty_address_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert_device("   ")

    def test_device_status_updates(self) -> None:
        device = self.store.upsert_device("198.51.100.5")
        polled_at = self.clock.timestamp()
        self.store.update_device_status(device.id, reachable=False, error="timeout", polled_at=polled_at)
        stored = self.store.get_device("198.51.100.5")
        assert stored is not None
        self.assertFalse(stored.reachable)
        self.assertEqual(stored.last_error, "timeout")
        self.assertEqual(stored.last_polled_at, polled_at)
        self.store.update_device_status(device.id, reachable=True)
        stored = self.store.get_device("198.51.100.5")
        assert stored is not None
        self.assertTrue(stored.reachable)
        self.assertIsNone(stored.last_error)

    def test_get_device_missing_returns_none(self) -> None:
        self.assertIsNone(self.store.get_device("203.0.113.99"))
        self.assertIsNone(self.store.get_device_by_id(1234))

    def test_devices_are_sorted_by_address(self) -> None:
        self.store.upsert_device("203.0.113.9")
        self.store.upsert_device("192.0.2.1")
        self.assertEqual(
            [device.address for device in self.store.list_devices()],
            ["192.0.2.1", "203.0.113.9"],
        )


class InterfaceTests(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.device = self.store.upsert_device("192.0.2.10")

    def test_upsert_interface_insert_then_update(self) -> None:
        interface = self.store.upsert_interface(
            self.device.id, 1, "Ethernet0/1", alias="uplink", speed_bps=1_000_000_000
        )
        self.assertEqual(interface.if_index, 1)
        self.assertEqual(interface.speed_bps, 1_000_000_000)
        updated = self.store.upsert_interface(
            self.device.id, 1, "Ethernet0/1", alias="uplink-core", speed_bps=10_000_000_000
        )
        self.assertEqual(updated.id, interface.id)
        self.assertEqual(updated.alias, "uplink-core")
        self.assertEqual(updated.speed_bps, 10_000_000_000)

    def test_interface_unique_per_device(self) -> None:
        other = self.store.upsert_device("192.0.2.11")
        self.store.upsert_interface(self.device.id, 1, "a")
        self.store.upsert_interface(other.id, 1, "b")
        self.assertEqual(len(self.store.list_interfaces()), 2)
        self.assertEqual(len(self.store.list_interfaces(self.device.id)), 1)

    def test_interfaces_are_ordered(self) -> None:
        for index in (10, 2, 1):
            self.store.upsert_interface(self.device.id, index, f"if{index}")
        self.assertEqual(
            [interface.if_index for interface in self.store.list_interfaces(self.device.id)],
            [1, 2, 10],
        )

    def test_negative_index_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.store.upsert_interface(self.device.id, -1, "bad")

    def test_get_interface_by_id(self) -> None:
        interface = self.store.upsert_interface(self.device.id, 3, "Ethernet0/3")
        self.assertEqual(self.store.get_interface_by_id(interface.id), interface)
        self.assertIsNone(self.store.get_interface_by_id(9999))


class SampleTests(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        device = self.store.upsert_device("192.0.2.10")
        self.interface = self.store.upsert_interface(device.id, 1, "Ethernet0/1", speed_bps=1_000_000_000)
        self.other_interface = self.store.upsert_interface(device.id, 2, "Ethernet0/2")
        self.other_device = self.store.upsert_device("192.0.2.11")

    def test_record_and_latest_sample(self) -> None:
        sample = self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock))
        self.assertEqual(sample.in_octets, 1000)
        self.assertEqual(sample.out_octets, 500)
        self.assertEqual(sample.counter_bits, 64)
        self.assertEqual(self.store.latest_sample(self.interface.id), sample)

    def test_interface_samples_are_oldest_first_and_limited(self) -> None:
        for position in range(5):
            self.clock.advance(1.0)
            self.store.record_sample(
                self.interface.id,
                **_sample_kwargs(self.clock, in_octets=1000 + position),
            )
        samples = self.store.interface_samples(self.interface.id, limit=3)
        self.assertEqual([sample.in_octets for sample in samples], [1002, 1003, 1004])
        self.assertEqual(len(self.store.interface_samples(self.interface.id, limit=50)), 5)
        self.assertEqual(self.store.count_interface_samples(self.interface.id), 5)

    def test_sample_validation(self) -> None:
        with self.assertRaises(ValueError):
            self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock, counter_bits=48))
        with self.assertRaises(ValueError):
            self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock, in_octets=-1))
        with self.assertRaises(StoreError):
            self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock, sampled_at="not-a-date"))
        with self.assertRaises(ValueError):
            self.store.interface_samples(self.interface.id, limit=0)

    def test_counter_only_first_sample_has_no_rate(self) -> None:
        sample = self.store.record_sample(
            self.interface.id,
            **_sample_kwargs(
                self.clock, in_bps=None, out_bps=None, utilization_pct=None
            ),
        )
        self.assertIsNone(sample.in_bps)
        reloaded = self.store.latest_sample(self.interface.id)
        assert reloaded is not None
        self.assertIsNone(reloaded.utilization_pct)

    def test_retention_prunes_old_samples(self) -> None:
        self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock))
        self.clock.advance(7200.0)
        self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock))
        self.assertEqual(self.store.count_samples(), 2)
        removed = self.store.prune_samples(1.0, now=self.clock.utcnow())
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.count_samples(), 1)
        with self.assertRaises(ValueError):
            self.store.prune_samples(0)

    def test_reset_samples_for_one_device(self) -> None:
        self.store.record_sample(self.interface.id, **_sample_kwargs(self.clock))
        device_two = self.store.upsert_device("198.51.100.7")
        interface_two = self.store.upsert_interface(device_two.id, 1, "Gi0/1")
        self.store.record_sample(interface_two.id, **_sample_kwargs(self.clock))
        removed = self.store.reset_samples_for_device(self.other_device.id)
        self.assertEqual(removed, 0)
        removed = self.store.reset_samples_for_device(device_two.id)
        self.assertEqual(removed, 1)
        self.assertEqual(self.store.count_samples(), 1)


class AlertTests(StoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.device = self.store.upsert_device("192.0.2.10")
        self.interface = self.store.upsert_interface(self.device.id, 3, "Ethernet0/3")

    def test_record_alert_and_dedupe_active(self) -> None:
        alert = self.store.record_alert(
            self.device.id, "utilization", "warning", "high utilization",
            interface_id=self.interface.id, value=91.2, threshold=80.0,
        )
        duplicate = self.store.record_alert(
            self.device.id, "utilization", "warning", "high utilization again",
            interface_id=self.interface.id, value=93.0, threshold=80.0,
        )
        self.assertEqual(alert.id, duplicate.id)
        self.assertEqual(self.store.count_alerts(), 1)

    def test_resolve_alert_and_reopen(self) -> None:
        alert = self.store.record_alert(self.device.id, "unreachable", "critical", "down")
        self.assertTrue(alert.active)
        self.clock.advance(5.0)
        self.assertTrue(self.store.resolve_alert(alert.id))
        self.assertFalse(self.store.resolve_alert(alert.id))
        resolved = self.store.get_alert(alert.id)
        assert resolved is not None
        self.assertFalse(resolved.active)
        self.assertIsNotNone(resolved.resolved_at)
        revised = self.store.record_alert(self.device.id, "unreachable", "critical", "down again")
        self.assertNotEqual(revised.id, alert.id)
        self.assertEqual(self.store.count_alerts(active_only=True), 1)
        self.assertEqual(self.store.count_alerts(active_only=False), 2)

    def test_resolve_alerts_by_target_and_kind(self) -> None:
        second_interface = self.store.upsert_interface(self.device.id, 4, "Ethernet0/4")
        self.store.record_alert(self.device.id, "utilization", "warning", "one", interface_id=self.interface.id)
        self.store.record_alert(self.device.id, "utilization", "warning", "two", interface_id=second_interface.id)
        self.assertEqual(
            self.store.resolve_alerts(self.device.id, "utilization", self.interface.id), 1
        )
        self.assertEqual(self.store.count_alerts(active_only=True), 1)
        self.assertEqual(
            self.store.resolve_alerts(self.device.id, "utilization", second_interface.id), 1
        )
        self.assertEqual(self.store.count_alerts(active_only=True), 0)

    def test_device_level_and_interface_level_alerts_are_distinct(self) -> None:
        device_alert = self.store.record_alert(self.device.id, "device_unreachable", "critical", "down")
        interface_alert = self.store.record_alert(
            self.device.id, "device_unreachable", "critical", "down", interface_id=self.interface.id
        )
        self.assertNotEqual(device_alert.id, interface_alert.id)
        self.assertEqual(self.store.resolve_alerts(self.device.id, "device_unreachable", None), 1)
        self.assertEqual(self.store.count_alerts(active_only=True), 1)

    def test_list_alerts_ordering_and_limits(self) -> None:
        first = self.store.record_alert(self.device.id, "unreachable", "critical", "first")
        self.clock.advance(1.0)
        second = self.store.record_alert(self.device.id, "utilization", "warning", "second", interface_id=self.interface.id)
        active = self.store.list_alerts()
        self.assertEqual([alert.id for alert in active], [second.id, first.id])
        self.assertEqual(len(self.store.list_alerts(limit=1)), 1)
        self.store.resolve_alert(first.id)
        self.assertEqual([alert.id for alert in self.store.list_alerts(active_only=False)], [second.id, first.id])
        self.assertEqual([alert.id for alert in self.store.list_alerts(active_only=True)], [second.id])

    def test_invalid_alert_query_limits(self) -> None:
        with self.assertRaises(ValueError):
            self.store.list_alerts(limit=0)


class TimestampTests(unittest.TestCase):
    def test_naive_timestamp_is_treated_as_utc(self) -> None:
        parsed = parse_timestamp("2026-01-02T03:04:05")
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)
        self.assertEqual(parsed.isoformat(), "2026-01-02T03:04:05+00:00")

    def test_invalid_timestamp_raises_store_error(self) -> None:
        with self.assertRaises(StoreError):
            parse_timestamp("yesterday")

    def test_iso_milliseconds_parse(self) -> None:
        parsed = parse_timestamp("2026-11-16T16:53:47.123+00:00")
        self.assertEqual(parsed.microsecond, 123000)


if __name__ == "__main__":
    unittest.main()
