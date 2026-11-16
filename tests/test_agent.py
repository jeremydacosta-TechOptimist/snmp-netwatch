"""Tests for the built-in SNMPv2c agent simulator, over real UDP."""

from __future__ import annotations

import socket
import unittest

from netwatch.agent import SimulatedDevice, SimulatedInterface, SnmpAgent
from netwatch.ber import (
    TAG_COUNTER32,
    TAG_COUNTER64,
    TAG_END_OF_MIB_VIEW,
    TAG_GAUGE32,
    TAG_INTEGER,
    TAG_NO_SUCH_OBJECT,
    TAG_OCTET_STRING,
    TAG_TIMETICKS,
)
from netwatch.mib import (
    IF_ALIAS,
    IF_DESCR,
    IF_HC_IN_OCTETS,
    IF_IN_OCTETS,
    IF_NUMBER,
    IF_OPER_STATUS,
    IF_SPEED,
    SYS_DESCR,
    SYS_LOCATION,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_UPTIME,
)
from netwatch.snmp import (
    PDU_SET,
    SnmpClient,
    SnmpMessage,
    SnmpTimeoutError,
    VarBind,
)
from tests.helpers import AgentTestCase, start_agent


class AgentLifecycleTests(unittest.TestCase):
    def test_start_stop_and_address(self) -> None:
        agent, _device, host, port = start_agent()
        try:
            self.assertEqual(host, "127.0.0.1")
            self.assertGreater(port, 0)
            self.assertEqual(agent.address, (host, port))
            self.assertEqual(agent.port, port)
        finally:
            agent.stop()
        agent.stop()  # idempotent
        with self.assertRaises(RuntimeError):
            _ = agent.address

    def test_address_before_start_raises(self) -> None:
        agent = SnmpAgent(SimulatedDevice())
        with self.assertRaises(RuntimeError):
            _ = agent.address

    def test_double_start_raises(self) -> None:
        agent, _device, _host, _port = start_agent()
        try:
            with self.assertRaises(RuntimeError):
                agent.start()
        finally:
            agent.stop()


class AgentGetTests(AgentTestCase):
    def _client(self, community: str = "public", timeout: float = 1.0) -> SnmpClient:
        client = SnmpClient(self.host, self.port, community=community, timeout=timeout, retries=0)
        self.addCleanup(client.close)
        return client

    def test_get_system_scalars(self) -> None:
        varbinds = self._client().get([SYS_NAME, SYS_DESCR, SYS_UPTIME, SYS_LOCATION, IF_NUMBER])
        values = {varbind.oid: varbind for varbind in varbinds}
        self.assertEqual(values[SYS_NAME].tag, TAG_OCTET_STRING)
        self.assertEqual(values[SYS_NAME].value, b"simsw01.example")
        self.assertIn(b"NetWatch simulated", values[SYS_DESCR].value)
        self.assertEqual(values[SYS_UPTIME].tag, TAG_TIMETICKS)
        self.assertEqual(values[SYS_UPTIME].value, 0)
        self.assertEqual(values[SYS_LOCATION].value, b"Lab rack A1")
        self.assertEqual(values[IF_NUMBER].tag, TAG_INTEGER)
        self.assertEqual(values[IF_NUMBER].value, 3)

    def test_get_interface_columns_have_correct_types(self) -> None:
        varbinds = self._client().get(
            [
                IF_DESCR + ".1",
                IF_SPEED + ".1",
                IF_OPER_STATUS + ".1",
                IF_IN_OCTETS + ".1",
                IF_HC_IN_OCTETS + ".1",
                IF_ALIAS + ".2",
            ]
        )
        values = {varbind.oid: varbind for varbind in varbinds}
        self.assertEqual(values[IF_DESCR + ".1"].value, b"Ethernet0/1")
        self.assertEqual(values[IF_SPEED + ".1"].tag, TAG_GAUGE32)
        self.assertEqual(values[IF_SPEED + ".1"].value, 1_000_000_000)
        self.assertEqual(values[IF_OPER_STATUS + ".1"].tag, TAG_INTEGER)
        self.assertEqual(values[IF_OPER_STATUS + ".1"].value, 1)
        self.assertEqual(values[IF_IN_OCTETS + ".1"].tag, TAG_COUNTER32)
        self.assertLess(values[IF_IN_OCTETS + ".1"].value, 2**32)
        self.assertEqual(values[IF_HC_IN_OCTETS + ".1"].tag, TAG_COUNTER64)
        self.assertEqual(values[IF_ALIAS + ".2"].value, b"server-farm")

    def test_get_unknown_object_returns_exception(self) -> None:
        varbind = self._client().get(["1.3.6.1.2.1.99.1.0"])[0]
        self.assertEqual(varbind.tag, TAG_NO_SUCH_OBJECT)
        self.assertTrue(varbind.is_exception)

    def test_get_next_advances_lexicographically(self) -> None:
        varbind = self._client().get_next([SYS_DESCR])[0]
        self.assertEqual(varbind.oid, SYS_OBJECT_ID)
        varbind = self._client().get_next([SYS_OBJECT_ID])[0]
        self.assertEqual(varbind.oid, SYS_UPTIME)

    def test_get_next_at_end_of_mib(self) -> None:
        highest = f"{IF_ALIAS}.3"
        varbind = self._client().get_next([highest])[0]
        self.assertEqual(varbind.tag, TAG_END_OF_MIB_VIEW)

    def test_walk_columns(self) -> None:
        varbinds = self._client().walk(IF_DESCR)
        self.assertEqual(len(varbinds), 3)
        self.assertEqual([varbind.value for varbind in varbinds], [b"Ethernet0/1", b"Ethernet0/2", b"Ethernet0/3"])
        self.assertTrue(all(varbind.oid.startswith(IF_DESCR + ".") for varbind in varbinds))

    def test_get_bulk_non_repeaters_and_repetitions(self) -> None:
        varbinds = self._client().get_bulk(
            [SYS_NAME, IF_DESCR], non_repeaters=1, max_repetitions=2
        )
        self.assertEqual(len(varbinds), 3)
        self.assertEqual(varbinds[0].oid, SYS_LOCATION)
        self.assertEqual(varbinds[1].oid, IF_DESCR + ".1")
        self.assertEqual(varbinds[2].oid, IF_DESCR + ".2")

    def test_get_bulk_is_bounded(self) -> None:
        varbinds = self._client().get_bulk([SYS_NAME], max_repetitions=5000)
        self.assertGreater(len(varbinds), 0)
        self.assertLessEqual(len(varbinds), 1000)

    def test_wrong_community_is_ignored(self) -> None:
        client = self._client(community="private", timeout=0.2)
        with self.assertRaises(SnmpTimeoutError):
            client.get([SYS_NAME])
        self.assertGreaterEqual(self.agent.rejected_community, 1)

    def test_malformed_datagram_is_counted_and_ignored(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.sendto(b"\x30\x00garbage", (self.host, self.port))
        response = self._client().get([SYS_NAME])
        self.assertEqual(response[0].value, b"simsw01.example")
        self.assertGreaterEqual(self.agent.malformed_packets, 1)

    def test_set_request_returns_not_writable(self) -> None:
        request = SnmpMessage(
            community="public",
            pdu_type=PDU_SET,
            request_id=4242,
            varbinds=[VarBind(SYS_NAME, TAG_OCTET_STRING, b"hacked")],
        )
        response = self._client().request(request)
        self.assertEqual(response.pdu_type, 0xA2)
        self.assertEqual(response.error_status, 17)
        self.assertEqual(response.request_id, 4242)


class AgentCounterTests(AgentTestCase):
    def _client(self) -> SnmpClient:
        client = SnmpClient(self.host, self.port, timeout=1.0, retries=0)
        self.addCleanup(client.close)
        return client

    def test_counters_grow_monotonically_and_match_the_model(self) -> None:
        client = self._client()
        first = client.get([IF_HC_IN_OCTETS + ".1"])[0].value
        self.agent_clock.advance(10.0)
        second = client.get([IF_HC_IN_OCTETS + ".1"])[0].value
        modelled_in, _modelled_out = self.device.counters()[1]
        self.assertEqual(second, modelled_in)
        self.assertGreater(second, first)
        rate_bps = (second - first) * 8.0 / 10.0
        interface = self.device.interfaces[0]
        low = interface.speed_bps * (interface.in_utilization - interface.swing)
        high = interface.speed_bps * (interface.in_utilization + interface.swing)
        self.assertGreaterEqual(rate_bps, low)
        self.assertLessEqual(rate_bps, high)

    def test_sysuptime_advances_with_clock(self) -> None:
        client = self._client()
        self.assertEqual(client.get([SYS_UPTIME])[0].value, 0)
        self.agent_clock.advance(5.0)
        self.assertEqual(client.get([SYS_UPTIME])[0].value, 500)

    def test_hc_counters_can_be_disabled(self) -> None:
        agent, _device, host, port = start_agent(support_hc_counters=False)
        self.addCleanup(agent.stop)
        with SnmpClient(host, port, timeout=1.0, retries=0) as client:
            self.assertEqual(client.get([IF_HC_IN_OCTETS + ".1"])[0].tag, TAG_NO_SUCH_OBJECT)
            varbind = client.get([IF_IN_OCTETS + ".1"])[0]
            self.assertEqual(varbind.tag, TAG_COUNTER32)


class AgentResponseTests(AgentTestCase):
    def test_getbulk_repetition_ordering(self) -> None:
        request = SnmpMessage.get_bulk(
            "public", 1, [IF_DESCR, IF_OPER_STATUS], non_repeaters=0, max_repetitions=2
        )
        response = self.agent.build_response(request)
        self.assertIsNotNone(response)
        oids = [varbind.oid for varbind in response.varbinds]
        self.assertEqual(
            oids,
            [
                IF_DESCR + ".1",
                IF_OPER_STATUS + ".1",
                IF_DESCR + ".2",
                IF_OPER_STATUS + ".2",
            ],
        )

    def test_getbulk_end_of_mib_view_is_repeated(self) -> None:
        highest = f"{IF_ALIAS}.3"
        request = SnmpMessage.get_bulk("public", 1, [highest], max_repetitions=2)
        response = self.agent.build_response(request)
        self.assertIsNotNone(response)
        self.assertEqual(len(response.varbinds), 2)
        self.assertTrue(all(varbind.tag == TAG_END_OF_MIB_VIEW for varbind in response.varbinds))

    def test_get_unknown_wrong_community_direct_response(self) -> None:
        request = SnmpMessage.get("public", 8, [SYS_NAME])
        response = self.agent.build_response(request)
        self.assertEqual(response.request_id, 8)
        self.assertEqual(response.community, "public")


class SimulatorValidationTests(unittest.TestCase):
    def test_interface_validation(self) -> None:
        with self.assertRaises(ValueError):
            SimulatedInterface(index=0, name="bad", alias="", speed_bps=1000)
        with self.assertRaises(ValueError):
            SimulatedInterface(index=1, name="bad", alias="", speed_bps=1000, oper_status=99)
        with self.assertRaises(ValueError):
            SimulatedInterface(
                index=1, name="bad", alias="", speed_bps=1000, in_utilization=0.1, swing=0.5
            )

    def test_duplicate_interface_index_is_rejected(self) -> None:
        interfaces = [
            SimulatedInterface(index=1, name="a", alias="", speed_bps=1000),
            SimulatedInterface(index=1, name="b", alias="", speed_bps=1000),
        ]
        with self.assertRaises(ValueError):
            SimulatedDevice(interfaces=interfaces)


if __name__ == "__main__":
    unittest.main()
