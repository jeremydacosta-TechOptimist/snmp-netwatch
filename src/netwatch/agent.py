"""Built-in SNMPv2c agent simulator for local demonstrations and tests.

The simulator exposes a small interface MIB (system group plus the IF-MIB
interface table and high-capacity counters) over a localhost UDP socket and
answers GET, GETNEXT and GETBULK requests the way an SNMPv2c agent should,
including the v2c exception values ``noSuchObject`` and ``endOfMibView``.

Counter growth is analytic rather than random: each interface has a utilisation
profile made of a constant load plus a slow sinusoidal variation, so
``ifInOctets`` / ``ifOutOctets`` grow monotonically and reproducible rates can
be computed from two polls. Tests inject a :class:`~netwatch.clock.FixedClock`
to make those counters fully deterministic.
"""

from __future__ import annotations

import math
import socket
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .ber import (
    TAG_COUNTER32,
    TAG_COUNTER64,
    TAG_END_OF_MIB_VIEW,
    TAG_GAUGE32,
    TAG_INTEGER,
    TAG_NO_SUCH_OBJECT,
    TAG_OCTET_STRING,
    TAG_OID,
    TAG_TIMETICKS,
)
from .clock import Clock, SystemClock
from .mib import (
    IF_ADMIN_STATUS,
    IF_ALIAS,
    IF_DESCR,
    IF_HIGH_SPEED,
    IF_HC_IN_OCTETS,
    IF_HC_OUT_OCTETS,
    IF_INDEX,
    IF_IN_ERRORS,
    IF_IN_OCTETS,
    IF_NAME,
    IF_NUMBER,
    IF_OPER_STATUS,
    IF_OUT_ERRORS,
    IF_OUT_OCTETS,
    IF_SPEED,
    IF_TYPE,
    OPER_STATUS_TEXT,
    SYS_CONTACT,
    SYS_DESCR,
    SYS_LOCATION,
    SYS_NAME,
    SYS_OBJECT_ID,
    SYS_SERVICES,
    SYS_UPTIME,
)
from .oid import oid_key, parse_oid
from .snmp import (
    PDU_GET,
    PDU_GETBULK,
    PDU_GETNEXT,
    PDU_RESPONSE,
    PDU_SET,
    SnmpError,
    SnmpMessage,
    VarBind,
)

__all__ = ["SimulatedInterface", "SimulatedDevice", "SnmpAgent", "default_interfaces"]

_SYS_SERVICES_VALUE = 72  # application + internet layers (RFC 3418 example value)
_MAX_BULK_VALUES = 1000


@dataclass(frozen=True)
class SimulatedInterface:
    """Configuration of one virtual interface exposed by the simulator."""

    index: int
    name: str
    alias: str
    speed_bps: int
    oper_status: int = 1
    admin_status: int = 1
    in_utilization: float = 0.15
    out_utilization: float = 0.10
    swing: float = 0.04
    period_s: float = 45.0
    phase: float = 0.0
    initial_in_octets: int = 1_000_000
    initial_out_octets: int = 800_000

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or self.index < 1:
            raise ValueError(f"interface index must be a positive integer, got {self.index!r}")
        if self.speed_bps <= 0:
            raise ValueError(f"interface {self.name}: speed_bps must be positive")
        if self.oper_status not in OPER_STATUS_TEXT:
            raise ValueError(f"interface {self.name}: invalid ifOperStatus {self.oper_status}")
        if self.admin_status not in (1, 2):
            raise ValueError(f"interface {self.name}: invalid ifAdminStatus {self.admin_status}")
        for label, utilization in (
            ("in_utilization", self.in_utilization),
            ("out_utilization", self.out_utilization),
        ):
            if not 0.0 <= utilization <= 1.0:
                raise ValueError(f"interface {self.name}: {label} must be within [0, 1]")
        if not 0.0 <= self.swing <= min(self.in_utilization, self.out_utilization):
            raise ValueError(
                f"interface {self.name}: swing must be within [0, min(in, out)] to keep counters monotonic"
            )
        if self.period_s <= 0:
            raise ValueError(f"interface {self.name}: period_s must be positive")
        if self.initial_in_octets < 0 or self.initial_out_octets < 0:
            raise ValueError(f"interface {self.name}: initial counters cannot be negative")


def default_interfaces() -> List[SimulatedInterface]:
    """Return the three virtual interfaces shown in the demo dashboard."""

    return [
        SimulatedInterface(
            index=1,
            name="Ethernet0/1",
            alias="uplink-core",
            speed_bps=1_000_000_000,
            oper_status=1,
            in_utilization=0.18,
            out_utilization=0.09,
            swing=0.04,
            period_s=45.0,
            phase=0.0,
        ),
        SimulatedInterface(
            index=2,
            name="Ethernet0/2",
            alias="server-farm",
            speed_bps=1_000_000_000,
            oper_status=1,
            in_utilization=0.32,
            out_utilization=0.27,
            swing=0.07,
            period_s=60.0,
            phase=1.7,
        ),
        SimulatedInterface(
            index=3,
            name="Ethernet0/3",
            alias="spare",
            speed_bps=100_000_000,
            oper_status=2,
            in_utilization=0.0,
            out_utilization=0.0,
            swing=0.0,
            period_s=30.0,
            phase=0.3,
        ),
    ]


def _traffic_octets(
    initial: int,
    average_bps: float,
    swing_bps: float,
    period_s: float,
    phase: float,
    elapsed_s: float,
) -> int:
    """Integrate a sinusoidal bit rate into a monotonic octet counter.

    The rate is ``average + swing * sin(2*pi*t/period + phase)`` bits per
    second; integrating it analytically keeps the counter smooth and strictly
    non-decreasing as long as ``swing <= average``.
    """

    average_bytes = average_bps / 8.0
    if swing_bps <= 0.0:
        return int(round(initial + average_bytes * elapsed_s))
    swing_bytes = swing_bps / 8.0
    omega = 2.0 * math.pi / period_s
    offset = initial + (swing_bytes / omega) * math.cos(phase)
    return int(round(average_bytes * elapsed_s - (swing_bytes / omega) * math.cos(omega * elapsed_s + phase) + offset))


class SimulatedDevice:
    """State behind :class:`SnmpAgent`: system group values and counter model."""

    def __init__(
        self,
        name: str = "simsw01.example",
        description: str = "NetWatch simulated SNMPv2c agent, model NS-24, firmware 1.0",
        location: str = "Lab rack A1",
        contact: str = "noc@example.net",
        object_id: str = "1.3.6.1.4.1.32473.1.1",
        interfaces: Optional[Sequence[SimulatedInterface]] = None,
        clock: Optional[Clock] = None,
        support_hc_counters: bool = True,
    ) -> None:
        self.name = name
        self.description = description
        self.location = location
        self.contact = contact
        self.object_id = object_id
        self.interfaces: List[SimulatedInterface] = list(interfaces) if interfaces else default_interfaces()
        seen: set[int] = set()
        for interface in self.interfaces:
            if interface.index in seen:
                raise ValueError(f"duplicate interface index {interface.index}")
            seen.add(interface.index)
        self.clock = clock or SystemClock()
        self.support_hc_counters = support_hc_counters
        self._started_at = self.clock.now()

    def elapsed_seconds(self) -> float:
        """Seconds of simulated uptime."""

        return max(0.0, self.clock.now() - self._started_at)

    def uptime_ticks(self) -> int:
        """sysUpTime in hundredths of a second."""

        return int(self.elapsed_seconds() * 100)

    def counters(self) -> Dict[int, Tuple[int, int]]:
        """Return ``{ifIndex: (in_octets, out_octets)}`` 64-bit counters."""

        elapsed = self.elapsed_seconds()
        result: Dict[int, Tuple[int, int]] = {}
        for interface in self.interfaces:
            average_in = interface.speed_bps * interface.in_utilization
            average_out = interface.speed_bps * interface.out_utilization
            swing = interface.speed_bps * interface.swing
            in_octets = _traffic_octets(
                interface.initial_in_octets,
                average_in,
                swing,
                interface.period_s,
                interface.phase,
                elapsed,
            )
            out_octets = _traffic_octets(
                interface.initial_out_octets,
                average_out,
                swing,
                interface.period_s,
                interface.phase + 1.0,
                elapsed,
            )
            result[interface.index] = (max(0, in_octets), max(0, out_octets))
        return result

    def mib(self) -> Dict[str, VarBind]:
        """Build the complete MIB as ``{oid: VarBind}`` for the current instant."""

        values: Dict[str, VarBind] = {}

        def put(oid: str, tag: int, value: Any) -> None:
            values[oid] = VarBind(oid=oid, tag=tag, value=value)

        put(SYS_DESCR, TAG_OCTET_STRING, self.description)
        put(SYS_OBJECT_ID, TAG_OID, self.object_id)
        put(SYS_UPTIME, TAG_TIMETICKS, self.uptime_ticks())
        put(SYS_CONTACT, TAG_OCTET_STRING, self.contact)
        put(SYS_NAME, TAG_OCTET_STRING, self.name)
        put(SYS_LOCATION, TAG_OCTET_STRING, self.location)
        put(SYS_SERVICES, TAG_INTEGER, _SYS_SERVICES_VALUE)
        put(IF_NUMBER, TAG_INTEGER, len(self.interfaces))
        counters = self.counters()
        for interface in self.interfaces:
            suffix = f".{interface.index}"
            in_octets, out_octets = counters[interface.index]
            put(IF_INDEX + suffix, TAG_INTEGER, interface.index)
            put(IF_DESCR + suffix, TAG_OCTET_STRING, interface.name)
            put(IF_TYPE + suffix, TAG_INTEGER, 6)  # ethernetCsmacd
            put(IF_SPEED + suffix, TAG_GAUGE32, interface.speed_bps)
            put(IF_ADMIN_STATUS + suffix, TAG_INTEGER, interface.admin_status)
            put(IF_OPER_STATUS + suffix, TAG_INTEGER, interface.oper_status)
            put(IF_IN_OCTETS + suffix, TAG_COUNTER32, in_octets % 2**32)
            put(IF_OUT_OCTETS + suffix, TAG_COUNTER32, out_octets % 2**32)
            put(IF_IN_ERRORS + suffix, TAG_COUNTER32, 0)
            put(IF_OUT_ERRORS + suffix, TAG_COUNTER32, 0)
            put(IF_NAME + suffix, TAG_OCTET_STRING, interface.name)
            put(IF_ALIAS + suffix, TAG_OCTET_STRING, interface.alias)
            put(IF_HIGH_SPEED + suffix, TAG_GAUGE32, max(1, interface.speed_bps // 1_000_000))
            if self.support_hc_counters:
                put(IF_HC_IN_OCTETS + suffix, TAG_COUNTER64, in_octets % 2**64)
                put(IF_HC_OUT_OCTETS + suffix, TAG_COUNTER64, out_octets % 2**64)
        return values


class SnmpAgent:
    """Threaded localhost UDP agent that answers SNMPv2c requests."""

    def __init__(
        self,
        device: Optional[SimulatedDevice] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        community: str = "public",
    ) -> None:
        self.device = device or SimulatedDevice()
        self.host = host
        self.requested_port = int(port)
        self.community = community
        self.requests_handled = 0
        self.malformed_packets = 0
        self.rejected_community = 0
        self._socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._mib_order: Optional[List[str]] = None
        self._mib_order_keys: Optional[Tuple[str, ...]] = None

    def __enter__(self) -> "SnmpAgent":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()

    def start(self) -> Tuple[str, int]:
        """Bind the UDP socket, start the serving thread and return the address."""

        if self._socket is not None:
            raise RuntimeError("agent is already running")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((self.host, self.requested_port))
        except OSError:
            sock.close()
            raise
        sock.settimeout(0.1)
        self._socket = sock
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._serve, name="netwatch-sim-agent", daemon=True)
        self._thread.start()
        return self.address

    @property
    def address(self) -> Tuple[str, int]:
        """Bound ``(host, port)`` tuple; available after :meth:`start`."""

        if self._socket is None:
            raise RuntimeError("agent is not running")
        host, port = self._socket.getsockname()
        return str(host), int(port)

    @property
    def port(self) -> int:
        """Bound UDP port (useful when the agent asked for port 0)."""

        return self.address[1]

    def stop(self) -> None:
        """Stop the serving thread and close the socket; safe to call twice."""

        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        if self._socket is not None:
            try:
                self._socket.close()
            finally:
                self._socket = None

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            sock = self._socket
            if sock is None:
                return
            try:
                data, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.handle_datagram(data, address)

    def handle_datagram(self, data: bytes, address: Tuple[str, int]) -> None:
        """Decode one datagram and send the response, ignoring malformed input."""

        try:
            request = SnmpMessage.decode(data)
        except SnmpError:
            self.malformed_packets += 1
            return
        if request.community != self.community:
            self.rejected_community += 1
            return
        response = self.build_response(request)
        if response is None:
            return
        sock = self._socket
        if sock is None:
            return
        try:
            sock.sendto(response.encode(), address)
        except OSError:
            return
        self.requests_handled += 1

    def build_response(self, request: SnmpMessage) -> Optional[SnmpMessage]:
        """Build the RESPONSE for ``request`` (public for direct unit testing)."""

        if request.pdu_type == PDU_GET:
            varbinds = [self._get_one(varbind.oid) for varbind in request.varbinds]
        elif request.pdu_type == PDU_GETNEXT:
            varbinds = [self._get_next(varbind.oid) for varbind in request.varbinds]
        elif request.pdu_type == PDU_GETBULK:
            varbinds = self._get_bulk(
                request.varbinds,
                non_repeaters=request.non_repeaters,
                max_repetitions=request.max_repetitions,
            )
        elif request.pdu_type == PDU_SET:
            return SnmpMessage(
                community=self.community,
                pdu_type=PDU_RESPONSE,
                request_id=request.request_id,
                error_status=17,  # notWritable: the simulator exposes a read-only MIB
                error_index=1 if request.varbinds else 0,
                varbinds=list(request.varbinds),
            )
        else:
            return None
        return SnmpMessage(
            community=self.community,
            pdu_type=PDU_RESPONSE,
            request_id=request.request_id,
            varbinds=varbinds,
        )

    def _mib(self) -> Dict[str, VarBind]:
        return self.device.mib()

    def _sorted_mib_oids(self, mib: Dict[str, VarBind]) -> List[str]:
        keys = tuple(mib.keys())
        if self._mib_order is None or self._mib_order_keys != keys:
            self._mib_order = sorted(keys, key=oid_key)
            self._mib_order_keys = keys
        return self._mib_order

    def _get_one(self, oid: str) -> VarBind:
        value = self._mib().get(oid)
        if value is None:
            return VarBind(oid=oid, tag=TAG_NO_SUCH_OBJECT)
        return value

    def _get_next(self, oid: str) -> VarBind:
        mib = self._mib()
        requested = oid_key(oid)
        order = self._sorted_mib_oids(mib)
        position = _bisect_right(order, requested)
        if position >= len(order):
            return VarBind(oid=oid, tag=TAG_END_OF_MIB_VIEW)
        return mib[order[position]]

    def _get_bulk(
        self, varbinds: Sequence[VarBind], non_repeaters: int, max_repetitions: int
    ) -> List[VarBind]:
        repeaters = len(varbinds) - max(0, min(non_repeaters, len(varbinds)))
        max_repetitions = max(0, min(max_repetitions, _MAX_BULK_VALUES // max(1, repeaters)))
        results: List[VarBind] = [self._get_next(varbind.oid) for varbind in varbinds[:non_repeaters]]
        cursors = [varbind.oid for varbind in varbinds[non_repeaters:]]
        ended = [False] * len(cursors)
        for _row in range(max_repetitions):
            for position, cursor in enumerate(cursors):
                if ended[position]:
                    results.append(VarBind(oid=cursor, tag=TAG_END_OF_MIB_VIEW))
                    continue
                next_varbind = self._get_next(cursor)
                results.append(next_varbind)
                if next_varbind.is_exception:
                    ended[position] = True
                else:
                    cursors[position] = next_varbind.oid
            if len(results) >= _MAX_BULK_VALUES:
                break
        return results


def _bisect_right(ordered_oids: Sequence[str], requested: tuple) -> int:
    """Return the first index whose OID is greater than ``requested``."""

    low, high = 0, len(ordered_oids)
    while low < high:
        middle = (low + high) // 2
        if parse_oid(ordered_oids[middle]) <= requested:
            low = middle + 1
        else:
            high = middle
    return low
