"""Polling engine: discover interfaces, compute rates, persist history and alerts.

A poll performs one GET for the system group, then GETNEXT walks for the
IF-MIB columns. High-capacity counters (ifHCInOctets/ifHCOutOctets, Counter64)
are preferred when the agent publishes them, otherwise the 32-bit
ifInOctets/ifOutOctets counters are used and classic counter wrap is handled.
Rates and utilization are computed from the delta against the previous stored
sample, so the first poll of a device records counters without a rate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

from .alerting import (
    KIND_OPER_DOWN,
    KIND_UNREACHABLE,
    KIND_UTILIZATION,
    Thresholds,
    evaluate_interface,
    evaluate_unreachable,
)
from .clock import Clock, SystemClock
from .mib import (
    IF_ALIAS,
    IF_DESCR,
    IF_HC_IN_OCTETS,
    IF_HC_OUT_OCTETS,
    IF_IN_OCTETS,
    IF_OPER_STATUS,
    IF_OUT_OCTETS,
    IF_SPEED,
    SYS_DESCR,
    SYS_NAME,
    SYS_UPTIME,
    oper_status_text,
)
from .oid import OidError, child_index
from .snmp import SnmpClient, SnmpError, VarBind
from .storage import Device, Store, parse_timestamp

__all__ = [
    "InterfaceReading",
    "PollResult",
    "counter_delta",
    "compute_rates",
    "Poller",
    "parse_endpoint",
]


@dataclass
class InterfaceReading:
    """One interface sampled during a poll, including derived rates."""

    if_index: int
    name: str
    alias: str
    oper_status: int
    speed_bps: Optional[int]
    in_octets: int
    out_octets: int
    counter_bits: int
    in_bps: Optional[float] = None
    out_bps: Optional[float] = None
    utilization_pct: Optional[float] = None

    @property
    def oper_status_text(self) -> str:
        """RFC 2863 label for the operational status."""

        return oper_status_text(self.oper_status)

    @property
    def label(self) -> str:
        """Name plus alias, used in alert messages."""

        return f"{self.name} ({self.alias})" if self.alias else self.name


@dataclass
class PollResult:
    """Outcome of polling one endpoint."""

    address: str
    name: str
    reachable: bool
    polled_at: datetime
    duration_ms: int
    interfaces: List[InterfaceReading] = field(default_factory=list)
    sys_name: Optional[str] = None
    sys_descr: Optional[str] = None
    uptime_seconds: Optional[float] = None
    error: Optional[str] = None
    alerts_opened: int = 0
    alerts_resolved: int = 0
    opened_alerts: List[str] = field(default_factory=list)


def parse_endpoint(value: str, default_port: int = 161) -> Tuple[str, int]:
    """Split ``host`` or ``host:port`` into a host and a port.

    The canonical device address keeps the port only when it differs from the
    default, so ``192.0.2.10`` and ``192.0.2.10:161`` are the same device.
    """

    text = value.strip()
    if not text:
        raise ValueError("device address cannot be empty")
    host = text
    port = default_port
    if text.count(":") == 1:
        possible_host, possible_port = text.rsplit(":", 1)
        if possible_port.isdigit():
            host = possible_host
            port = int(possible_port)
            if not 0 < port <= 65535:
                raise ValueError(f"port must be within 1..65535, got {port}")
    if not host:
        raise ValueError(f"invalid device address {value!r}")
    return host, port


def counter_delta(current: int, previous: int, counter_bits: int = 32) -> int:
    """Return the increase between two counters, handling classic wrap.

    Wrap only applies to 32-bit counters; a 64-bit counter that goes backwards
    is treated by :func:`compute_rates` as a reset. Both inputs must fit in the
    counter width.
    """

    if counter_bits not in (32, 64):
        raise ValueError("counter_bits must be 32 or 64")
    modulus = 1 << counter_bits
    if not 0 <= previous < modulus:
        raise ValueError(f"previous counter {previous} does not fit in {counter_bits} bits")
    if not 0 <= current < modulus:
        raise ValueError(f"current counter {current} does not fit in {counter_bits} bits")
    if current >= previous:
        return current - previous
    return modulus - previous + current


def compute_rates(
    in_octets: int,
    out_octets: int,
    previous_in_octets: int,
    previous_out_octets: int,
    elapsed_seconds: float,
    speed_bps: Optional[int],
    counter_bits: int = 32,
) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """Compute ``(in_bps, out_bps, utilization_pct)`` from two counter samples.

    Returns ``(None, None, None)`` when the interval is not positive or when a
    64-bit counter moved backwards (the device restarted), because such a delta
    is not a traffic measurement. Utilization is the busier direction divided by
    the interface speed, so a full-duplex link can reach 100% in one direction.
    """

    if elapsed_seconds <= 0:
        return None, None, None
    if counter_bits == 64 and (
        in_octets < previous_in_octets or out_octets < previous_out_octets
    ):
        return None, None, None
    delta_in = counter_delta(in_octets, previous_in_octets, counter_bits)
    delta_out = counter_delta(out_octets, previous_out_octets, counter_bits)
    in_bps = delta_in * 8.0 / elapsed_seconds
    out_bps = delta_out * 8.0 / elapsed_seconds
    utilization: Optional[float] = None
    if speed_bps is not None and speed_bps > 0:
        utilization = max(in_bps, out_bps) / float(speed_bps) * 100.0
    return in_bps, out_bps, utilization


class Poller:
    """Collects SNMP data, stores it and applies threshold rules."""

    def __init__(
        self,
        store: Store,
        thresholds: Optional[Thresholds] = None,
        clock: Optional[Clock] = None,
        timeout: float = 1.0,
        retries: int = 1,
        max_walk_rows: int = 500,
    ) -> None:
        self.store = store
        self.thresholds = thresholds or Thresholds()
        self.clock = clock or store.clock or SystemClock()
        self.timeout = timeout
        self.retries = retries
        self.max_walk_rows = max_walk_rows

    def poll(
        self,
        address: str,
        host: Optional[str] = None,
        port: int = 161,
        community: str = "public",
        name: Optional[str] = None,
    ) -> PollResult:
        """Poll one endpoint and persist the outcome.

        ``address`` is the stable label stored in SQLite (for the simulator it is
        simply ``simulator``), while ``host``/``port`` are the actual UDP
        endpoint, which lets the demo use an ephemeral port without polluting
        the device history with a new row per run.
        """

        started = time.perf_counter()
        device = self.store.upsert_device(address, name=name, community=community)
        host = host or address
        try:
            with SnmpClient(
                host=host,
                port=port,
                community=community,
                timeout=self.timeout,
                retries=self.retries,
            ) as client:
                result = self._poll_reachable(client, device)
        except (SnmpError, OSError) as exc:
            result = self._record_unreachable(device, str(exc))
        result.duration_ms = max(0, int(round((time.perf_counter() - started) * 1000)))
        return result

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _poll_reachable(self, client: SnmpClient, device: Device) -> PollResult:
        scalar_varbinds = client.get([SYS_NAME, SYS_DESCR, SYS_UPTIME])
        scalars = {varbind.oid: varbind for varbind in scalar_varbinds}
        sys_name = _text(scalars.get(SYS_NAME))
        sys_descr = _text(scalars.get(SYS_DESCR))
        uptime_ticks = _integer(scalars.get(SYS_UPTIME))
        if sys_name and sys_name != device.name:
            device = self.store.upsert_device(
                device.address, name=sys_name, community=device.community
            )

        descr = self._walk_column(client, IF_DESCR)
        alias = self._walk_column(client, IF_ALIAS)
        oper = self._walk_column(client, IF_OPER_STATUS)
        speed = self._walk_column(client, IF_SPEED)
        hc_in = self._walk_column(client, IF_HC_IN_OCTETS)
        hc_out = self._walk_column(client, IF_HC_OUT_OCTETS)
        use_hc = bool(hc_in) and bool(hc_out)
        if use_hc:
            in_octets = hc_in
            out_octets = hc_out
            counter_bits = 64
        else:
            in_octets = self._walk_column(client, IF_IN_OCTETS)
            out_octets = self._walk_column(client, IF_OUT_OCTETS)
            counter_bits = 32

        sampled_at = self.clock.timestamp()
        polled_at = parse_timestamp(sampled_at)
        indexes = sorted(set(descr) | set(oper) | set(speed) | set(in_octets) | set(out_octets))
        readings: List[InterfaceReading] = []
        for if_index in indexes:
            interface_name = _text(descr.get(if_index), f"if{if_index}")
            interface_alias = _text(alias.get(if_index))
            oper_status = _integer(oper.get(if_index), 4)
            speed_bps = _integer(speed.get(if_index))
            current_in = _integer(in_octets.get(if_index), 0)
            current_out = _integer(out_octets.get(if_index), 0)
            interface = self.store.upsert_interface(
                device_id=device.id,
                if_index=if_index,
                name=interface_name,
                alias=interface_alias,
                speed_bps=speed_bps if speed_bps and speed_bps > 0 else None,
            )
            previous = self.store.latest_sample(interface.id)
            in_bps: Optional[float] = None
            out_bps: Optional[float] = None
            utilization: Optional[float] = None
            if previous is not None and previous.counter_bits == counter_bits:
                elapsed = (polled_at - previous.timestamp).total_seconds()
                in_bps, out_bps, utilization = compute_rates(
                    in_octets=current_in,
                    out_octets=current_out,
                    previous_in_octets=previous.in_octets,
                    previous_out_octets=previous.out_octets,
                    elapsed_seconds=elapsed,
                    speed_bps=speed_bps if speed_bps and speed_bps > 0 else None,
                    counter_bits=counter_bits,
                )
            reading = InterfaceReading(
                if_index=if_index,
                name=interface_name,
                alias=interface_alias,
                oper_status=oper_status,
                speed_bps=speed_bps if speed_bps and speed_bps > 0 else None,
                in_octets=current_in,
                out_octets=current_out,
                counter_bits=counter_bits,
                in_bps=in_bps,
                out_bps=out_bps,
                utilization_pct=utilization,
            )
            readings.append(reading)
            self.store.record_sample(
                interface_id=interface.id,
                sampled_at=sampled_at,
                in_octets=current_in,
                out_octets=current_out,
                counter_bits=counter_bits,
                in_bps=in_bps,
                out_bps=out_bps,
                utilization_pct=utilization,
                oper_status=oper_status,
            )

        opened, resolved, opened_messages = self._apply_interface_alerts(device, readings)
        resolved += self._resolve_vanished_interfaces(device, {reading.if_index for reading in readings})
        status = evaluate_unreachable(device.address, None, self.thresholds)
        if status.resolve:
            resolved += self.store.resolve_alerts(device.id, KIND_UNREACHABLE, None)
        self.store.update_device_status(device.id, reachable=True, error=None, polled_at=sampled_at)
        return PollResult(
            address=device.address,
            name=device.name,
            reachable=True,
            polled_at=polled_at,
            duration_ms=0,
            interfaces=readings,
            sys_name=sys_name or device.name,
            sys_descr=sys_descr,
            uptime_seconds=None if uptime_ticks is None else uptime_ticks / 100.0,
            alerts_opened=opened,
            alerts_resolved=resolved,
            opened_alerts=opened_messages,
        )

    def _walk_column(self, client: SnmpClient, base_oid: str) -> Dict[int, VarBind]:
        values: Dict[int, VarBind] = {}
        for varbind in client.walk(base_oid, max_rows=self.max_walk_rows):
            try:
                index = child_index(base_oid, varbind.oid)
            except OidError:
                continue
            values[index] = varbind
        return values

    def _apply_interface_alerts(
        self, device: Device, readings: Sequence[InterfaceReading]
    ) -> Tuple[int, int, List[str]]:
        opened = 0
        resolved = 0
        opened_messages: List[str] = []
        for reading in readings:
            interface = self.store.get_interface(device.id, reading.if_index)
            if interface is None:  # defensive: the poller just upserted it
                continue
            decisions = evaluate_interface(
                reading.label,
                reading.oper_status,
                reading.utilization_pct,
                self.thresholds,
            )
            for decision in decisions:
                if decision.active:
                    existing = self.store.find_active_alert(device.id, decision.kind, interface.id)
                    self.store.record_alert(
                        device_id=device.id,
                        interface_id=interface.id,
                        kind=decision.kind,
                        severity=decision.severity,
                        message=decision.message,
                        value=decision.value,
                        threshold=decision.threshold,
                    )
                    if existing is None:
                        opened += 1
                        opened_messages.append(decision.message)
                else:
                    resolved += self.store.resolve_alerts(device.id, decision.kind, interface.id)
        return opened, resolved, opened_messages

    def _resolve_vanished_interfaces(self, device: Device, present: set) -> int:
        resolved = 0
        for interface in self.store.list_interfaces(device.id):
            if interface.if_index in present:
                continue
            for kind in (KIND_UTILIZATION, KIND_OPER_DOWN):
                resolved += self.store.resolve_alerts(device.id, kind, interface.id)
        return resolved

    def _record_unreachable(self, device: Device, error: str) -> PollResult:
        sampled_at = self.clock.timestamp()
        self.store.update_device_status(device.id, reachable=False, error=error, polled_at=sampled_at)
        decision = evaluate_unreachable(device.address, error, self.thresholds)
        opened = 0
        opened_messages: List[str] = []
        if decision.active:
            existing = self.store.find_active_alert(device.id, KIND_UNREACHABLE, None)
            self.store.record_alert(
                device_id=device.id,
                interface_id=None,
                kind=decision.kind,
                severity=decision.severity,
                message=decision.message,
            )
            if existing is None:
                opened = 1
                opened_messages.append(decision.message)
        return PollResult(
            address=device.address,
            name=device.name,
            reachable=False,
            polled_at=parse_timestamp(sampled_at),
            duration_ms=0,
            interfaces=[],
            error=error,
            alerts_opened=opened,
            opened_alerts=opened_messages,
        )


def _text(varbind: Optional[VarBind], default: str = "") -> str:
    if varbind is None or varbind.is_exception or varbind.value is None:
        return default
    value = varbind.value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _integer(varbind: Optional[VarBind], default: Optional[int] = None) -> Optional[int]:
    if varbind is None or varbind.is_exception or varbind.value is None:
        return default
    try:
        return int(varbind.value)
    except (TypeError, ValueError):
        return default
