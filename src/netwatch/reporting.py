"""Read models and text rendering for reports, alerts and poll output.

The JSON summary built here is the same payload served by
``GET /api/summary`` on the dashboard server, so scripts and the HTML views see
one consistent shape.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .alerting import Thresholds
from .formatting import (
    format_bps,
    format_duration,
    format_oper_status,
    format_speed,
    format_timestamp,
    format_uptime,
    format_utilization,
)
from .poller import PollResult
from .storage import Alert, Device, Interface, Store, parse_timestamp

__all__ = [
    "build_summary",
    "build_alerts_payload",
    "poll_result_to_dict",
    "render_poll_result",
    "render_report",
    "render_alerts",
]


def poll_result_to_dict(result: PollResult) -> Dict[str, Any]:
    """Serialise a poll result for ``netwatch poll --json``."""

    return {
        "address": result.address,
        "name": result.name,
        "reachable": result.reachable,
        "error": result.error,
        "polled_at": result.polled_at.isoformat(timespec="seconds"),
        "duration_ms": result.duration_ms,
        "sys_name": result.sys_name,
        "sys_descr": result.sys_descr,
        "uptime_seconds": result.uptime_seconds,
        "alerts_opened": result.alerts_opened,
        "alerts_resolved": result.alerts_resolved,
        "opened_alerts": list(result.opened_alerts),
        "interfaces": [
            {
                "if_index": reading.if_index,
                "name": reading.name,
                "alias": reading.alias,
                "oper_status": reading.oper_status,
                "oper_status_text": reading.oper_status_text,
                "speed_bps": reading.speed_bps,
                "in_octets": reading.in_octets,
                "out_octets": reading.out_octets,
                "counter_bits": reading.counter_bits,
                "in_bps": reading.in_bps,
                "out_bps": reading.out_bps,
                "utilization_pct": reading.utilization_pct,
            }
            for reading in result.interfaces
        ],
    }


def _alert_target(alert: Alert, devices: Dict[int, Device], interfaces: Dict[int, Interface]) -> str:
    device = devices.get(alert.device_id)
    device_label = device.name if device is not None else f"device {alert.device_id}"
    if alert.interface_id is None:
        return device_label
    interface = interfaces.get(alert.interface_id)
    interface_label = interface.name if interface is not None else f"if{alert.interface_id}"
    if interface is not None and interface.alias:
        interface_label = f"{interface_label} ({interface.alias})"
    return f"{device_label} / {interface_label}"


def build_summary(
    store: Store,
    thresholds: Optional[Thresholds] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Build the JSON-ready monitoring summary used by reports and the API."""

    thresholds = thresholds or Thresholds()
    generated = generated_at if generated_at is not None else store.clock.utcnow()
    devices = store.list_devices()
    interfaces = store.list_interfaces()
    interfaces_by_device: Dict[int, List[Interface]] = {}
    for interface in interfaces:
        interfaces_by_device.setdefault(interface.device_id, []).append(interface)
    device_entries: List[Dict[str, Any]] = []
    total_samples = store.count_samples()
    for device in devices:
        interface_entries: List[Dict[str, Any]] = []
        for interface in interfaces_by_device.get(device.id, []):
            latest = store.latest_sample(interface.id)
            interface_entries.append(
                {
                    "if_index": interface.if_index,
                    "name": interface.name,
                    "alias": interface.alias,
                    "speed_bps": interface.speed_bps,
                    "oper_status": latest.oper_status if latest is not None else None,
                    "oper_status_text": (
                        format_oper_status(latest.oper_status) if latest is not None else None
                    ),
                    "in_bps": latest.in_bps if latest is not None else None,
                    "out_bps": latest.out_bps if latest is not None else None,
                    "utilization_pct": latest.utilization_pct if latest is not None else None,
                    "in_octets": latest.in_octets if latest is not None else None,
                    "out_octets": latest.out_octets if latest is not None else None,
                    "counter_bits": latest.counter_bits if latest is not None else None,
                    "sampled_at": latest.sampled_at if latest is not None else None,
                    "samples": store.count_interface_samples(interface.id),
                }
            )
        device_entries.append(
            {
                "address": device.address,
                "name": device.name,
                "community": device.community,
                "reachable": device.reachable,
                "last_error": device.last_error,
                "last_polled_at": device.last_polled_at,
                "interfaces": interface_entries,
            }
        )
    devices_by_id = {device.id: device for device in devices}
    interfaces_by_id = {interface.id: interface for interface in interfaces}
    alert_entries = [
        {
            "id": alert.id,
            "kind": alert.kind,
            "severity": alert.severity,
            "message": alert.message,
            "target": _alert_target(alert, devices_by_id, interfaces_by_id),
            "device": devices_by_id[alert.device_id].address
            if alert.device_id in devices_by_id
            else None,
            "interface": interfaces_by_id[alert.interface_id].name
            if alert.interface_id is not None and alert.interface_id in interfaces_by_id
            else None,
            "value": alert.value,
            "threshold": alert.threshold,
            "created_at": alert.created_at,
            "resolved_at": alert.resolved_at,
        }
        for alert in store.list_alerts(active_only=True, limit=200)
    ]
    return {
        "generated_at": generated.isoformat(timespec="seconds"),
        "thresholds": {
            "utilization_pct": float(thresholds.utilization_pct),
            "oper_status_down": bool(thresholds.oper_status_down),
            "device_unreachable": bool(thresholds.device_unreachable),
        },
        "totals": {
            "devices": len(devices),
            "reachable_devices": sum(1 for device in devices if device.reachable),
            "interfaces": len(interfaces),
            "samples": total_samples,
            "active_alerts": store.count_alerts(active_only=True),
        },
        "devices": device_entries,
        "alerts": alert_entries,
    }


def build_alerts_payload(
    store: Store, include_resolved: bool = False, limit: int = 100
) -> Dict[str, Any]:
    """Build the JSON-ready alert list used by ``netwatch alerts --json``."""

    alerts = store.list_alerts(active_only=not include_resolved, limit=limit)
    devices = {device.id: device for device in store.list_devices()}
    interfaces = {interface.id: interface for interface in store.list_interfaces()}
    entries = []
    for alert in alerts:
        device = devices.get(alert.device_id)
        interface = (
            interfaces.get(alert.interface_id) if alert.interface_id is not None else None
        )
        entries.append(
            {
                "id": alert.id,
                "kind": alert.kind,
                "severity": alert.severity,
                "state": "resolved" if alert.resolved_at else "active",
                "target": _alert_target(alert, devices, interfaces),
                "device": device.address if device is not None else None,
                "interface": interface.name if interface is not None else None,
                "value": alert.value,
                "threshold": alert.threshold,
                "message": alert.message,
                "created_at": alert.created_at,
                "resolved_at": alert.resolved_at,
            }
        )
    active = store.count_alerts(active_only=True)
    total = store.count_alerts(active_only=False)
    return {
        "active": active,
        "resolved": total - active,
        "total": total,
        "alerts": entries,
    }


def render_poll_result(result: PollResult) -> str:
    """Render one poll result as a compact terminal-friendly block."""

    status = "reachable" if result.reachable else "UNREACHABLE"
    lines = [
        f"device {result.name} ({result.address}) - {status} in "
        f"{format_duration(result.duration_ms)} at {format_timestamp(result.polled_at)}"
    ]
    if not result.reachable:
        lines.append(f"  error: {result.error}")
        for message in result.opened_alerts:
            lines.append(f"  alert opened: {message}")
        return "\n".join(lines)
    if result.sys_descr:
        lines.append(f"  sysDescr : {result.sys_descr}")
    if result.uptime_seconds is not None:
        lines.append(f"  sysUpTime: {format_uptime(result.uptime_seconds)}")
    header = (
        f"  {'INTERFACE':<14} {'ALIAS':<14} {'SPEED':>10} {'OPER':<8} "
        f"{'IN':>13} {'OUT':>13} {'UTIL':>7}"
    )
    lines.append(header)
    for reading in result.interfaces:
        lines.append(
            f"  {reading.name:<14} {reading.alias:<14} {format_speed(reading.speed_bps):>10} "
            f"{reading.oper_status_text:<8} {format_bps(reading.in_bps):>13} "
            f"{format_bps(reading.out_bps):>13} {format_utilization(reading.utilization_pct):>7}"
        )
    for message in result.opened_alerts:
        lines.append(f"  alert opened: {message}")
    if result.alerts_resolved:
        lines.append(f"  alerts resolved: {result.alerts_resolved}")
    return "\n".join(lines)


def render_report(
    store: Store,
    thresholds: Optional[Thresholds] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    """Render the human-readable monitoring report."""

    summary = build_summary(store, thresholds, generated_at)
    totals = summary["totals"]
    thresholds = thresholds or Thresholds()
    generated = parse_timestamp(summary["generated_at"])
    lines = [
        f"netwatch report - {format_timestamp(generated)}",
        f"database  : {store.path}",
        (
            f"thresholds: utilization >= {float(thresholds.utilization_pct):.1f}%, "
            f"oper-down alerts={'on' if thresholds.oper_status_down else 'off'}, "
            f"unreachable alerts={'on' if thresholds.device_unreachable else 'off'}"
        ),
        "",
        (
            f"devices: {totals['devices']} ({totals['reachable_devices']} reachable) | "
            f"interfaces: {totals['interfaces']} | samples: {totals['samples']} | "
            f"active alerts: {totals['active_alerts']}"
        ),
        "",
    ]
    if not summary["devices"]:
        lines.append("No devices have been polled yet. Run: netwatch poll --simulate")
        return "\n".join(lines)
    lines.append(
        f"{'DEVICE':<22} {'NAME':<18} {'STATUS':<12} {'IFACES':>6}  LAST POLL"
    )
    for device in summary["devices"]:
        last_poll = device["last_polled_at"]
        last_poll_text = format_timestamp(parse_timestamp(last_poll)) if last_poll else "-"
        status = "reachable" if device["reachable"] else "unreachable"
        lines.append(
            f"{device['address']:<22} {device['name']:<18} {status:<12} "
            f"{len(device['interfaces']):>6}  {last_poll_text}"
        )
    lines.append("")
    for device in summary["devices"]:
        if not device["interfaces"]:
            continue
        lines.append(f"interfaces on {device['address']} ({device['name']})")
        lines.append(
            f"  {'INTERFACE':<14} {'ALIAS':<14} {'SPEED':>10} {'OPER':<8} "
            f"{'IN':>13} {'OUT':>13} {'UTIL':>7} {'SAMPLES':>7}"
        )
        for interface in device["interfaces"]:
            lines.append(
                f"  {interface['name']:<14} {interface['alias']:<14} "
                f"{format_speed(interface['speed_bps']):>10} "
                f"{(interface['oper_status_text'] or '-'):<8} "
                f"{format_bps(interface['in_bps']):>13} "
                f"{format_bps(interface['out_bps']):>13} "
                f"{format_utilization(interface['utilization_pct']):>7} "
                f"{interface['samples']:>7}"
            )
        lines.append("")
    if summary["alerts"]:
        lines.append("active alerts")
        for alert in summary["alerts"]:
            created = format_timestamp(parse_timestamp(alert["created_at"]))
            lines.append(
                f"  [{alert['severity']}] {alert['kind']} {alert['target']} "
                f"({created}) - {alert['message']}"
            )
    else:
        lines.append("active alerts: none")
    return "\n".join(lines)


def render_alerts(
    store: Store, include_resolved: bool = False, limit: int = 100
) -> str:
    """Render the alert list for ``netwatch alerts``."""

    alerts = store.list_alerts(active_only=not include_resolved, limit=limit)
    devices = {device.id: device for device in store.list_devices()}
    interfaces = {interface.id: interface for interface in store.list_interfaces()}
    if not alerts:
        active_count = store.count_alerts(active_only=True)
        total_count = store.count_alerts(active_only=False)
        lines = [
            "no alerts recorded"
            if include_resolved
            else "no active alerts recorded",
            "",
            f"{active_count} active alert(s), {total_count - active_count} resolved alert(s) in total",
        ]
        return "\n".join(lines)
    if include_resolved:
        header = (
            f"{'ID':>4}  {'CREATED':<21} {'SEVERITY':<9} {'KIND':<18} "
            f"{'TARGET':<40} {'STATE':<9} MESSAGE"
        )
    else:
        header = (
            f"{'ID':>4}  {'CREATED':<21} {'SEVERITY':<9} {'KIND':<18} "
            f"{'TARGET':<40} MESSAGE"
        )
    lines = [header]
    for alert in alerts:
        target = _alert_target(alert, devices, interfaces)
        created = format_timestamp(parse_timestamp(alert.created_at))
        if include_resolved:
            state = "resolved" if not alert.active else "active"
            lines.append(
                f"{alert.id:>4}  {created:<21} {alert.severity:<9} {alert.kind:<18} "
                f"{target:<40} {state:<9} {alert.message}"
            )
        else:
            lines.append(
                f"{alert.id:>4}  {created:<21} {alert.severity:<9} {alert.kind:<18} "
                f"{target:<40} {alert.message}"
            )
    active_count = store.count_alerts(active_only=True)
    total_count = store.count_alerts(active_only=False)
    resolved_count = total_count - active_count
    lines.append("")
    lines.append(
        f"{active_count} active alert(s), {resolved_count} resolved alert(s) in total"
    )
    return "\n".join(lines)
