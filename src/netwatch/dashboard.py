"""Self-contained HTML dashboard with inline SVG sparklines.

The generated page embeds all CSS and SVG inline: no CDN, no external fonts, no
JavaScript and no network requests, so it can be opened from disk or served by
the built-in HTTP server. A ``<meta http-equiv="refresh">`` tag reloads the page
periodically when served.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from .alerting import Thresholds
from .formatting import (
    format_bps,
    format_oper_status,
    format_speed,
    format_timestamp,
    format_utilization,
)
from .storage import Device, Interface, Store, parse_timestamp

__all__ = ["render_dashboard", "sparkline_points", "sparkline_pair_svg"]

_SPARK_WIDTH = 220
_SPARK_HEIGHT = 42
_SPARK_PADDING = 3


def sparkline_points(
    values: Sequence[float],
    width: int = _SPARK_WIDTH,
    height: int = _SPARK_HEIGHT,
    padding: int = _SPARK_PADDING,
    maximum: Optional[float] = None,
) -> str:
    """Project values onto a polyline ``points`` string.

    Values are scaled against ``maximum`` (defaulting to the largest value) with
    a zero baseline, which keeps two directions of traffic visually comparable.
    """

    if not values:
        return ""
    top = maximum if maximum is not None else max(values)
    top = max(float(top), 1e-9)
    inner_height = height - 2 * padding
    if len(values) == 1:
        # A single sample is drawn as a full-width flat segment so the
        # sparkline remains visible instead of collapsing to a dot.
        y = height - padding - (max(0.0, float(values[0])) / top) * inner_height
        return f"{padding:.1f},{y:.1f} {width - padding:.1f},{y:.1f}"
    step = (width - 2 * padding) / (len(values) - 1)
    points: List[str] = []
    for position, value in enumerate(values):
        x = padding + position * step
        ratio = max(0.0, float(value)) / top
        y = height - padding - ratio * inner_height
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def sparkline_pair_svg(
    in_values: Sequence[float],
    out_values: Sequence[float],
    label: str,
    width: int = _SPARK_WIDTH,
    height: int = _SPARK_HEIGHT,
) -> str:
    """Render two traffic series as an inline SVG sparkline."""

    combined = [float(value) for value in list(in_values) + list(out_values) if value is not None]
    maximum = max(combined) if combined else None
    in_points = sparkline_points(in_values, width, height, maximum=maximum)
    out_points = sparkline_points(out_values, width, height, maximum=maximum)
    safe_label = html.escape(label, quote=True)
    parts = [
        f'<svg class="spark" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-label="traffic sparkline for {safe_label}">',
        f'<line class="spark-axis" x1="{_SPARK_PADDING}" y1="{height - _SPARK_PADDING}" '
        f'x2="{width - _SPARK_PADDING}" y2="{height - _SPARK_PADDING}" />',
    ]
    if in_points:
        parts.append(f'<polyline class="spark-in" points="{in_points}" />')
    if out_points:
        parts.append(f'<polyline class="spark-out" points="{out_points}" />')
    parts.append("</svg>")
    return "".join(parts)


_STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px;
  background: #0b1220; color: #dbe4f0;
  font: 14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif;
}
header { margin-bottom: 20px; }
h1 { margin: 0; font-size: 24px; letter-spacing: 0.02em; color: #f8fbff; }
h2 { margin: 0 0 10px; font-size: 16px; color: #9fb3cc; text-transform: uppercase; letter-spacing: 0.08em; }
p.subtitle { margin: 2px 0 0; color: #8da2bd; }
p.meta { margin: 8px 0 0; color: #8da2bd; font-size: 13px; }
section { background: #111c30; border: 1px solid #22334d; border-radius: 8px; padding: 16px; margin-bottom: 18px; overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #1d2c44; white-space: nowrap; }
th { color: #94a9c4; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #16253d; }
td.num, th.num { text-align: right; }
.ok { color: #5bd6a2; font-weight: 600; }
.bad { color: #ff7b7b; font-weight: 600; }
.warn { color: #ffc266; font-weight: 600; }
.muted { color: #6f829c; }
.empty { margin: 0; color: #8da2bd; }
code { background: #1b2b45; border-radius: 4px; padding: 1px 5px; color: #cfe0f5; }
.spark { display: block; }
.spark-axis { stroke: #2a3d5c; stroke-width: 1; }
.spark-in { fill: none; stroke: #54a6ff; stroke-width: 1.6; stroke-linejoin: round; }
.spark-out { fill: none; stroke: #ffb454; stroke-width: 1.6; stroke-linejoin: round; }
.legend { display: flex; gap: 16px; color: #8da2bd; font-size: 12px; margin-top: 8px; align-items: center; }
.legend span::before { content: ""; display: inline-block; width: 10px; height: 3px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }
.legend .in::before { background: #54a6ff; }
.legend .out::before { background: #ffb454; }
footer { color: #6f829c; font-size: 12px; margin-top: 22px; }
"""


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _device_status_cell(device: Device) -> str:
    if device.reachable:
        return '<span class="ok">reachable</span>'
    error = f' title="{_esc(device.last_error or "unreachable")}"' if device.last_error else ""
    return f'<span class="bad"{error}>unreachable</span>'


def _oper_cell(status: int) -> str:
    label = format_oper_status(status)
    if status == 1:
        return f'<span class="ok">{_esc(label)}</span>'
    if status == 2:
        return f'<span class="bad">{_esc(label)}</span>'
    return f'<span class="warn">{_esc(label)}</span>'


def render_dashboard(
    store: Store,
    thresholds: Optional[Thresholds] = None,
    generated_at: Optional[datetime] = None,
    refresh_seconds: int = 30,
    sample_limit: int = 30,
) -> str:
    """Render the complete dashboard document for the current store contents."""

    thresholds = thresholds or Thresholds()
    generated = generated_at if generated_at is not None else store.clock.utcnow()
    devices = store.list_devices()
    interfaces = store.list_interfaces()
    alerts = store.list_alerts(active_only=True, limit=50)
    devices_by_id: Dict[int, Device] = {device.id: device for device in devices}
    interfaces_by_id: Dict[int, Interface] = {interface.id: interface for interface in interfaces}
    interfaces_by_device: Dict[int, List[Interface]] = {}
    for interface in interfaces:
        interfaces_by_device.setdefault(interface.device_id, []).append(interface)
    total_samples = store.count_samples()
    active_alerts = store.count_alerts(active_only=True)
    reachable_devices = sum(1 for device in devices if device.reachable)

    parts: List[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en">')
    parts.append("<head>")
    parts.append('<meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">')
    parts.append("<title>netwatch dashboard</title>")
    parts.append(f"<style>{_STYLE}</style>")
    parts.append("</head>")
    parts.append("<body>")
    parts.append("<header>")
    parts.append("<h1>netwatch</h1>")
    parts.append('<p class="subtitle">SNMPv2c network monitor</p>')
    parts.append(
        '<p class="meta">Generated '
        f"{_esc(format_timestamp(generated))} &middot; refresh every {int(refresh_seconds)} s &middot; "
        f"{len(devices)} device(s), {reachable_devices} reachable &middot; "
        f"{len(interfaces)} interface(s) &middot; {total_samples} sample(s) &middot; "
        f"{active_alerts} active alert(s)</p>"
    )
    parts.append("</header>")

    # Alerts -----------------------------------------------------------
    parts.append('<section id="alerts">')
    parts.append("<h2>Active alerts</h2>")
    if not alerts:
        parts.append('<p class="empty">No active alerts.</p>')
    else:
        parts.append("<table>")
        parts.append(
            '<thead><tr><th>Severity</th><th>Kind</th><th>Target</th><th>Opened</th><th>Message</th></tr></thead>'
        )
        parts.append("<tbody>")
        for alert in alerts:
            device = devices_by_id.get(alert.device_id)
            target = device.name if device is not None else str(alert.device_id)
            if alert.interface_id is not None:
                interface = interfaces_by_id.get(alert.interface_id)
                if interface is not None:
                    target = f"{target} / {interface.name}"
            severity_class = "bad" if alert.severity == "critical" else "warn"
            parts.append(
                "<tr>"
                f'<td><span class="{severity_class}">{_esc(alert.severity)}</span></td>'
                f"<td>{_esc(alert.kind)}</td>"
                f"<td>{_esc(target)}</td>"
                f"<td>{_esc(format_timestamp(parse_timestamp(alert.created_at)))}</td>"
                f"<td>{_esc(alert.message)}</td>"
                "</tr>"
            )
        parts.append("</tbody>")
        parts.append("</table>")
    parts.append("</section>")

    # Devices ----------------------------------------------------------
    parts.append('<section id="devices">')
    parts.append("<h2>Devices</h2>")
    if not devices:
        parts.append(
            '<p class="empty">No devices yet. Run <code>netwatch poll --simulate</code> '
            "to generate a complete dataset.</p>"
        )
    else:
        parts.append("<table>")
        parts.append(
            '<thead><tr><th>Device</th><th>Name</th><th>Status</th><th class="num">Interfaces</th>'
            "<th>Last poll</th></tr></thead>"
        )
        parts.append("<tbody>")
        for device in devices:
            last_poll = (
                format_timestamp(parse_timestamp(device.last_polled_at))
                if device.last_polled_at
                else "-"
            )
            parts.append(
                "<tr>"
                f'<td data-device="{_esc(device.address)}">{_esc(device.address)}</td>'
                f"<td>{_esc(device.name)}</td>"
                f"<td>{_device_status_cell(device)}</td>"
                f'<td class="num">{len(interfaces_by_device.get(device.id, []))}</td>'
                f"<td>{_esc(last_poll)}</td>"
                "</tr>"
            )
        parts.append("</tbody>")
        parts.append("</table>")
    parts.append("</section>")

    # Interfaces -------------------------------------------------------
    parts.append('<section id="interfaces">')
    parts.append("<h2>Interfaces</h2>")
    if not interfaces:
        parts.append('<p class="empty">No interfaces discovered yet.</p>')
    else:
        parts.append("<table>")
        parts.append(
            '<thead><tr><th>Device</th><th>Interface</th><th>Alias</th><th>Speed</th><th>Oper</th>'
            '<th class="num">In</th><th class="num">Out</th><th class="num">Utilization</th>'
            "<th>Traffic (recent samples)</th></tr></thead>"
        )
        parts.append("<tbody>")
        for interface in interfaces:
            device = devices_by_id.get(interface.device_id)
            device_label = device.address if device is not None else str(interface.device_id)
            samples = store.interface_samples(interface.id, limit=sample_limit)
            latest = samples[-1] if samples else None
            if latest is not None:
                oper_cell = _oper_cell(latest.oper_status)
                in_text = format_bps(latest.in_bps)
                out_text = format_bps(latest.out_bps)
                util_text = format_utilization(latest.utilization_pct)
            else:
                oper_cell = '<span class="muted">-</span>'
                in_text = out_text = util_text = "-"
            rate_samples = [sample for sample in samples if sample.in_bps is not None or sample.out_bps is not None]
            in_values = [float(sample.in_bps or 0.0) for sample in rate_samples]
            out_values = [float(sample.out_bps or 0.0) for sample in rate_samples]
            spark = (
                sparkline_pair_svg(in_values, out_values, f"{device_label} {interface.name}")
                if rate_samples
                else '<span class="muted">no rates yet</span>'
            )
            parts.append(
                "<tr"
                f' data-device="{_esc(device_label)}"'
                f' data-if-index="{interface.if_index}">'
                f"<td>{_esc(device_label)}</td>"
                f"<td>{_esc(interface.name)}</td>"
                f"<td>{_esc(interface.alias) if interface.alias else '-'}</td>"
                f"<td>{_esc(format_speed(interface.speed_bps))}</td>"
                f"<td>{oper_cell}</td>"
                f'<td class="num">{_esc(in_text)}</td>'
                f'<td class="num">{_esc(out_text)}</td>'
                f'<td class="num">{_esc(util_text)}</td>'
                f"<td>{spark}</td>"
                "</tr>"
            )
        parts.append("</tbody>")
        parts.append("</table>")
        parts.append(
            '<div class="legend"><span class="in">inbound</span>'
            '<span class="out">outbound</span></div>'
        )
    parts.append("</section>")

    parts.append("<footer>")
    parts.append(
        "netwatch 1.0 &middot; utilization threshold "
        f"{float(thresholds.utilization_pct):.1f}% &middot; history retained by the SQLite store"
    )
    parts.append("</footer>")
    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts) + "\n"
