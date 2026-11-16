"""Formatting helpers shared by the CLI, reports and the HTML dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from .mib import oper_status_text

__all__ = [
    "format_bps",
    "format_speed",
    "format_utilization",
    "format_oper_status",
    "format_timestamp",
    "format_duration",
    "format_uptime",
]

_UNITS = ("bps", "Kbps", "Mbps", "Gbps", "Tbps")


def format_bps(value: Optional[float]) -> str:
    """Format a bit rate with a unit that keeps the number readable."""

    if value is None:
        return "-"
    number = float(value)
    if number < 0:
        return f"{number:.0f} bps"
    unit = 0
    while number >= 1000.0 and unit < len(_UNITS) - 1:
        number /= 1000.0
        unit += 1
    if unit == 0:
        return f"{number:.0f} {_UNITS[unit]}"
    return f"{number:.2f} {_UNITS[unit]}"


def format_speed(speed_bps: Optional[int]) -> str:
    """Format an interface speed (ifSpeed / ifHighSpeed)."""

    if speed_bps is None or speed_bps <= 0:
        return "unknown"
    return format_bps(float(speed_bps))


def format_utilization(value: Optional[float]) -> str:
    """Format a utilization percentage."""

    if value is None:
        return "-"
    return f"{float(value):.1f}%"


def format_oper_status(value: int) -> str:
    """Format an ifOperStatus value with its RFC 2863 label."""

    return oper_status_text(int(value))


def format_timestamp(value: datetime) -> str:
    """Format a datetime as ``YYYY-MM-DD HH:MM:SS UTC``."""

    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def format_duration(milliseconds: int) -> str:
    """Format a poll duration in milliseconds."""

    return f"{int(milliseconds)} ms"


def format_uptime(seconds: Optional[float]) -> str:
    """Format sysUpTime as ``Nd HH:MM:SS``."""

    if seconds is None:
        return "-"
    total = max(0, int(seconds))
    days, remainder = divmod(total, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, secs = divmod(remainder, 60)
    return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
