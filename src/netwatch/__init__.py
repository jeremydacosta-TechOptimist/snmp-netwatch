"""netwatch - a zero-dependency SNMPv2c network monitor.

The package contains a hand-written BER/SNMPv2c codec, a localhost agent
simulator, a polling engine that computes interface rates and utilization, a
SQLite history store with threshold alerting, and a self-contained HTML
dashboard with a small JSON API.
"""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = ["__version__"]
