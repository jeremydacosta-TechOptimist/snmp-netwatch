"""Time sources used by the simulator, poller, storage and reports.

Everything that reads the clock takes a :class:`Clock` instance so tests can
use :class:`FixedClock` and obtain deterministic timestamps and counter rates.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

__all__ = ["Clock", "SystemClock", "FixedClock"]


class Clock:
    """Wall clock read as Unix seconds and UTC datetimes."""

    def now(self) -> float:
        """Return the current Unix timestamp in seconds."""

        return time.time()

    def utcnow(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""

        return datetime.fromtimestamp(self.now(), tz=timezone.utc)

    def timestamp(self) -> str:
        """Return the current time as an ISO-8601 UTC string with milliseconds."""

        return self.utcnow().isoformat(timespec="milliseconds")


class SystemClock(Clock):
    """Real wall clock; the default in production code paths."""


class FixedClock(Clock):
    """Manually advanced clock used by deterministic tests and demos."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._now = float(start)

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> float:
        """Move the clock forward and return the new timestamp."""

        if seconds < 0:
            raise ValueError("cannot move a clock backwards")
        self._now += float(seconds)
        return self._now
